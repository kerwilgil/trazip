package update

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"runtime"
	"strings"
	"time"
)

const (
	// DefaultRepo is the public distribution channel — binaries and signed
	// manifests only, never source. Kept separate from the private source
	// repository on purpose: this repo's contents are safe to expose to an
	// unauthenticated client running on an end user's machine.
	DefaultRepo = "kerwilgil/trazip-releases"

	githubAPIBase = "https://api.github.com"
	apiTimeout    = 10 * time.Second
	maxJSONBytes  = 1 << 20 // 1 MiB — generous for a release API response or update.json, nowhere close to a real one
	maxSigBytes   = 4096
	maxRedirects  = 5
)

// ghAsset/ghRelease are the subset of GitHub's Releases API this package
// actually reads — deliberately not the full schema.
type ghAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

type ghRelease struct {
	TagName     string    `json:"tag_name"`
	Draft       bool      `json:"draft"`
	Prerelease  bool      `json:"prerelease"`
	PublishedAt time.Time `json:"published_at"`
	Assets      []ghAsset `json:"assets"`
}

var tagPattern = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

// httpsOnlyRedirect builds a CheckRedirect that stops after max hops and
// refuses to follow ANY redirect that downgrades an https:// request to
// something else — a network attacker who can inject a 30x response
// should not be able to bounce TRAZIP onto a plaintext connection it can
// then read or tamper with. Factored out so tests exercise this exact
// policy (via a TLS test server) instead of a hand-rolled copy of it.
func httpsOnlyRedirect(max int) func(req *http.Request, via []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= max {
			return fmt.Errorf("stopped after %d redirects", max)
		}
		if via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
			return fmt.Errorf("refusing to follow a redirect from https to %s", req.URL.Scheme)
		}
		return nil
	}
}

// requireHTTPSURL rejects anything that isn't an absolute https:// URL with
// a real host and no embedded credentials. httpsOnlyRedirect stops a
// request from being downgraded mid-flight by a redirect, but it has
// nothing to say about a URL that arrives as plain HTTP (or something
// else entirely) as the very first request — a compromised or malformed
// GitHub API response could hand back a browser_download_url like that
// for update.json, its signature, the app executable, or the updater
// helper, and every one of those is checked against this before any
// request is ever made for it.
func requireHTTPSURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("malformed URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("URL scheme %q is not https", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("URL has no host")
	}
	if u.User != nil {
		return fmt.Errorf("URL must not contain embedded credentials")
	}
	return nil
}

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout:       apiTimeout,
		CheckRedirect: httpsOnlyRedirect(maxRedirects),
	}
}

// checkRelease is the full check pipeline: fetch the latest stable release,
// fetch and Ed25519-verify its update.json, validate every field in it
// (validate.go), and decide (via strict numeric semver, never string
// comparison) whether it's actually newer than currentVersion. Nothing in
// the returned ReleaseInfo is trusted from the network without having
// passed both signature verification and field validation first.
func checkRelease(ctx context.Context, client *http.Client, apiBase, repo, currentVersion, userAgent string) (ReleaseInfo, error) {
	rel, err := fetchLatestRelease(ctx, client, apiBase, repo, userAgent)
	if err != nil {
		return ReleaseInfo{}, err
	}
	latestVersion := strings.TrimPrefix(rel.TagName, "v")

	manifest, err := fetchManifest(ctx, client, rel, userAgent)
	if err != nil {
		return ReleaseInfo{}, err
	}
	if manifest.Version != latestVersion {
		return ReleaseInfo{}, fmt.Errorf("manifest version %q does not match release tag %q", manifest.Version, rel.TagName)
	}

	cmp, err := compareVersions(latestVersion, currentVersion)
	if err != nil {
		return ReleaseInfo{}, err
	}

	info := ReleaseInfo{
		CurrentVersion: currentVersion,
		LatestVersion:  latestVersion,
		// Strictly greater-than, never >=: a manifest claiming to be the
		// "latest" version equal to (or, if the server is confused or
		// compromised, older than) what's already installed must never be
		// offered as an update. See semver.go's compareVersions.
		Available:   cmp > 0,
		PublishedAt: rel.PublishedAt,
		NotesURL:    manifest.NotesURL,
	}
	if !info.Available {
		return info, nil
	}

	if runtime.GOOS != "windows" {
		return ReleaseInfo{}, fmt.Errorf("no update asset published for %s yet", runtime.GOOS)
	}
	appAsset, updaterAsset, err := validateManifest(manifest, runtime.GOARCH)
	if err != nil {
		return ReleaseInfo{}, fmt.Errorf("manifest validation: %w", err)
	}

	info.Asset, err = resolveGitHubAsset(rel, appAsset)
	if err != nil {
		return ReleaseInfo{}, fmt.Errorf("app asset: %w", err)
	}
	info.UpdaterAsset, err = resolveGitHubAsset(rel, updaterAsset)
	if err != nil {
		return ReleaseInfo{}, fmt.Errorf("updater asset: %w", err)
	}
	return info, nil
}

// resolveGitHubAsset matches a manifest-declared, already-validated asset
// identity against the release's own asset list, and cross-checks the
// size GitHub itself reports for that file against what the signed
// manifest declared — a signed Size that quietly disagreed with the file
// actually attached to the release would be a sign something is wrong,
// not a detail to ignore.
func resolveGitHubAsset(rel *ghRelease, ma ManifestAsset) (Asset, error) {
	ghA, ok := findAsset(rel.Assets, ma.Asset)
	if !ok {
		return Asset{}, fmt.Errorf("asset %q not found (or duplicated) in the release", ma.Asset)
	}
	if ghA.Size > 0 && ghA.Size != ma.Size {
		return Asset{}, fmt.Errorf("manifest size %d for %q does not match the release-reported size %d", ma.Size, ma.Asset, ghA.Size)
	}
	if err := requireHTTPSURL(ghA.BrowserDownloadURL); err != nil {
		return Asset{}, fmt.Errorf("asset %q download URL: %w", ma.Asset, err)
	}
	return Asset{Name: ma.Asset, URL: ghA.BrowserDownloadURL, Size: ma.Size, SHA256: ma.SHA256}, nil
}

// fetchLatestRelease calls GitHub's /releases/latest, which already
// excludes drafts and prereleases by the endpoint's own definition —
// checked again here defensively rather than trusted blindly.
func fetchLatestRelease(ctx context.Context, client *http.Client, apiBase, repo, userAgent string) (*ghRelease, error) {
	url := fmt.Sprintf("%s/repos/%s/releases/latest", apiBase, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("no releases found (the distribution repository may not exist yet, or has no public releases)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d from the release API", resp.StatusCode)
	}

	data, err := readLimited(resp.Body, maxJSONBytes)
	if err != nil {
		return nil, err
	}

	var rel ghRelease
	if err := json.Unmarshal(data, &rel); err != nil {
		return nil, fmt.Errorf("malformed release API response: %w", err)
	}
	if rel.Draft || rel.Prerelease {
		return nil, fmt.Errorf("latest release is a draft or prerelease; the stable channel has no update")
	}
	if !tagPattern.MatchString(rel.TagName) {
		return nil, fmt.Errorf("release tag %q is not a valid vX.Y.Z tag", rel.TagName)
	}
	return &rel, nil
}

// findAsset returns the single asset named name. A MISSING name and a
// DUPLICATED name are both treated as "not found" — a release that
// accidentally (or maliciously) shipped two assets with the same name is
// exactly as untrustworthy as one that shipped none, since there's no
// sound way to know which of the two a caller meant.
func findAsset(assets []ghAsset, name string) (ghAsset, bool) {
	var found ghAsset
	count := 0
	for _, a := range assets {
		if a.Name == name {
			found = a
			count++
		}
	}
	if count != 1 {
		return ghAsset{}, false
	}
	return found, true
}

// fetchManifest downloads update.json and update.json.sig from rel's own
// assets and verifies the signature before returning anything — see
// sign.go's verifyManifest.
func fetchManifest(ctx context.Context, client *http.Client, rel *ghRelease, userAgent string) (*Manifest, error) {
	manifestAsset, ok := findAsset(rel.Assets, "update.json")
	if !ok {
		return nil, fmt.Errorf("release is missing a unique update.json asset")
	}
	sigAsset, ok := findAsset(rel.Assets, "update.json.sig")
	if !ok {
		return nil, fmt.Errorf("release is missing a unique update.json.sig asset")
	}
	if err := requireHTTPSURL(manifestAsset.BrowserDownloadURL); err != nil {
		return nil, fmt.Errorf("update.json download URL: %w", err)
	}
	if err := requireHTTPSURL(sigAsset.BrowserDownloadURL); err != nil {
		return nil, fmt.Errorf("update.json.sig download URL: %w", err)
	}

	manifestBytes, err := fetchAssetBytes(ctx, client, manifestAsset.BrowserDownloadURL, userAgent, maxJSONBytes)
	if err != nil {
		return nil, fmt.Errorf("downloading update.json: %w", err)
	}
	sigBytes, err := fetchAssetBytes(ctx, client, sigAsset.BrowserDownloadURL, userAgent, maxSigBytes)
	if err != nil {
		return nil, fmt.Errorf("downloading update.json.sig: %w", err)
	}

	if err := verifyManifest(manifestBytes, strings.TrimSpace(string(sigBytes))); err != nil {
		return nil, fmt.Errorf("manifest signature: %w", err)
	}

	var m Manifest
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		// The signature verified but the payload doesn't parse — this can
		// only happen if the manifest itself was published malformed, not
		// from anything a network attacker could produce (they'd need the
		// private key to get this far at all). Still fails closed either way.
		return nil, fmt.Errorf("malformed update.json (signature verified, contents unparsable): %w", err)
	}
	return &m, nil
}

func fetchAssetBytes(ctx context.Context, client *http.Client, assetURL, userAgent string, max int64) ([]byte, error) {
	// Defense in depth: callers already validate before reaching here, but
	// this must fail closed on its own too, so no future caller can bypass
	// the HTTPS-only policy just by not checking first.
	if err := requireHTTPSURL(assetURL); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, assetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return readLimited(resp.Body, max)
}

func readLimited(r io.Reader, max int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("response exceeds %d bytes", max)
	}
	return data, nil
}
