package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// maxDownloadBytes bounds a single update asset — generous for a ~25MB
// TRAZIP.exe with headroom, but still a hard ceiling against a compromised
// or misconfigured server sending something enormous. Enforced against
// BOTH the server's declared Content-Length and the actual bytes received,
// since a lying Content-Length must not be trusted either.
const maxDownloadBytes = 300 * 1024 * 1024 // 300 MiB

// downloadAsset streams url to destDir/name+".partial", honoring ctx
// cancellation. It never produces a file at the final "real" name — only
// the caller, after verifying the .partial's SHA-256, may rename it into a
// trusted path. A cancelled or failed download always removes its own
// .partial rather than leaving a half-written file behind.
func downloadAsset(ctx context.Context, client *http.Client, assetURL, destDir, name string, expectedSize int64, progress func(downloaded, total int64)) (path string, err error) {
	// Defense in depth: the caller (Manager.downloadAndVerify) already
	// validated this URL via resolveGitHubAsset, but downloadAsset must
	// fail closed on its own too, so no future caller can bypass the
	// HTTPS-only policy just by not checking first.
	if err := requireHTTPSURL(assetURL); err != nil {
		return "", err
	}
	if expectedSize > maxDownloadBytes {
		return "", fmt.Errorf("asset size %d exceeds the %d byte limit", expectedSize, maxDownloadBytes)
	}
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return "", err
	}
	partialPath := filepath.Join(destDir, name+".partial")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, assetURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d downloading asset", resp.StatusCode)
	}
	if resp.ContentLength > maxDownloadBytes {
		return "", fmt.Errorf("server-reported size %d exceeds the %d byte limit", resp.ContentLength, maxDownloadBytes)
	}

	total := expectedSize
	if resp.ContentLength > 0 {
		total = resp.ContentLength
	}

	out, err := os.OpenFile(partialPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}

	// LimitReader's +1 lets copyWithProgress notice an oversized body (one
	// byte past the limit reads successfully instead of silently stopping
	// exactly at the boundary) and report it as a real error below, rather
	// than quietly truncating and letting a hash check catch it later.
	limited := io.LimitReader(resp.Body, maxDownloadBytes+1)
	written, copyErr := copyWithProgress(out, limited, total, progress)
	closeErr := out.Close()

	if copyErr != nil || closeErr != nil {
		os.Remove(partialPath)
		if copyErr != nil {
			return "", copyErr
		}
		return "", closeErr
	}
	if written > maxDownloadBytes {
		os.Remove(partialPath)
		return "", fmt.Errorf("downloaded content exceeds the %d byte limit", maxDownloadBytes)
	}
	// A signed manifest's Size is exactly as trustworthy as its SHA-256 —
	// both come from the same verified update.json — so a byte count that
	// merely fits under the cap isn't enough; it must match exactly.
	if expectedSize > 0 && written != expectedSize {
		os.Remove(partialPath)
		return "", fmt.Errorf("downloaded %d bytes, expected exactly %d", written, expectedSize)
	}
	return partialPath, nil
}

func copyWithProgress(dst io.Writer, src io.Reader, total int64, progress func(downloaded, total int64)) (int64, error) {
	buf := make([]byte, 32*1024)
	var written int64
	for {
		n, rErr := src.Read(buf)
		if n > 0 {
			w, wErr := dst.Write(buf[:n])
			written += int64(w)
			if wErr != nil {
				return written, wErr
			}
			if progress != nil {
				progress(written, total)
			}
		}
		if rErr != nil {
			if rErr == io.EOF {
				return written, nil
			}
			return written, rErr
		}
	}
}

// verifyFileSHA256 hashes path and compares it (case-insensitively) against
// expectedHex — the last gate before a downloaded file is ever considered
// trustworthy enough to hand to the updater.
func verifyFileSHA256(path, expectedHex string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, expectedHex) {
		return fmt.Errorf("sha256 mismatch: got %s, want %s", got, expectedHex)
	}
	return nil
}
