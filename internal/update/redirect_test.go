package update

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHTTPSToHTTPSRedirectAllowed confirms a same-scheme redirect through
// httpsOnlyRedirect still works — the policy only blocks downgrades, never
// ordinary redirects.
func TestHTTPSToHTTPSRedirectAllowed(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ok", http.StatusFound)
	})
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	client := srv.Client()
	client.CheckRedirect = httpsOnlyRedirect(maxRedirects)

	resp, err := client.Get(srv.URL + "/start")
	if err != nil {
		t.Fatalf("https->https redirect should succeed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

// TestHTTPSToHTTPRedirectRejected is the core of audit item C.7: a
// network attacker who can inject a redirect must not be able to bounce
// TRAZIP from HTTPS onto a plaintext connection.
func TestHTTPSToHTTPRedirectRejected(t *testing.T) {
	// The downgrade target — plain HTTP, never reached if the policy works.
	reached := false
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.Write([]byte("should never get here"))
	}))
	defer plain.Close()

	tlsMux := http.NewServeMux()
	tlsMux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL, http.StatusFound)
	})
	tlsSrv := httptest.NewTLSServer(tlsMux)
	defer tlsSrv.Close()

	client := tlsSrv.Client()
	client.CheckRedirect = httpsOnlyRedirect(maxRedirects)

	_, err := client.Get(tlsSrv.URL + "/start")
	if err == nil {
		t.Fatal("expected an error when a redirect downgrades https to http")
	}
	if reached {
		t.Error("the plain-HTTP downgrade target was reached — the redirect was followed")
	}
}

// TestRedirectLoopStopsAfterLimit confirms a (possibly malicious) endless
// redirect chain is bounded, not followed forever.
func TestRedirectLoopStopsAfterLimit(t *testing.T) {
	var mux http.ServeMux
	hops := 0
	mux.HandleFunc("/loop", func(w http.ResponseWriter, r *http.Request) {
		hops++
		http.Redirect(w, r, "/loop", http.StatusFound)
	})
	srv := httptest.NewTLSServer(&mux)
	defer srv.Close()

	client := srv.Client()
	client.CheckRedirect = httpsOnlyRedirect(maxRedirects)

	_, err := client.Get(srv.URL + "/loop")
	if err == nil {
		t.Fatal("expected an error from an endless redirect loop")
	}
	if hops > maxRedirects+1 {
		t.Errorf("followed %d hops, want at most %d", hops, maxRedirects+1)
	}
}

// TestCheckReleaseOverHTTPSWithRedirect exercises the full checkRelease
// pipeline (not just the raw client) through one HTTPS->HTTPS redirect, to
// confirm the policy is actually wired into production code paths, not
// only unit-tested in isolation.
func TestCheckReleaseOverHTTPSWithRedirect(t *testing.T) {
	requireWindows(t)
	appBytes, updaterBytes := []byte("app"), []byte("updater")
	appName := expectedAppAssetName("0.8.0")
	m := validManifest("0.8.0", appBytes, updaterBytes)
	manifestBytes, sigHex := signedManifest(t, m)

	mux := http.NewServeMux()
	mux.HandleFunc("/assets/update.json-redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/assets/update.json", http.StatusFound)
	})
	mux.HandleFunc("/assets/update.json", func(w http.ResponseWriter, r *http.Request) { w.Write(manifestBytes) })
	mux.HandleFunc("/assets/update.json.sig", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(sigHex)) })
	mux.HandleFunc("/assets/"+appName, func(w http.ResponseWriter, r *http.Request) { w.Write(appBytes) })
	mux.HandleFunc("/assets/"+updaterAssetName, func(w http.ResponseWriter, r *http.Request) { w.Write(updaterBytes) })

	var srv *httptest.Server
	mux.HandleFunc("/repos/kerwilgil/trazip-releases/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		release := ghReleaseJSON("v0.8.0", false, false, map[string]string{
			"update.json":     srv.URL + "/assets/update.json-redirect", // one hop before the real manifest
			"update.json.sig": srv.URL + "/assets/update.json.sig",
			appName:           srv.URL + "/assets/" + appName,
			updaterAssetName:  srv.URL + "/assets/" + updaterAssetName,
		})
		w.Write(release)
	})
	srv = httptest.NewTLSServer(mux)
	defer srv.Close()

	client := srv.Client()
	client.Timeout = apiTimeout
	client.CheckRedirect = httpsOnlyRedirect(maxRedirects)

	info, err := checkRelease(context.Background(), client, srv.URL, "kerwilgil/trazip-releases", "0.7.0", "TRAZIP/0.7.0-test")
	if err != nil {
		t.Fatalf("checkRelease over HTTPS with a same-scheme redirect: %v", err)
	}
	if !info.Available {
		t.Fatal("expected an update to be available")
	}
}
