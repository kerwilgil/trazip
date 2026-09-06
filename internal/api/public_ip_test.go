package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFetchPublicIP(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		ip      string
		family  int
		wantErr string
	}{
		{name: "IPv4 valid", status: http.StatusOK, body: `{"ip":"190.34.10.20"}`, ip: "190.34.10.20", family: 4},
		{name: "IPv6 valid", status: http.StatusOK, body: `{"ip":"2a02:6b8::1"}`, ip: "2a02:6b8::1", family: 6},
		{name: "malformed JSON", status: http.StatusOK, body: `{`, wantErr: "invalid JSON"},
		{name: "invalid IP", status: http.StatusOK, body: `{"ip":"not-an-ip"}`, wantErr: "invalid IP address"},
		{name: "HTTP error", status: http.StatusInternalServerError, body: `{}`, wantErr: "HTTP 500"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()
			got := fetchPublicIP(context.Background(), srv.URL, srv.Client())
			if got.Source != publicIPSource {
				t.Fatalf("source = %q", got.Source)
			}
			if got.IP != tt.ip || got.Family != tt.family {
				t.Fatalf("result = %+v", got)
			}
			if tt.wantErr != "" && !strings.Contains(got.Err, tt.wantErr) {
				t.Fatalf("Err = %q, want %q", got.Err, tt.wantErr)
			}
		})
	}
}

func TestFetchPublicIPHonorsContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	got := fetchPublicIP(ctx, srv.URL, srv.Client())
	if got.Err == "" {
		t.Fatal("expected cancellation error")
	}
	if got.IP != "" || got.Family != 0 {
		t.Fatalf("unexpected result: %+v", got)
	}
}
