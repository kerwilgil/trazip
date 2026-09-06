package tlsintel

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// selfSignedCert builds a minimal, hermetic self-signed certificate so tests
// never depend on real network access or real CAs.
func selfSignedCert(t *testing.T, dnsNames []string, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: dnsNames[0], Organization: []string{"TRAZIP Test"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		DNSNames:              dnsNames,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func startTLSServer(t *testing.T, cert tls.Certificate) (host string, port int) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				tc, ok := c.(*tls.Conn)
				if !ok {
					return
				}
				tc.Handshake()
				buf := make([]byte, 1)
				tc.Read(buf)
			}(conn)
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port
}

func TestInspectValidChain(t *testing.T) {
	cert := selfSignedCert(t, []string{"trazip.test"}, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	host, port := startTLSServer(t, cert)

	res := Inspect(context.Background(), host, port, "trazip.test")
	if res.Err != "" {
		t.Fatalf("unexpected error: %s", res.Err)
	}
	if len(res.Chain) != 1 {
		t.Fatalf("Chain length = %d, want 1", len(res.Chain))
	}
	leaf := res.Chain[0]
	if leaf.Subject == "" || !strings.Contains(leaf.Subject, "trazip.test") {
		t.Errorf("Subject = %q, want it to mention trazip.test", leaf.Subject)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "trazip.test" {
		t.Errorf("DNSNames = %v, want [trazip.test]", leaf.DNSNames)
	}
	if leaf.Expired {
		t.Error("cert should not be reported as expired")
	}
	if leaf.SHA256Fingerprint == "" || len(leaf.SHA256Fingerprint) != 64 {
		t.Errorf("SHA256Fingerprint = %q, want a 64-char hex string", leaf.SHA256Fingerprint)
	}
	// Self-signed and not in the system trust store: the handshake must
	// still succeed and return the full chain, but validation must fail.
	if res.ValidationOK {
		t.Error("a self-signed cert not in the system trust store must not validate as OK")
	}
	if res.ValidationError == "" {
		t.Error("expected a validation error explaining why the chain is untrusted")
	}
	if res.Protocol == "" {
		t.Error("expected a negotiated TLS protocol version")
	}
}

func TestInspectExpiredCert(t *testing.T) {
	cert := selfSignedCert(t, []string{"expired.test"}, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	host, port := startTLSServer(t, cert)

	res := Inspect(context.Background(), host, port, "expired.test")
	if res.Err != "" {
		t.Fatalf("unexpected connection error: %s", res.Err)
	}
	if len(res.Chain) != 1 {
		t.Fatalf("Chain length = %d, want 1", len(res.Chain))
	}
	if !res.Chain[0].Expired {
		t.Error("cert with NotAfter in the past should be reported as expired")
	}
	if res.Chain[0].DaysUntilExpiry >= 0 {
		t.Errorf("DaysUntilExpiry = %d, want negative for an expired cert", res.Chain[0].DaysUntilExpiry)
	}
	if res.ValidationOK {
		t.Error("expired cert must not validate as OK")
	}
}

func TestInspectConnectionRefused(t *testing.T) {
	// Grab a free port, then close it immediately so the connection fails.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	res := Inspect(context.Background(), "127.0.0.1", port, "")
	if res.Err == "" {
		t.Error("expected a connection error for a closed port")
	}
}

func TestInspectDefaultsSNIToHost(t *testing.T) {
	cert := selfSignedCert(t, []string{"trazip.test"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	_, port := startTLSServer(t, cert)

	// SNI left empty must default to the connection host, not silently fail.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res := Inspect(ctx, "127.0.0.1", port, "")
	if res.SNI != "127.0.0.1" {
		t.Errorf("SNI = %q, want it defaulted to the host", res.SNI)
	}
}

func TestCertInfoFieldsPopulated(t *testing.T) {
	cert := selfSignedCert(t, []string{"a.test", "b.test"}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	host, port := startTLSServer(t, cert)

	res := Inspect(context.Background(), host, port, "a.test")
	if res.Err != "" {
		t.Fatalf("unexpected error: %s", res.Err)
	}
	leaf := res.Chain[0]
	if leaf.SerialNumber == "" {
		t.Error("SerialNumber should not be empty")
	}
	if leaf.SignatureAlgorithm == "" || leaf.PublicKeyAlgorithm == "" {
		t.Error("SignatureAlgorithm/PublicKeyAlgorithm should not be empty")
	}
	if len(leaf.DNSNames) != 2 {
		t.Errorf("DNSNames = %v, want 2 entries", leaf.DNSNames)
	}
}
