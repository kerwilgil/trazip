// Package tlsintel implements the TLS Inspector (prompt maestro §9 Fase 4,
// módulo 20): a direct handshake against a host that reports the full
// certificate chain, negotiated protocol/cipher/ALPN and validation errors
// without ever hiding an untrusted chain — verification always runs
// separately from the handshake itself, over crypto/tls + crypto/x509
// (approved in §5.3, no third-party dependency needed).
package tlsintel

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"time"
)

// CertInfo is one certificate in the presented chain.
type CertInfo struct {
	Subject            string   `json:"subject"`
	Issuer             string   `json:"issuer"`
	DNSNames           []string `json:"dnsNames,omitempty"`
	IPAddresses        []string `json:"ipAddresses,omitempty"`
	NotBefore          string   `json:"notBefore"` // RFC3339
	NotAfter           string   `json:"notAfter"`  // RFC3339
	Expired            bool     `json:"expired"`
	DaysUntilExpiry    int      `json:"daysUntilExpiry"`
	SerialNumber       string   `json:"serialNumber"`
	SignatureAlgorithm string   `json:"signatureAlgorithm"`
	PublicKeyAlgorithm string   `json:"publicKeyAlgorithm"`
	SHA256Fingerprint  string   `json:"sha256Fingerprint"`
	IsCA               bool     `json:"isCA"`
}

// Result is the outcome of inspecting one host:port's TLS endpoint.
type Result struct {
	Host            string     `json:"host"`
	Port            int        `json:"port"`
	SNI             string     `json:"sni"`
	Protocol        string     `json:"protocol"` // e.g. "TLS 1.3"
	CipherSuite     string     `json:"cipherSuite"`
	ALPN            string     `json:"alpn"`
	Chain           []CertInfo `json:"chain"`
	ValidationOK    bool       `json:"validationOK"`
	ValidationError string     `json:"validationError,omitempty"`
	DurationMs      int64      `json:"durationMs"`
	Err             string     `json:"err,omitempty"`
}

// Inspect connects to host:port, completes a TLS handshake with SNI set to
// sni (defaults to host when empty), and reports the chain as presented —
// the handshake itself never validates the chain (InsecureSkipVerify) so an
// untrusted or expired certificate still yields a full report instead of a
// bare connection error; ValidationOK/ValidationError come from a separate
// verification pass against the system trust store.
func Inspect(ctx context.Context, host string, port int, sni string) Result {
	start := time.Now()
	if sni == "" {
		sni = host
	}
	res := Result{Host: host, Port: port, SNI: sni}

	dialer := &net.Dialer{Timeout: 8 * time.Second}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		res.Err = err.Error()
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	}
	defer rawConn.Close()

	cfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // chain retrieval only; verified separately below
		NextProtos:         []string{"h2", "http/1.1"},
		MinVersion:         tls.VersionTLS10,
	}
	conn := tls.Client(rawConn, cfg)
	conn.SetDeadline(time.Now().Add(8 * time.Second))
	if err := conn.HandshakeContext(ctx); err != nil {
		res.Err = err.Error()
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	}
	defer conn.Close()

	state := conn.ConnectionState()
	res.Protocol = tls.VersionName(state.Version)
	res.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	res.ALPN = state.NegotiatedProtocol

	for _, cert := range state.PeerCertificates {
		res.Chain = append(res.Chain, toCertInfo(cert))
	}

	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		intermediates := x509.NewCertPool()
		for _, c := range state.PeerCertificates[1:] {
			intermediates.AddCert(c)
		}
		_, verr := leaf.Verify(x509.VerifyOptions{
			DNSName:       sni,
			Roots:         roots,
			Intermediates: intermediates,
		})
		if verr != nil {
			res.ValidationError = verr.Error()
		} else {
			res.ValidationOK = true
		}
	}

	res.DurationMs = time.Since(start).Milliseconds()
	return res
}

func toCertInfo(cert *x509.Certificate) CertInfo {
	sum := sha256.Sum256(cert.Raw)
	ips := make([]string, len(cert.IPAddresses))
	for i, ip := range cert.IPAddresses {
		ips[i] = ip.String()
	}
	days := int(time.Until(cert.NotAfter).Hours() / 24)
	return CertInfo{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		DNSNames:           cert.DNSNames,
		IPAddresses:        ips,
		NotBefore:          cert.NotBefore.Format(time.RFC3339),
		NotAfter:           cert.NotAfter.Format(time.RFC3339),
		Expired:            time.Now().After(cert.NotAfter),
		DaysUntilExpiry:    days,
		SerialNumber:       cert.SerialNumber.String(),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		SHA256Fingerprint:  hex.EncodeToString(sum[:]),
		IsCA:               cert.IsCA,
	}
}

// String renders a one-line summary, useful for logs and CLI output.
func (r Result) String() string {
	if r.Err != "" {
		return fmt.Sprintf("%s:%d: error: %s", r.Host, r.Port, r.Err)
	}
	return fmt.Sprintf("%s:%d (SNI %s) %s %s ALPN=%s validación=%v", r.Host, r.Port, r.SNI, r.Protocol, r.CipherSuite, r.ALPN, r.ValidationOK)
}
