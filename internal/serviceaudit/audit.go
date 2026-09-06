// Package serviceaudit performs one bounded, protocol-safe validation against
// a service the operator already discovered. It never sends exploit payloads,
// credentials or brute-force attempts.
package serviceaudit

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"trazip/internal/dnsintel"
	"trazip/internal/tlsintel"
)

type Finding struct {
	Level    string `json:"level"` // info | low | medium | high
	Category string `json:"category"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Evidence string `json:"evidence,omitempty"`
}

type Result struct {
	Target     string            `json:"target"`
	Port       int               `json:"port"`
	Protocol   string            `json:"protocol"`
	Reachable  bool              `json:"reachable"`
	Metadata   map[string]string `json:"metadata"`
	Findings   []Finding         `json:"findings"`
	DurationMs int64             `json:"durationMs"`
	Err        string            `json:"err,omitempty"`
}

type ExposureResult struct {
	Expected   []int `json:"expected"`
	Observed   []int `json:"observed"`
	Unexpected []int `json:"unexpected"`
	Missing    []int `json:"missing"`
	Compliant  bool  `json:"compliant"`
}

func Audit(ctx context.Context, target string, port int) (r Result) {
	start := time.Now()
	r = Result{
		Target:   target,
		Port:     port,
		Metadata: map[string]string{},
		Findings: []Finding{},
	}
	defer func() { r.DurationMs = time.Since(start).Milliseconds() }()
	switch port {
	case 80, 8000, 8008, 8080, 8081:
		r.Protocol = "http"
		auditHTTP(ctx, &r, "http://"+net.JoinHostPort(target, strconv.Itoa(port))+"/")
	case 443, 8443:
		r.Protocol = "https"
		auditTLS(ctx, &r)
		if r.Reachable {
			auditHTTP(ctx, &r, "https://"+net.JoinHostPort(target, strconv.Itoa(port))+"/")
		}
	case 465, 636, 853, 993, 995, 5061:
		r.Protocol = "tls"
		auditTLS(ctx, &r)
	case 22:
		r.Protocol = "ssh"
		auditSSH(ctx, &r)
	case 53:
		r.Protocol = "dns"
		auditDNS(ctx, &r)
	case 5060:
		r.Protocol = "sip"
		auditSIP(ctx, &r)
	default:
		r.Protocol = "tcp"
		auditConnect(ctx, &r)
	}
	return r
}

func CompareExposure(observed, expected []int) ExposureResult {
	obs, exp := normalizePorts(observed), normalizePorts(expected)
	oSet, eSet := make(map[int]bool, len(obs)), make(map[int]bool, len(exp))
	for _, p := range obs {
		oSet[p] = true
	}
	for _, p := range exp {
		eSet[p] = true
	}
	r := ExposureResult{Observed: obs, Expected: exp}
	for _, p := range obs {
		if !eSet[p] {
			r.Unexpected = append(r.Unexpected, p)
		}
	}
	for _, p := range exp {
		if !oSet[p] {
			r.Missing = append(r.Missing, p)
		}
	}
	r.Compliant = len(r.Unexpected) == 0 && len(r.Missing) == 0
	return r
}

func normalizePorts(in []int) []int {
	set := map[int]bool{}
	for _, p := range in {
		if p >= 1 && p <= 65535 {
			set[p] = true
		}
	}
	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

func auditConnect(ctx context.Context, r *Result) {
	d := net.Dialer{Timeout: 4 * time.Second}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(r.Target, strconv.Itoa(r.Port)))
	if err != nil {
		r.Err = err.Error()
		return
	}
	r.Reachable = true
	_ = c.Close()
	r.Findings = append(r.Findings, Finding{Level: "info", Category: "reachability", Title: "Servicio TCP alcanzable", Detail: "La conexión TCP se completó sin enviar datos de aplicación."})
}

func auditHTTP(ctx context.Context, r *Result, rawURL string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, rawURL, nil)
	if err != nil {
		r.Err = err.Error()
		return
	}
	req.Header.Set("User-Agent", "TRAZIP defensive-audit")
	client := &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		r.Err = err.Error()
		return
	}
	defer resp.Body.Close()
	r.Reachable = true
	r.Metadata["status"] = strconv.Itoa(resp.StatusCode)
	r.Metadata["url"] = rawURL
	if loc := resp.Header.Get("Location"); loc != "" {
		r.Metadata["location"] = loc
	}
	missing := []string{}
	for _, name := range []string{"Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"} {
		if resp.Header.Get(name) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		r.Findings = append(r.Findings, Finding{Level: "low", Category: "http_headers", Title: "Cabeceras defensivas ausentes", Detail: "La respuesta no incluyó todas las cabeceras defensivas observables.", Evidence: strings.Join(missing, ", ")})
	} else {
		r.Findings = append(r.Findings, Finding{Level: "info", Category: "http_headers", Title: "Cabeceras defensivas presentes", Detail: "Las cabeceras evaluadas estuvieron presentes en la respuesta HEAD."})
	}
}

func auditTLS(ctx context.Context, r *Result) {
	t := tlsintel.Inspect(ctx, r.Target, r.Port, r.Target)
	if t.Err != "" {
		r.Err = t.Err
		return
	}
	r.Reachable = true
	r.Metadata["tls"] = t.Protocol
	r.Metadata["cipher"] = t.CipherSuite
	if !t.ValidationOK {
		r.Findings = append(r.Findings, Finding{Level: "high", Category: "tls_validation", Title: "Certificado TLS no confiable", Detail: t.ValidationError})
	}
	if t.Protocol == "TLS 1.0" || t.Protocol == "TLS 1.1" {
		r.Findings = append(r.Findings, Finding{Level: "medium", Category: "tls_version", Title: "Versión TLS obsoleta", Detail: "El endpoint negoció " + t.Protocol + "."})
	}
	if len(t.Chain) > 0 && t.Chain[0].DaysUntilExpiry < 30 {
		level := "medium"
		if t.Chain[0].Expired {
			level = "high"
		}
		r.Findings = append(r.Findings, Finding{Level: level, Category: "tls_expiry", Title: "Certificado próximo a vencer o vencido", Detail: fmt.Sprintf("Días restantes: %d", t.Chain[0].DaysUntilExpiry)})
	}
	if len(r.Findings) == 0 {
		r.Findings = append(r.Findings, Finding{Level: "info", Category: "tls", Title: "TLS validado", Detail: t.Protocol + " · " + t.CipherSuite})
	}
}

func auditSSH(ctx context.Context, r *Result) {
	d := net.Dialer{Timeout: 4 * time.Second}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(r.Target, strconv.Itoa(r.Port)))
	if err != nil {
		r.Err = err.Error()
		return
	}
	defer c.Close()
	r.Reachable = true
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	lineBytes, err := bufio.NewReaderSize(c, 512).ReadSlice('\n')
	if err != nil && len(lineBytes) == 0 {
		r.Findings = append(r.Findings, Finding{Level: "info", Category: "ssh", Title: "SSH alcanzable", Detail: "No se recibió banner dentro del límite."})
		return
	}
	line := strings.TrimSpace(string(lineBytes))
	if len(line) > 256 {
		line = line[:256]
	}
	r.Metadata["banner"] = line
	r.Findings = append(r.Findings, Finding{Level: "info", Category: "ssh_banner", Title: "Banner SSH observado", Detail: "Metadato de saludo de solo lectura.", Evidence: line})
}

func auditDNS(ctx context.Context, r *Result) {
	q := dnsintel.Query(ctx, ".", "NS", net.JoinHostPort(r.Target, strconv.Itoa(r.Port)), false)
	if q.Err != "" {
		r.Err = q.Err
		return
	}
	r.Reachable = true
	r.Metadata["rcode"] = q.RCode
	r.Findings = append(r.Findings, Finding{Level: "info", Category: "dns", Title: "DNS respondió consulta NS raíz", Detail: "Se envió una sola consulta sin transferencia de zona ni diccionario.", Evidence: q.RCode})
}

func auditSIP(ctx context.Context, r *Result) {
	r.Metadata["transport"] = "udp"
	d := net.Dialer{Timeout: 4 * time.Second}
	c, err := d.DialContext(ctx, "udp", net.JoinHostPort(r.Target, strconv.Itoa(r.Port)))
	if err != nil {
		r.Err = err.Error()
		return
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	nonce := make([]byte, 8)
	_, _ = rand.Read(nonce)
	branch := hex.EncodeToString(nonce)
	msg := fmt.Sprintf("OPTIONS sip:%s SIP/2.0\r\nVia: SIP/2.0/UDP 0.0.0.0;branch=z9hG4bK%s;rport\r\nMax-Forwards: 1\r\nTo: <sip:%s>\r\nFrom: <sip:trazip@localhost>;tag=%s\r\nCall-ID: %s@trazip.local\r\nCSeq: 1 OPTIONS\r\nUser-Agent: TRAZIP defensive-audit\r\nContent-Length: 0\r\n\r\n", r.Target, branch, r.Target, branch, branch)
	if _, err = c.Write([]byte(msg)); err != nil {
		r.Err = err.Error()
		return
	}
	buf := make([]byte, 2048)
	n, err := c.Read(buf)
	if err != nil {
		r.Err = "sin respuesta SIP OPTIONS: " + err.Error()
		return
	}
	r.Reachable = true
	status := strings.SplitN(string(buf[:n]), "\r\n", 2)[0]
	if len(status) > 256 {
		status = status[:256]
	}
	r.Metadata["status"] = status
	r.Findings = append(r.Findings, Finding{Level: "info", Category: "sip_options", Title: "SIP respondió OPTIONS", Detail: "Una única solicitud OPTIONS, sin credenciales ni registro.", Evidence: status})
}
