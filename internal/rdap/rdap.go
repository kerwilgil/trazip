// Package rdap implements RDAP lookups (prompt maestro §9 Fase 4, módulo 22,
// primera mitad) the way RFC 7484 actually specifies a client should: fetch
// IANA's bootstrap registry once (which maps IP/ASN ranges to the
// responsible RIR's RDAP service), cache it, do a local longest-match
// lookup, then query that RIR directly — never a third-party redirector
// masquerading as "the RIR." Every result carries a Disclosure per §5.7.
package rdap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"trazip/internal/intel/external"
)

const (
	defaultBootstrapIPv4 = "https://data.iana.org/rdap/ipv4.json"
	defaultBootstrapIPv6 = "https://data.iana.org/rdap/ipv6.json"
	defaultBootstrapASN  = "https://data.iana.org/rdap/asn.json"
	bootstrapTTL         = 24 * time.Hour
)

// Client caches the IANA bootstrap registry so repeated lookups don't
// re-fetch it. The zero value is not usable; construct with NewClient.
type Client struct {
	HTTPClient       *http.Client
	BootstrapIPv4URL string
	BootstrapIPv6URL string
	BootstrapASNURL  string
	BootstrapDNS     string

	mu          sync.Mutex
	ipv4        []prefixEntry
	ipv6        []prefixEntry
	asn         []asnEntry
	bootstrapAt time.Time

	// El registro de dominios se carga aparte del de IP/ASN: son ficheros
	// distintos y una consulta de dominio no debe obligar a descargar los
	// otros tres, ni al revés.
	dnsServices    map[string]string // sufijo -> URL base RDAP del registro
	dnsBootstrapAt time.Time
}

type prefixEntry struct {
	Prefix netip.Prefix
	URLs   []string
}

type asnEntry struct {
	Start, End uint32
	URLs       []string
}

// NewClient builds a Client pointed at IANA's real bootstrap files.
func NewClient() *Client {
	return &Client{
		HTTPClient:       &http.Client{Timeout: 10 * time.Second},
		BootstrapIPv4URL: defaultBootstrapIPv4,
		BootstrapIPv6URL: defaultBootstrapIPv6,
		BootstrapASNURL:  defaultBootstrapASN,
		BootstrapDNS:     defaultBootstrapDNS,
	}
}

// Contact is one entity (registrant, administrative, abuse, ...) from the
// RDAP response's entities section.
type Contact struct {
	Roles   []string `json:"roles,omitempty"`
	Name    string   `json:"name,omitempty"`
	Org     string   `json:"org,omitempty"`
	Email   string   `json:"email,omitempty"`
	Phone   string   `json:"phone,omitempty"`
	Address string   `json:"address,omitempty"`
}

// Result is one RDAP lookup's outcome.
type Result struct {
	Query        string              `json:"query"`
	RIR          string              `json:"rir"`
	RDAPBaseURL  string              `json:"rdapBaseURL"`
	Handle       string              `json:"handle,omitempty"`
	Name         string              `json:"name,omitempty"`
	Country      string              `json:"country,omitempty"`
	CIDR         string              `json:"cidr,omitempty"`
	StartAddress string              `json:"startAddress,omitempty"`
	EndAddress   string              `json:"endAddress,omitempty"`
	StartASN     int64               `json:"startASN,omitempty"`
	EndASN       int64               `json:"endASN,omitempty"`
	Status       []string            `json:"status,omitempty"`
	Contacts     []Contact           `json:"contacts,omitempty"`
	AbuseEmail   string              `json:"abuseEmail,omitempty"`
	Nameservers  []string            `json:"nameservers,omitempty"`
	Remarks      []string            `json:"remarks,omitempty"`
	Registered   string              `json:"registered,omitempty"`  // RFC3339, empty if unknown
	LastChanged  string              `json:"lastChanged,omitempty"` // RFC3339, empty if unknown
	Disclosure   external.Disclosure `json:"disclosure"`
	Err          string              `json:"err,omitempty"`
}

// bootstrapFile is IANA's RFC 7484 bootstrap registry format:
// {"services": [ [ ["resource1","resource2"], ["https://rir.example/"] ], ... ]}
type bootstrapFile struct {
	Services [][2][]string `json:"services"`
}

func (c *Client) ensureBootstrap(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.bootstrapAt) < bootstrapTTL && c.bootstrapAt.After(time.Time{}) {
		return nil
	}

	ipv4, err := c.fetchPrefixBootstrap(ctx, c.BootstrapIPv4URL)
	if err != nil {
		return fmt.Errorf("bootstrap IPv4: %w", err)
	}
	ipv6, err := c.fetchPrefixBootstrap(ctx, c.BootstrapIPv6URL)
	if err != nil {
		return fmt.Errorf("bootstrap IPv6: %w", err)
	}
	asn, err := c.fetchASNBootstrap(ctx, c.BootstrapASNURL)
	if err != nil {
		return fmt.Errorf("bootstrap ASN: %w", err)
	}

	c.ipv4, c.ipv6, c.asn = ipv4, ipv6, asn
	c.bootstrapAt = time.Now()
	return nil
}

func (c *Client) fetchJSON(ctx context.Context, url string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}

func (c *Client) fetchPrefixBootstrap(ctx context.Context, url string) ([]prefixEntry, error) {
	var bf bootstrapFile
	if err := c.fetchJSON(ctx, url, &bf); err != nil {
		return nil, err
	}
	var entries []prefixEntry
	for _, svc := range bf.Services {
		resources, urls := svc[0], svc[1]
		for _, r := range resources {
			p, err := netip.ParsePrefix(r)
			if err != nil {
				continue
			}
			entries = append(entries, prefixEntry{Prefix: p, URLs: urls})
		}
	}
	return entries, nil
}

func (c *Client) fetchASNBootstrap(ctx context.Context, url string) ([]asnEntry, error) {
	var bf bootstrapFile
	if err := c.fetchJSON(ctx, url, &bf); err != nil {
		return nil, err
	}
	var entries []asnEntry
	for _, svc := range bf.Services {
		resources, urls := svc[0], svc[1]
		for _, r := range resources {
			start, end, ok := parseASNRange(r)
			if !ok {
				continue
			}
			entries = append(entries, asnEntry{Start: start, End: end, URLs: urls})
		}
	}
	return entries, nil
}

func parseASNRange(s string) (start, end uint32, ok bool) {
	parts := strings.SplitN(s, "-", 2)
	a, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return 0, 0, false
	}
	if len(parts) == 1 {
		return uint32(a), uint32(a), true
	}
	b, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return 0, 0, false
	}
	return uint32(a), uint32(b), true
}

func (c *Client) findRIR(addr netip.Addr) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entries := c.ipv4
	if addr.Is6() && !addr.Is4In6() {
		entries = c.ipv6
	}
	var best prefixEntry
	bestBits := -1
	for _, e := range entries {
		if e.Prefix.Contains(addr) && e.Prefix.Bits() > bestBits {
			best = e
			bestBits = e.Prefix.Bits()
		}
	}
	if bestBits < 0 || len(best.URLs) == 0 {
		return "", false
	}
	return best.URLs[0], true
}

func (c *Client) findRIRForASN(asn uint32) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.asn {
		if asn >= e.Start && asn <= e.End && len(e.URLs) > 0 {
			return e.URLs[0], true
		}
	}
	return "", false
}

// LookupIP queries RDAP for the RIR responsible for ip.
func (c *Client) LookupIP(ctx context.Context, ip string) (Result, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return Result{Query: ip, Err: "IP inválida: " + err.Error()}, err
	}
	if err := c.ensureBootstrap(ctx); err != nil {
		res := Result{Query: ip, Err: "no se pudo cargar el registro bootstrap de IANA: " + err.Error()}
		return res, err
	}
	base, ok := c.findRIR(addr)
	if !ok {
		res := Result{Query: ip, Err: "no hay un RIR bootstrap conocido para esta dirección"}
		return res, errors.New(res.Err)
	}
	url := strings.TrimRight(base, "/") + "/ip/" + addr.String()
	return c.query(ctx, ip, base, url, "dirección IP")
}

// LookupASN queries RDAP for the RIR responsible for an Autonomous System.
func (c *Client) LookupASN(ctx context.Context, asn int) (Result, error) {
	if asn < 0 {
		return Result{Err: "ASN inválido"}, fmt.Errorf("ASN inválido")
	}
	if err := c.ensureBootstrap(ctx); err != nil {
		res := Result{Query: fmt.Sprintf("AS%d", asn), Err: "no se pudo cargar el registro bootstrap de IANA: " + err.Error()}
		return res, err
	}
	base, ok := c.findRIRForASN(uint32(asn))
	if !ok {
		res := Result{Query: fmt.Sprintf("AS%d", asn), Err: "no hay un RIR bootstrap conocido para este ASN"}
		return res, errors.New(res.Err)
	}
	url := strings.TrimRight(base, "/") + "/autnum/" + strconv.Itoa(asn)
	return c.query(ctx, fmt.Sprintf("AS%d", asn), base, url, "número de sistema autónomo (ASN)")
}

type rdapEntity struct {
	Roles      []string        `json:"roles"`
	Handle     string          `json:"handle"`
	VCardArray json.RawMessage `json:"vcardArray"`
}

type rdapEvent struct {
	Action string `json:"eventAction"`
	Date   string `json:"eventDate"`
}

type rdapRemark struct {
	Title       string   `json:"title"`
	Description []string `json:"description"`
}

// rdapCidr0 is one entry of the RFC 8977 cidr0_cidrs extension — the exact
// CIDR a RIR allocated, more precise than reconstructing it from
// startAddress/endAddress (which can span a non-power-of-two range made of
// several CIDRs).
type rdapCidr0 struct {
	V4Prefix string `json:"v4prefix"`
	V6Prefix string `json:"v6prefix"`
	Length   int    `json:"length"`
}

// rdapNameserver is one entry of the optional nameservers array some RIRs
// (notably LACNIC) attach to an IP network object for its reverse-DNS
// delegation — the RDAP equivalent of classic whois's "nserver" lines.
type rdapNameserver struct {
	LDHName string `json:"ldhName"`
}

type rdapResponse struct {
	Handle       string           `json:"handle"`
	Name         string           `json:"name"`
	Country      string           `json:"country"`
	StartAddress string           `json:"startAddress"`
	EndAddress   string           `json:"endAddress"`
	StartAutnum  int64            `json:"startAutnum"`
	EndAutnum    int64            `json:"endAutnum"`
	Status       []string         `json:"status"`
	Entities     []rdapEntity     `json:"entities"`
	Remarks      []rdapRemark     `json:"remarks"`
	Events       []rdapEvent      `json:"events"`
	Cidr0Cidrs   []rdapCidr0      `json:"cidr0_cidrs"`
	Nameservers  []rdapNameserver `json:"nameservers"`
	ErrorCode    int              `json:"errorCode"`
	Title        string           `json:"title"`
	Description  []string         `json:"description"`
}

func (c *Client) query(ctx context.Context, queryLabel, base, url, dataSent string) (Result, error) {
	res := Result{Query: queryLabel, RDAPBaseURL: base, RIR: rirNameFromBase(base)}
	res.Disclosure = external.Disclosure{
		Source:      "RDAP (" + res.RIR + ")",
		QueriedAt:   external.Now(),
		DataSent:    dataSent,
		CachePolicy: "registro bootstrap IANA cacheado 24h; la consulta RDAP en sí no se cachea",
		Confidence:  "alta",
		RateLimit:   "sujeto al rate limit público del RIR consultado; usar bajo demanda, no en bucle",
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		res.Err = err.Error()
		return res, err
	}
	req.Header.Set("Accept", "application/rdap+json")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		res.Err = err.Error()
		return res, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		res.Err = err.Error()
		return res, err
	}
	if resp.StatusCode == http.StatusNotFound {
		res.Err = "no encontrado en " + res.RIR
		return res, nil
	}
	if resp.StatusCode != http.StatusOK {
		res.Err = fmt.Sprintf("%s respondió HTTP %d", res.RIR, resp.StatusCode)
		return res, nil
	}

	var parsed rdapResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		res.Err = "respuesta RDAP no interpretable: " + err.Error()
		return res, err
	}

	res.Handle = parsed.Handle
	res.Name = parsed.Name
	res.Country = parsed.Country
	res.StartAddress = parsed.StartAddress
	res.EndAddress = parsed.EndAddress
	res.StartASN = parsed.StartAutnum
	res.EndASN = parsed.EndAutnum
	res.Status = parsed.Status
	if len(parsed.Cidr0Cidrs) > 0 {
		c := parsed.Cidr0Cidrs[0]
		if c.V4Prefix != "" {
			res.CIDR = fmt.Sprintf("%s/%d", c.V4Prefix, c.Length)
		} else if c.V6Prefix != "" {
			res.CIDR = fmt.Sprintf("%s/%d", c.V6Prefix, c.Length)
		}
	}
	for _, ns := range parsed.Nameservers {
		if ns.LDHName != "" {
			res.Nameservers = append(res.Nameservers, ns.LDHName)
		}
	}
	for _, r := range parsed.Remarks {
		if r.Title != "" {
			res.Remarks = append(res.Remarks, r.Title+": "+strings.Join(r.Description, " "))
		} else {
			res.Remarks = append(res.Remarks, strings.Join(r.Description, " "))
		}
	}
	for _, ev := range parsed.Events {
		t, terr := time.Parse(time.RFC3339, ev.Date)
		if terr != nil {
			continue
		}
		switch ev.Action {
		case "registration":
			res.Registered = t.Format(time.RFC3339)
		case "last changed":
			res.LastChanged = t.Format(time.RFC3339)
		}
	}
	for _, e := range parsed.Entities {
		contact := Contact{Roles: e.Roles}
		contact.Name, contact.Org, contact.Email, contact.Phone, contact.Address = parseVCard(e.VCardArray)
		res.Contacts = append(res.Contacts, contact)
		for _, role := range e.Roles {
			if role == "abuse" && contact.Email != "" {
				res.AbuseEmail = contact.Email
			}
		}
	}

	return res, nil
}

func rirNameFromBase(base string) string {
	base = strings.ToLower(base)
	switch {
	case strings.Contains(base, "arin.net"):
		return "ARIN"
	case strings.Contains(base, "ripe.net"):
		return "RIPE NCC"
	case strings.Contains(base, "apnic.net"):
		return "APNIC"
	case strings.Contains(base, "lacnic.net"):
		return "LACNIC"
	case strings.Contains(base, "afrinic.net"):
		return "AFRINIC"
	default:
		return base
	}
}

// parseVCard extracts name/org/email/phone/address from a jCard array
// (["vcard", [ ["fn",{},"text","Name"], ["email",{},"text","a@b.com"], ... ]])
// without a full vCard implementation — RDAP only ever uses this handful of
// fields for the identity information §22 asks for. "adr" is special-cased:
// per RFC 6350 its value is a 7-element structured array (PO box, extended
// address, street, locality, region, postal code, country), not a plain
// string like every other field here.
func parseVCard(raw json.RawMessage) (name, org, email, phone, address string) {
	if len(raw) == 0 {
		return
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil || len(arr) < 2 {
		return
	}
	var fields [][]json.RawMessage
	if err := json.Unmarshal(arr[1], &fields); err != nil {
		return
	}
	for _, f := range fields {
		if len(f) < 4 {
			continue
		}
		var fieldName string
		json.Unmarshal(f[0], &fieldName)
		if strings.ToLower(fieldName) == "adr" {
			var parts []string
			if err := json.Unmarshal(f[3], &parts); err == nil {
				var nonEmpty []string
				for _, p := range parts {
					if strings.TrimSpace(p) != "" {
						nonEmpty = append(nonEmpty, p)
					}
				}
				address = strings.Join(nonEmpty, ", ")
			}
			continue
		}
		var value string
		json.Unmarshal(f[3], &value)
		switch strings.ToLower(fieldName) {
		case "fn":
			name = value
		case "org":
			org = value
		case "email":
			email = value
		case "tel":
			phone = value
		}
	}
	return
}
