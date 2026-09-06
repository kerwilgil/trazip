// Bogon Intelligence — v1.3 Gate 4. A one-shot lookup of one IP or prefix
// against two independent, separately-classified datasources — never a
// subscription, never polling, never a background feed updater.
//
// IANA special-purpose != Team Cymru fullbogon — these are two different
// registries with two different meanings, and this file never collapses
// them into one boolean. IANA's own registry documentation explicitly
// warns that appearing in the special-purpose registry does not imply a
// uniform routability property; Team Cymru's Fullbogons list means only
// "currently allocated-but-unannounced or unallocated, per Team Cymru's
// own tracking" — neither says anything about attack, hijack, malware,
// abuse, compromise, or safety. This file never produces IsBad/
// IsMalicious/IsAttack/IsDangerous/IsBogon or any other collapsed
// boolean; IANASpecialPurpose and CymruFullBogon are reported and
// preserved independently, and every combination (in both, in neither,
// in only one) is a normal, expected outcome.
//
// LIVE SOURCE PREFLIGHT (verified before writing any parser):
//   - IANA IPv4/IPv6 special-purpose registry CSVs both have the header
//     "Address Block,Name,RFC,Allocation Date,Termination Date,Source,
//     Destination,Forwardable,Globally Reachable,Reserved-by-Protocol"
//     (confirmed live, byte-identical column names on both registries).
//     Boolean columns render as the literal strings "True"/"False"; a
//     row can carry a quoted, comma-separated multi-prefix Address Block
//     (confirmed live: "192.0.0.170/32, 192.0.0.171/32" for the NAT64/
//     DNS64 Discovery entry) that must split into independent prefixes
//     sharing the same row metadata.
//   - Team Cymru's fullbogons-ipv4.txt/fullbogons-ipv6.txt are plain
//     text, one CIDR per line, "#"-prefixed comment lines (confirmed
//     live: "# last updated ...", "# Know your network!  Please
//     rigorously test all filters!"), no blank lines observed but
//     handled defensively anyway. Bodies observed live: ~70KB (IPv4,
//     ~3500 entries), comparable order of magnitude for IPv6 (~2800
//     entries) — see bogonFeedMaxBytes below for the resulting limit.
package bgp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"regexp"
	"strings"

	"trazip/internal/intel/external"
)

// ianaIPv4CSVURL/ianaIPv6CSVURL/cymruIPv4URL/cymruIPv6URL are package
// variables, not constants, specifically so tests in this package can
// redirect them to a local fixture server without needing any change to
// Client's own fields/contract (bgp.go's Client is RIPEstat-shaped;
// these are four unrelated external feeds).
var (
	ianaIPv4CSVURL = "https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry-1.csv"
	ianaIPv6CSVURL = "https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry-1.csv"
	cymruIPv4URL   = "https://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt"
	cymruIPv6URL   = "https://www.team-cymru.org/Services/Bogons/fullbogons-ipv6.txt"
)

// bogonFeedMaxBytes bounds every Gate 4 feed download. The largest body
// observed live (Team Cymru's fullbogons-ipv4.txt) was ~70KB; this limit
// is roughly 115x that, comfortably over the required >=2x margin while
// staying far under the 32MiB ceiling — generous enough to tolerate feed
// growth for years without ever being mistaken for "no limit at all".
const bogonFeedMaxBytes = 8 * 1024 * 1024 // 8 MiB

// fetchBogonFeed downloads url via c.client() (reusing the same
// *http.Client Client already uses for RIPEstat — this is deliberately
// NOT Client.get(), which is RIPEstat-JSON-shaped and has its own,
// differently-justified body limit that this file must not touch),
// respecting ctx, requiring HTTP 200, and refusing to treat a body that
// hits the byte limit as complete: it reads one byte past the limit
// specifically so a truncated-but-under-limit body is never silently
// accepted as the whole feed.
func (c *Client) fetchBogonFeed(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d desde %s", resp.StatusCode, url)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, bogonFeedMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("error leyendo cuerpo de %s: %w", url, err)
	}
	if len(body) > bogonFeedMaxBytes {
		return nil, fmt.Errorf("respuesta de %s excede el límite de %d bytes — rechazada completa, nunca parseada parcialmente", url, bogonFeedMaxBytes)
	}
	return body, nil
}

func ianaDisclosure(dataSent string) external.Disclosure {
	return external.Disclosure{
		Source:      "IANA (Internet Assigned Numbers Authority)",
		QueriedAt:   external.Now(),
		DataSent:    dataSent,
		CachePolicy: "sin caché local — cada consulta descarga el registry completo",
		Confidence:  "alta — registry autoritativo publicado directamente por IANA",
		RateLimit:   "CSV público sin autenticación; uso razonable, no hacer polling en bucle",
	}
}

func cymruDisclosure(dataSent string) external.Disclosure {
	return external.Disclosure{
		Source:      "Team Cymru (Fullbogons)",
		QueriedAt:   external.Now(),
		DataSent:    dataSent,
		CachePolicy: "sin caché local — cada consulta descarga el feed completo",
		Confidence:  "media — lista mantenida por un tercero, cambia con el tiempo",
		RateLimit:   "feed público de texto plano sin autenticación; uso razonable, no hacer polling en bucle",
	}
}

// BogonLookupRequest queries one IP or prefix against both datasources.
// ASNs, country codes, hostnames, and arbitrary strings are rejected
// locally (see validateBogonLookupRequest) — this Gate only ever
// classifies addresses and prefixes.
type BogonLookupRequest struct {
	Resource string
}

// IANASpecialPurposeMatch is the most specific IANA special-purpose
// registry row that fully contains the queried resource, preserved
// verbatim. Every *bool is nil when IANA's own CSV cell was empty/N/A —
// never coerced to false, since IANA leaving a property undeclared is
// not the same claim as IANA declaring it false.
type IANASpecialPurposeMatch struct {
	Prefix          string `json:"prefix"`
	Name            string `json:"name"`
	RFC             string `json:"rfc"`
	AllocationDate  string `json:"allocationDate"`
	TerminationDate string `json:"terminationDate"`

	Source             *bool `json:"source,omitempty"`
	Destination        *bool `json:"destination,omitempty"`
	Forwardable        *bool `json:"forwardable,omitempty"`
	GloballyReachable  *bool `json:"globallyReachable,omitempty"`
	ReservedByProtocol *bool `json:"reservedByProtocol,omitempty"`
}

// BogonLookupResult is the bounded, honest result of one
// BogonLookupRequest. IANASpecialPurpose and CymruFullBogon are
// independent — every one of the four (true,true)/(true,false)/
// (false,true)/(false,false) combinations is normal and expected, and
// neither field is ever synthesized from the other.
type BogonLookupResult struct {
	Resource     string `json:"resource"`
	ResourceKind string `json:"resourceKind"` // "ip" | "prefix"
	Family       int    `json:"family"`       // 4 | 6

	// IANASpecialPurpose: nil = IANA datasource could not be determined
	// (HTTP/parse failure); false = feed fetched and parsed correctly,
	// no special-purpose entry fully contains Resource; true = a
	// special-purpose entry fully contains Resource (see IANAMatch).
	IANASpecialPurpose *bool                    `json:"ianaSpecialPurpose,omitempty"`
	IANAMatch          *IANASpecialPurposeMatch `json:"ianaMatch,omitempty"`

	// CymruFullBogon: nil = Team Cymru datasource could not be
	// determined; false = feed fetched and parsed correctly, no
	// fullbogon entry fully contains Resource; true = a fullbogon entry
	// fully contains Resource (see CymruMatchPrefix).
	CymruFullBogon   *bool  `json:"cymruFullBogon,omitempty"`
	CymruMatchPrefix string `json:"cymruMatchPrefix,omitempty"`

	// DataSufficient is true only when BOTH datasources succeeded AND
	// both classifications were determined (IANASpecialPurpose != nil
	// AND CymruFullBogon != nil). A single failed datasource makes the
	// whole lookup insufficient, but the other datasource's real,
	// already-determined classification is still preserved in the
	// struct and in Evidence — never discarded.
	DataSufficient bool `json:"dataSufficient"`

	Evidence []ComponentEvidence `json:"evidence"`
	Err      string              `json:"err,omitempty"`
}

// validateBogonLookupRequest enforces the full Gate 4 local contract
// before any network access, entirely via ClassifyResource — an ASN,
// country code, hostname, malformed IP, malformed prefix, or empty
// string is KindInvalid/KindASN and rejected here with zero HTTP calls.
// A single IP is represented as ResourceKind="ip" (never silently
// reframed as "the user asked for a /32 or /128 prefix" — that
// distinction is used only internally for containment checks, see
// containsResource).
func validateBogonLookupRequest(req BogonLookupRequest) (kind string, family int, addr netip.Addr, prefix netip.Prefix, isPrefix bool, resource string, err error) {
	trimmed := strings.TrimSpace(req.Resource)
	if trimmed == "" {
		return "", 0, netip.Addr{}, netip.Prefix{}, false, "", fmt.Errorf("Resource vacío — obligatorio")
	}

	switch classified, normalized := ClassifyResource(trimmed); classified {
	case KindIPv4:
		a, perr := netip.ParseAddr(normalized)
		if perr != nil {
			return "", 0, netip.Addr{}, netip.Prefix{}, false, "", fmt.Errorf("IP inválida: %q", req.Resource)
		}
		return "ip", 4, a, netip.Prefix{}, false, normalized, nil
	case KindIPv6:
		a, perr := netip.ParseAddr(normalized)
		if perr != nil {
			return "", 0, netip.Addr{}, netip.Prefix{}, false, "", fmt.Errorf("IP inválida: %q", req.Resource)
		}
		return "ip", 6, a, netip.Prefix{}, false, normalized, nil
	case KindPrefix4:
		p, perr := netip.ParsePrefix(normalized)
		if perr != nil {
			return "", 0, netip.Addr{}, netip.Prefix{}, false, "", fmt.Errorf("prefijo inválido: %q", req.Resource)
		}
		return "prefix", 4, netip.Addr{}, p, true, normalized, nil
	case KindPrefix6:
		p, perr := netip.ParsePrefix(normalized)
		if perr != nil {
			return "", 0, netip.Addr{}, netip.Prefix{}, false, "", fmt.Errorf("prefijo inválido: %q", req.Resource)
		}
		return "prefix", 6, netip.Addr{}, p, true, normalized, nil
	}
	return "", 0, netip.Addr{}, netip.Prefix{}, false, "", fmt.Errorf("recurso inválido (se espera IP o prefijo IPv4/IPv6, no ASN/país/hostname): %q", req.Resource)
}

// containsResource reports whether candidate FULLY contains the queried
// resource. For a single-IP query this is exactly candidate.Contains
// (addr) — no partial-containment concept applies to a point. For a
// prefix query, candidate must be at least as general (candidate.Bits()
// <= query.Bits()) AND contain the query's base address — for two valid
// CIDR blocks this is sufficient to guarantee the query is entirely
// inside candidate (CIDR blocks are hierarchically nested or disjoint,
// never partially overlapping), so this never reports true on the
// partial-overlap case the Gate explicitly forbids (e.g. 8.0.0.0/7 is
// NOT fully inside 10.0.0.0/8, and this returns false for that pair).
func containsResource(candidate netip.Prefix, addr netip.Addr, queryPrefix netip.Prefix, isPrefix bool) bool {
	if !isPrefix {
		return candidate.Contains(addr)
	}
	return candidate.Bits() <= queryPrefix.Bits() && candidate.Contains(queryPrefix.Addr())
}

// ---- IANA CSV parsing ----

// ianaCSVRequiredColumns is the full header this file knows how to map —
// columns are matched by name (never fixed index), and if the feed's
// header is missing even one of these, the whole feed is Degraded rather
// than guessed at.
var ianaCSVRequiredColumns = []string{
	"Address Block", "Name", "RFC", "Allocation Date", "Termination Date",
	"Source", "Destination", "Forwardable", "Globally Reachable", "Reserved-by-Protocol",
}

type ianaEntry struct {
	Prefix          netip.Prefix
	Name            string
	RFC             string
	AllocationDate  string
	TerminationDate string

	Source             *bool
	Destination        *bool
	Forwardable        *bool
	GloballyReachable  *bool
	ReservedByProtocol *bool
}

// footnoteMarkerRE matches a trailing bracketed footnote reference IANA
// embeds directly inside cell values (verified live: "192.0.0.0/24 [2]"
// in Address Block, "False [1]" in a boolean column) — this package never
// interprets what a footnote SAYS (that requires reading IANA's own
// registry page prose, out of scope), but a footnote's mere presence must
// never corrupt a cell's real structural value (a valid prefix, or a
// true/false state) into looking malformed or absent.
var footnoteMarkerRE = regexp.MustCompile(`\s*\[\d+\]\s*$`)

func stripFootnoteMarker(s string) string {
	return footnoteMarkerRE.ReplaceAllString(strings.TrimSpace(s), "")
}

// splitAddressBlock splits one CSV "Address Block" cell into its
// constituent prefix strings — most rows have exactly one, but a row can
// legitimately carry several comma-separated prefixes sharing the same
// row metadata (confirmed live: "192.0.0.170/32, 192.0.0.171/32"), and
// any individual prefix can carry a trailing footnote marker (confirmed
// live: "192.0.0.0/24 [2]") that must be stripped before parsing.
func splitAddressBlock(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = stripFootnoteMarker(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseIANABool maps IANA's literal "True"/"False" cell values —
// anything else (empty, "N/A", a future value IANA might introduce) maps
// to nil, never guessed into false. An empty cell is not a claim of
// "false"; it is IANA declining to state the property for that row.
func parseIANABool(raw string) *bool {
	switch strings.ToLower(stripFootnoteMarker(raw)) {
	case "true":
		v := true
		return &v
	case "false":
		v := false
		return &v
	default:
		return nil
	}
}

// parseIANACSV decodes one IANA special-purpose registry CSV body,
// mapping columns by name. Any structural problem — an unreadable
// header, a missing required column, a row encoding/csv itself can't
// parse, or an Address Block cell that doesn't split into valid
// netip.Prefix values — degrades the WHOLE feed (returns an error) rather
// than silently returning a partial entry list.
func parseIANACSV(body []byte) ([]ianaEntry, error) {
	r := csv.NewReader(bytes.NewReader(body))
	header, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("no se pudo leer encabezado CSV IANA: %w", err)
	}
	colIndex := make(map[string]int, len(header))
	for i, h := range header {
		colIndex[strings.TrimSpace(h)] = i
	}
	for _, want := range ianaCSVRequiredColumns {
		if _, ok := colIndex[want]; !ok {
			return nil, fmt.Errorf("CSV IANA sin columna requerida %q", want)
		}
	}

	var entries []ianaEntry
	rowNum := 1
	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		rowNum++
		if err != nil {
			return nil, fmt.Errorf("fila %d del CSV IANA malformada: %w", rowNum, err)
		}
		addrBlockRaw := record[colIndex["Address Block"]]
		prefixStrs := splitAddressBlock(addrBlockRaw)
		if len(prefixStrs) == 0 {
			return nil, fmt.Errorf("fila %d del CSV IANA: Address Block vacío", rowNum)
		}
		name := record[colIndex["Name"]]
		rfc := record[colIndex["RFC"]]
		allocDate := record[colIndex["Allocation Date"]]
		termDate := record[colIndex["Termination Date"]]
		source := parseIANABool(record[colIndex["Source"]])
		destination := parseIANABool(record[colIndex["Destination"]])
		forwardable := parseIANABool(record[colIndex["Forwardable"]])
		globallyReachable := parseIANABool(record[colIndex["Globally Reachable"]])
		reservedByProtocol := parseIANABool(record[colIndex["Reserved-by-Protocol"]])

		for _, ps := range prefixStrs {
			prefix, perr := netip.ParsePrefix(ps)
			if perr != nil {
				return nil, fmt.Errorf("fila %d del CSV IANA: Address Block %q no es un prefijo válido: %w", rowNum, ps, perr)
			}
			entries = append(entries, ianaEntry{
				Prefix: prefix, Name: name, RFC: rfc, AllocationDate: allocDate, TerminationDate: termDate,
				Source: source, Destination: destination, Forwardable: forwardable,
				GloballyReachable: globallyReachable, ReservedByProtocol: reservedByProtocol,
			})
		}
	}
	return entries, nil
}

// mostSpecificIANAMatch returns the entry with the longest prefix length
// among every entry that fully contains the query — IANA can have a
// general entry (192.0.0.0/24) and a more specific one nested inside it
// (192.0.0.9/32); the more specific one wins so its own metadata is never
// shadowed by its parent's.
func mostSpecificIANAMatch(entries []ianaEntry, addr netip.Addr, queryPrefix netip.Prefix, isPrefix bool) *ianaEntry {
	var best *ianaEntry
	for i := range entries {
		e := &entries[i]
		if !containsResource(e.Prefix, addr, queryPrefix, isPrefix) {
			continue
		}
		if best == nil || e.Prefix.Bits() > best.Prefix.Bits() {
			best = e
		}
	}
	return best
}

// ---- Team Cymru fullbogons parsing ----

// parseCymruFeed decodes one fullbogons text body into its CIDR entries
// — "#"-prefixed comment lines and blank lines are ignored, but any
// other non-empty line that isn't a valid CIDR of the requested family
// degrades the WHOLE feed (never silently skipped, never a partial
// list).
func parseCymruFeed(body []byte, family int) ([]netip.Prefix, error) {
	wantBits := 32
	if family == 6 {
		wantBits = 128
	}

	var out []netip.Prefix
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 64*1024), bogonFeedMaxBytes+1)
	lineNum := 0
	for sc.Scan() {
		lineNum++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, err := netip.ParsePrefix(line)
		if err != nil {
			return nil, fmt.Errorf("línea %d del feed Cymru no es un CIDR válido: %q", lineNum, line)
		}
		if p.Addr().BitLen() != wantBits {
			return nil, fmt.Errorf("línea %d del feed Cymru es de familia incorrecta (se esperaba IPv%d): %q", lineNum, family, line)
		}
		out = append(out, p)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("error leyendo feed Cymru: %w", err)
	}
	return out, nil
}

// mostSpecificCymruMatch mirrors mostSpecificIANAMatch for a flat prefix
// list (Cymru entries carry no metadata beyond the prefix itself).
func mostSpecificCymruMatch(entries []netip.Prefix, addr netip.Addr, queryPrefix netip.Prefix, isPrefix bool) *netip.Prefix {
	var best *netip.Prefix
	for i := range entries {
		p := entries[i]
		if !containsResource(p, addr, queryPrefix, isPrefix) {
			continue
		}
		if best == nil || p.Bits() > best.Bits() {
			best = &p
		}
	}
	return best
}

// BogonLookup classifies req.Resource against IANA's special-purpose
// registry and Team Cymru's Fullbogons list — at most 2 HTTP calls,
// user-initiated, never polling, never a background timer or goroutine.
// Any local validation failure short-circuits before any network access.
func (c *Client) BogonLookup(ctx context.Context, req BogonLookupRequest) BogonLookupResult {
	var res BogonLookupResult

	kind, family, addr, prefix, isPrefix, resource, err := validateBogonLookupRequest(req)
	if err != nil {
		res.Resource = strings.TrimSpace(req.Resource)
		res.Err = err.Error()
		res.Evidence = []ComponentEvidence{
			{Component: "iana-special-purpose", Status: ComponentNotApplicable},
			{Component: "team-cymru-fullbogons", Status: ComponentNotApplicable},
		}
		return res
	}
	res.Resource = resource
	res.ResourceKind = kind
	res.Family = family

	ianaOK := c.classifyIANA(ctx, &res, family, addr, prefix, isPrefix)
	cymruOK := c.classifyCymru(ctx, &res, family, addr, prefix, isPrefix)

	res.DataSufficient = ianaOK && cymruOK
	if !res.DataSufficient {
		var failed []string
		if !ianaOK {
			failed = append(failed, "iana-special-purpose")
		}
		if !cymruOK {
			failed = append(failed, "team-cymru-fullbogons")
		}
		res.Err = fmt.Sprintf("datasource(s) fallidos: %s", strings.Join(failed, ", "))
	}
	return res
}

func (c *Client) classifyIANA(ctx context.Context, res *BogonLookupResult, family int, addr netip.Addr, prefix netip.Prefix, isPrefix bool) bool {
	url := ianaIPv4CSVURL
	if family == 6 {
		url = ianaIPv6CSVURL
	}
	// The Resource never travels in the request — this is a static CSV
	// download, the same one regardless of what's being looked up — so
	// DataSent must never imply the queried IP/prefix was sent to IANA
	// (Gate 4 P1 fix: an earlier revision wrongly included it here).
	dataSent := fmt.Sprintf("IANA special-purpose registry IPv%d, registry CSV completo descargado (el resource consultado no viaja en la petición)", family)

	body, err := c.fetchBogonFeed(ctx, url)
	if err != nil {
		res.Evidence = append(res.Evidence, ComponentEvidence{
			Component: "iana-special-purpose", Status: ComponentDegraded,
			Disclosure: ianaDisclosure(dataSent), Err: err.Error(),
		})
		return false
	}
	entries, err := parseIANACSV(body)
	if err != nil {
		res.Evidence = append(res.Evidence, ComponentEvidence{
			Component: "iana-special-purpose", Status: ComponentDegraded,
			Disclosure: ianaDisclosure(dataSent), Err: err.Error(),
		})
		return false
	}

	match := mostSpecificIANAMatch(entries, addr, prefix, isPrefix)
	found := match != nil
	res.IANASpecialPurpose = &found
	if match != nil {
		res.IANAMatch = &IANASpecialPurposeMatch{
			Prefix:             match.Prefix.String(),
			Name:               match.Name,
			RFC:                match.RFC,
			AllocationDate:     match.AllocationDate,
			TerminationDate:    match.TerminationDate,
			Source:             match.Source,
			Destination:        match.Destination,
			Forwardable:        match.Forwardable,
			GloballyReachable:  match.GloballyReachable,
			ReservedByProtocol: match.ReservedByProtocol,
		}
	}
	res.Evidence = append(res.Evidence, ComponentEvidence{
		Component: "iana-special-purpose", Status: ComponentOK, Disclosure: ianaDisclosure(dataSent),
	})
	return true
}

func (c *Client) classifyCymru(ctx context.Context, res *BogonLookupResult, family int, addr netip.Addr, prefix netip.Prefix, isPrefix bool) bool {
	url := cymruIPv4URL
	if family == 6 {
		url = cymruIPv6URL
	}
	// The Resource never travels in the request — Cymru's feed is
	// fetched whole, by family, with no per-resource query parameter —
	// so DataSent describes exactly that, never implying the Resource
	// itself was sent anywhere.
	dataSent := fmt.Sprintf("Team Cymru Fullbogons IPv%d, feed completo descargado (el resource consultado no viaja en la petición)", family)

	body, err := c.fetchBogonFeed(ctx, url)
	if err != nil {
		res.Evidence = append(res.Evidence, ComponentEvidence{
			Component: "team-cymru-fullbogons", Status: ComponentDegraded,
			Disclosure: cymruDisclosure(dataSent), Err: err.Error(),
		})
		return false
	}
	prefixes, err := parseCymruFeed(body, family)
	if err != nil {
		res.Evidence = append(res.Evidence, ComponentEvidence{
			Component: "team-cymru-fullbogons", Status: ComponentDegraded,
			Disclosure: cymruDisclosure(dataSent), Err: err.Error(),
		})
		return false
	}

	match := mostSpecificCymruMatch(prefixes, addr, prefix, isPrefix)
	found := match != nil
	res.CymruFullBogon = &found
	if match != nil {
		res.CymruMatchPrefix = match.String()
	}
	res.Evidence = append(res.Evidence, ComponentEvidence{
		Component: "team-cymru-fullbogons", Status: ComponentOK, Disclosure: cymruDisclosure(dataSent),
	})
	return true
}
