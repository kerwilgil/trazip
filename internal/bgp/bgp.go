// Package bgp implements BGP routing status and RPKI validation lookups
// (prompt maestro §9 Fase 4, módulo 22, segunda mitad) against RIPEstat's
// public data API — run by RIPE NCC (a RIR, per §5.7 "RPKI/ROA y BGP bajo
// demanda"), free, unauthenticated, and documented at
// https://stat.ripe.net/docs/02.data-api/. RIPEstat is used instead of a
// raw looking-glass or a private BGP-feed vendor because it already
// aggregates RouteViews/RIS with RPKI validation in one well-known,
// no-auth, no-cost, RIR-operated endpoint — exactly the profile §5.8 asks
// external dependencies to meet.
package bgp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"trazip/internal/intel/external"
)

const defaultBaseURL = "https://stat.ripe.net/data"

// Client queries RIPEstat. The zero value works (falls back to the real
// endpoint); tests override BaseURL to point at a local server.
//
// cacheInit/cachePtr add a lazily-initialized, bounded, in-memory result
// cache (cache.go) without breaking existing callers that build a Client
// as a bare struct literal (&Client{BaseURL: addr}, used throughout this
// package's tests) — see getCache().
type Client struct {
	HTTPClient *http.Client
	BaseURL    string

	cacheInit sync.Once
	cachePtr  *cache
}

// getCache lazily initializes and returns this Client's result cache.
// Safe for concurrent use; safe on a zero-value Client (including one
// built as &Client{BaseURL: addr} in tests) — a cache is created on
// first use, never required at construction time.
func (c *Client) getCache() *cache {
	c.cacheInit.Do(func() {
		c.cachePtr = newCache(0)
	})
	return c.cachePtr
}

// NewClient builds a Client pointed at the real RIPEstat API.
func NewClient() *Client {
	return &Client{HTTPClient: &http.Client{Timeout: 10 * time.Second}, BaseURL: defaultBaseURL}
}

func (c *Client) client() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

func (c *Client) baseURL() string {
	if c.BaseURL != "" {
		return c.BaseURL
	}
	return defaultBaseURL
}

// RouteStatus reports which origin ASNs are currently announcing a
// resource (an IP or a prefix), per RIPEstat's routing-status endpoint.
type RouteStatus struct {
	Resource  string `json:"resource"`
	Announced bool   `json:"announced"`
	// Prefix is the actual encompassing routed prefix RIPEstat resolved
	// resource to (e.g. querying "1.1.1.1" returns "1.1.1.0/24") — the real
	// announced prefix, not the queried resource verbatim. Callers validating
	// RPKI (RPKIValidate) must use THIS, never a synthesized /32 or /128: a
	// ROA's maxLength very commonly excludes a full-length prefix even when
	// the real, less-specific announcement it covers is perfectly RPKI-valid,
	// so querying the wrong prefix produces a false "invalid" for nearly
	// every address (caught by diagnosis.runRoutingSecurity's own manual
	// smoke test against 1.1.1.1, which is genuinely RPKI-valid at /24).
	Prefix     string              `json:"prefix,omitempty"`
	Origins    []int               `json:"origins,omitempty"`
	Disclosure external.Disclosure `json:"disclosure"`
	Err        string              `json:"err,omitempty"`
}

// RPKIStatus reports RPKI Route Origin Validation for one (ASN, prefix)
// pair, per RIPEstat's rpki-validation endpoint.
type RPKIStatus struct {
	ASN        int                 `json:"asn"`
	Prefix     string              `json:"prefix"`
	Status     string              `json:"status,omitempty"` // "valid" | "invalid" | "unknown" | "not-found"
	Reason     string              `json:"reason,omitempty"`
	Disclosure external.Disclosure `json:"disclosure"`
	Err        string              `json:"err,omitempty"`
}

type ripestatEnvelope struct {
	Status string          `json:"status"`
	Data   json.RawMessage `json:"data"`
}

// routingStatusData mirrors RIPEstat's actual routing-status response —
// there is no "announced" boolean; presence of a non-empty origins list is
// what "announced" means (verified against the live API, not guessed).
type routingStatusData struct {
	// Resource is RIPEstat's own resolved covering prefix for the query —
	// see RouteStatus.Prefix's doc comment for why this matters.
	Resource string `json:"resource"`
	Origins  []struct {
		Origin int `json:"origin"`
	} `json:"origins"`
}

// rpkiValidationData mirrors RIPEstat's actual rpki-validation response —
// validating_roas is an array of matched ROAs, each with its own validity,
// not an object with a single "reason" string (verified against the live
// API, not guessed).
type rpkiValidationData struct {
	Status         string `json:"status"`
	ValidatingROAs []struct {
		Origin    string `json:"origin"`
		Prefix    string `json:"prefix"`
		Validity  string `json:"validity"`
		MaxLength int    `json:"max_length"`
	} `json:"validating_roas"`
}

func (c *Client) get(ctx context.Context, endpoint string, params url.Values, v any) error {
	u := c.baseURL() + "/" + endpoint + "/data.json?" + params.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("RIPEstat HTTP %d", resp.StatusCode)
	}
	var env ripestatEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("respuesta RIPEstat no interpretable: %w", err)
	}
	if env.Status != "ok" {
		return fmt.Errorf("RIPEstat status=%q", env.Status)
	}
	return json.Unmarshal(env.Data, v)
}

func disclosure(dataSent string) external.Disclosure {
	return external.Disclosure{
		Source:      "RIPEstat (RIPE NCC)",
		QueriedAt:   external.Now(),
		DataSent:    dataSent,
		CachePolicy: "sin caché local — cada consulta es en vivo",
		Confidence:  "media", // agrega RouteViews/RIS; útil como corroboración, no como fuente única (§23)
		RateLimit:   "API pública sin autenticación; RIPE NCC pide uso razonable, no hacer polling en bucle",
	}
}

// RoutingStatus queries which ASN(s) currently announce resource (an IP or
// CIDR prefix).
func (c *Client) RoutingStatus(ctx context.Context, resource string) RouteStatus {
	resource = strings.TrimSpace(resource)
	res := RouteStatus{Resource: resource, Disclosure: disclosure("prefijo/IP consultado")}
	if resource == "" {
		res.Err = "recurso vacío"
		return res
	}

	var data routingStatusData
	if err := c.get(ctx, "routing-status", url.Values{"resource": {resource}}, &data); err != nil {
		res.Err = err.Error()
		return res
	}
	for _, o := range data.Origins {
		res.Origins = append(res.Origins, o.Origin)
	}
	res.Announced = len(res.Origins) > 0
	res.Prefix = data.Resource
	return res
}

// RPKIValidate checks whether asn is a valid RPKI origin for prefix.
func (c *Client) RPKIValidate(ctx context.Context, asn int, prefix string) RPKIStatus {
	prefix = strings.TrimSpace(prefix)
	res := RPKIStatus{ASN: asn, Prefix: prefix, Disclosure: disclosure(fmt.Sprintf("ASN %d + prefijo %s", asn, prefix))}
	if prefix == "" || asn <= 0 {
		res.Err = "ASN o prefijo inválido"
		return res
	}

	var data rpkiValidationData
	params := url.Values{"resource": {strconv.Itoa(asn)}, "prefix": {prefix}}
	if err := c.get(ctx, "rpki-validation", params, &data); err != nil {
		res.Err = err.Error()
		return res
	}
	res.Status = normalizeRPKIStatus(data.Status)
	var reasons []string
	for _, roa := range data.ValidatingROAs {
		reasons = append(reasons, fmt.Sprintf("ROA origin=%s prefix=%s max_length=%d validity=%s", roa.Origin, roa.Prefix, roa.MaxLength, roa.Validity))
	}
	res.Reason = strings.Join(reasons, "; ")
	return res
}

// normalizeRPKIStatus buckets RIPEstat's status values into the three the
// spec asks for (§22 "válido, inválido o no encontrado") while keeping the
// original detail (e.g. "invalid_asn" vs "invalid_length" — RIPEstat's
// validator distinguishes wrong-origin from prefix-too-specific) in the
// per-ROA Reason string built by RPKIValidate.
func normalizeRPKIStatus(s string) string {
	v := strings.ToLower(strings.TrimSpace(s))
	switch {
	case v == "valid":
		return "valid"
	case strings.HasPrefix(v, "invalid"):
		return "invalid"
	case v == "unknown" || v == "":
		return "unknown"
	default:
		return v
	}
}
