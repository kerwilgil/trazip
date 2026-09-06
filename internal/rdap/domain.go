package rdap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"trazip/internal/intel/external"
)

// defaultBootstrapDNS es el registro de IANA que asigna cada dominio de primer
// nivel a su servidor RDAP, el equivalente para nombres de los de IP y ASN.
const defaultBootstrapDNS = "https://data.iana.org/rdap/dns.json"

// DomainResult es el resultado de consultar un nombre de dominio.
//
// Lleva Asked y Registered por separado a propósito: los registros solo conocen
// dominios *registrados*, y un subdominio lo crea el dueño en su propia zona
// DNS sin pasar por ningún registrador. Preguntar por "app.ejemplo.com" y
// recibir los datos de "ejemplo.com" sin decirlo sería engañoso — parecería que
// el subdominio está registrado cuando lo que existe es el dominio padre.
type DomainResult struct {
	Asked      string `json:"asked"`      // lo que escribió el operador
	Registered string `json:"registered"` // el dominio que sí figura en el registro
	IsExact    bool   `json:"isExact"`    // true si lo preguntado era el dominio registrado
	TLD        string `json:"tld,omitempty"`
	Registry   string `json:"registry,omitempty"` // URL base RDAP del registro consultado

	Handle      string    `json:"handle,omitempty"`
	Registrar   string    `json:"registrar,omitempty"`
	Status      []string  `json:"status,omitempty"`
	Nameservers []string  `json:"nameservers,omitempty"`
	Contacts    []Contact `json:"contacts,omitempty"`
	AbuseEmail  string    `json:"abuseEmail,omitempty"`
	Remarks     []string  `json:"remarks,omitempty"`

	Created      string `json:"created,omitempty"` // RFC3339
	Updated      string `json:"updated,omitempty"` // RFC3339
	Expires      string `json:"expires,omitempty"` // RFC3339
	DaysToExpiry *int   `json:"daysToExpiry,omitempty"`

	Notes      []string            `json:"notes"`
	Disclosure external.Disclosure `json:"disclosure"`
	Err        string              `json:"err,omitempty"`
}

// LookupDomain consulta RDAP por un nombre de dominio.
//
// Si el nombre tiene subdominios, se prueba primero tal cual y se van quitando
// etiquetas por la izquierda hasta que el registro responde. Eso evita
// depender de una lista de sufijos públicos —que haría falta para saber que
// "co.uk" no es registrable pero "ejemplo.co.uk" sí— a cambio de unas pocas
// peticiones extra, y de paso responde con precisión cuál es el dominio
// registrado de verdad.
func (c *Client) LookupDomain(ctx context.Context, name string) (DomainResult, error) {
	asked := normalizeDomain(name)
	res := DomainResult{Asked: asked, Notes: []string{}}
	if asked == "" {
		res.Err = "nombre de dominio vacío"
		return res, errors.New(res.Err)
	}
	// Una dirección no se registra en ningún TLD. Va antes que la comprobación
	// del punto porque si no, una IPv6 caería en "necesita al menos un punto",
	// y porque el error genérico sería "IANA no publica servidor RDAP para el
	// dominio de primer nivel \"1\"": cierto, pero no le dice a nadie qué hacer.
	if _, perr := netip.ParseAddr(asked); perr == nil {
		res.Err = "eso es una dirección IP, no un dominio: usá la consulta RDAP de IP"
		return res, errors.New(res.Err)
	}
	if strings.Count(asked, ".") < 1 {
		res.Err = "un dominio necesita al menos un punto (ejemplo.com)"
		return res, errors.New(res.Err)
	}

	if err := c.ensureDNSBootstrap(ctx); err != nil {
		res.Err = "no se pudo cargar el registro bootstrap de dominios de IANA: " + err.Error()
		return res, err
	}

	labels := strings.Split(asked, ".")
	var lastErr string
	// Se prueba del nombre completo hacia el dominio de segundo nivel; no tiene
	// sentido consultar el TLD suelto, que nunca es un registro de dominio.
	for i := 0; i <= len(labels)-2; i++ {
		candidate := strings.Join(labels[i:], ".")
		base, tld, ok := c.findDomainRegistry(candidate)
		if !ok {
			res.Err = fmt.Sprintf("IANA no publica servidor RDAP para el dominio de primer nivel %q", labels[len(labels)-1])
			return res, errors.New(res.Err)
		}

		out, err := c.queryDomain(ctx, candidate, base, tld)
		if err != nil {
			return out, err
		}
		if out.Err == "" {
			out.Asked = asked
			out.IsExact = candidate == asked
			if !out.IsExact {
				out.Notes = append(out.Notes,
					fmt.Sprintf("%q no figura en el registro: los registros solo conocen dominios registrados, y los subdominios los crea su dueño en su propia zona DNS. Los datos mostrados son de %q, el dominio registrado del que cuelga.", asked, candidate))
			}
			return out, nil
		}
		lastErr = out.Err
	}

	res.Err = "no se encontró ningún dominio registrado en " + asked
	if lastErr != "" {
		res.Notes = append(res.Notes, "última respuesta del registro: "+lastErr)
	}
	return res, nil
}

// queryDomain consulta un dominio concreto contra su registro.
func (c *Client) queryDomain(ctx context.Context, domain, base, tld string) (DomainResult, error) {
	res := DomainResult{
		Asked: domain, Registered: domain, IsExact: true,
		TLD: tld, Registry: base, Notes: []string{},
	}
	res.Disclosure = external.Disclosure{
		Source:      "RDAP de dominios (" + tld + ")",
		QueriedAt:   external.Now(),
		DataSent:    "nombre de dominio consultado",
		CachePolicy: "registro bootstrap de IANA cacheado 24h; la consulta al registro no se cachea",
		Confidence:  "alta",
		RateLimit:   "sujeto al rate limit público del registro; usar bajo demanda, no en bucle",
	}

	url := strings.TrimRight(base, "/") + "/domain/" + domain
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
	switch {
	case resp.StatusCode == http.StatusNotFound:
		// No es un fallo: significa que ese nombre no está registrado, que es
		// justo lo que LookupDomain necesita saber para seguir subiendo.
		res.Err = "no registrado"
		return res, nil
	case resp.StatusCode == http.StatusTooManyRequests:
		res.Err = "el registro respondió 429 (demasiadas consultas); esperá un momento"
		return res, nil
	case resp.StatusCode != http.StatusOK:
		res.Err = fmt.Sprintf("el registro respondió HTTP %d", resp.StatusCode)
		return res, nil
	}

	var parsed rdapResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		res.Err = "respuesta RDAP no interpretable: " + err.Error()
		return res, err
	}

	res.Handle = parsed.Handle
	res.Status = parsed.Status
	for _, ns := range parsed.Nameservers {
		if ns.LDHName != "" {
			res.Nameservers = append(res.Nameservers, strings.ToLower(ns.LDHName))
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
			res.Created = t.Format(time.RFC3339)
		case "last changed", "last update of RDAP database":
			if res.Updated == "" || ev.Action == "last changed" {
				res.Updated = t.Format(time.RFC3339)
			}
		case "expiration":
			res.Expires = t.Format(time.RFC3339)
			d := int(time.Until(t).Hours() / 24)
			res.DaysToExpiry = &d
		}
	}
	for _, e := range parsed.Entities {
		contact := Contact{Roles: e.Roles}
		contact.Name, contact.Org, contact.Email, contact.Phone, contact.Address = parseVCard(e.VCardArray)
		res.Contacts = append(res.Contacts, contact)
		for _, role := range e.Roles {
			switch role {
			case "registrar":
				if contact.Org != "" {
					res.Registrar = contact.Org
				} else if contact.Name != "" {
					res.Registrar = contact.Name
				}
			case "abuse":
				if contact.Email != "" {
					res.AbuseEmail = contact.Email
				}
			}
		}
	}

	// Un dominio vencido o a punto de vencer explica caídas que parecen de red,
	// así que se dice explícitamente en vez de dejar solo la fecha.
	if res.DaysToExpiry != nil {
		switch d := *res.DaysToExpiry; {
		case d < 0:
			res.Notes = append(res.Notes, fmt.Sprintf("el registro venció hace %d días", -d))
		case d <= 30:
			res.Notes = append(res.Notes, fmt.Sprintf("el registro vence en %d días", d))
		}
	}
	return res, nil
}

// normalizeDomain acepta lo que el operador pegue: una URL, un nombre con
// punto final, mayúsculas o espacios.
func normalizeDomain(in string) string {
	s := strings.TrimSpace(strings.ToLower(in))
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.Index(s, "@"); i >= 0 { // por si pegan un correo
		s = s[i+1:]
	}
	if strings.HasPrefix(s, "[") { // IPv6 entre corchetes, con o sin puerto
		if i := strings.Index(s, "]"); i > 0 {
			return s[1:i]
		}
	}
	// El puerto se quita solo si hay un único ":" seguido de dígitos. Cortar en
	// el primer ":" a secas convertiría "2606:4700::1111" en "2606", y entonces
	// una IPv6 pegada sin corchetes saldría con un error que no explica nada.
	if i := strings.LastIndex(s, ":"); i >= 0 && strings.Count(s, ":") == 1 && isDigits(s[i+1:]) {
		s = s[:i]
	}
	return strings.Trim(s, ".")
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// findDomainRegistry busca el servidor RDAP del sufijo más largo que coincida.
// Se compara por sufijo y no solo por el último punto porque IANA publica
// entradas de varias etiquetas para algunos registros.
func (c *Client) findDomainRegistry(domain string) (base, tld string, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	best := ""
	for suffix, url := range c.dnsServices {
		if domain == suffix || strings.HasSuffix(domain, "."+suffix) {
			if len(suffix) > len(best) {
				best, base, tld = suffix, url, suffix
			}
		}
	}
	return base, tld, best != ""
}

func (c *Client) ensureDNSBootstrap(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.dnsServices) > 0 && time.Since(c.dnsBootstrapAt) < bootstrapTTL {
		return nil
	}
	var bf bootstrapFile
	if err := c.fetchJSON(ctx, c.BootstrapDNS, &bf); err != nil {
		return err
	}
	services := make(map[string]string, 1500)
	for _, svc := range bf.Services {
		if len(svc) != 2 || len(svc[1]) == 0 {
			continue
		}
		url := svc[1][0]
		for _, suffix := range svc[0] {
			s := strings.Trim(strings.ToLower(strings.TrimSpace(suffix)), ".")
			if s != "" {
				services[s] = url
			}
		}
	}
	if len(services) == 0 {
		return errors.New("el registro de dominios de IANA llegó vacío")
	}
	c.dnsServices = services
	c.dnsBootstrapAt = time.Now()
	return nil
}
