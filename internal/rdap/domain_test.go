package rdap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNormalizeDomain(t *testing.T) {
	cases := map[string]string{
		"  EDATAHOME.com. ":                 "edatahome.com",
		"https://www.google.com/search?q=x": "www.google.com",
		"http://ejemplo.com:8080/a/b":       "ejemplo.com",
		"mail@vozelia.com":                  "vozelia.com",
		"ejemplo.com#frag":                  "ejemplo.com",
		"[2606:4700::1111]:443":             "2606:4700::1111",
		"2606:4700::1111":                   "2606:4700::1111", // sin puerto que quitar
		"1.1.1.1:53":                        "1.1.1.1",
		"":                                  "",
	}
	for in, want := range cases {
		if got := normalizeDomain(in); got != want {
			t.Errorf("normalizeDomain(%q) = %q, se esperaba %q", in, got, want)
		}
	}
}

// Una IP no se registra en ningún TLD. El mensaje tiene que decir eso y no el
// error interno de que "1" no es un dominio de primer nivel conocido.
func TestLookupDomainRejectsAddresses(t *testing.T) {
	c := NewClient()
	for _, in := range []string{"1.1.1.1", "2606:4700::1111", "[2606:4700::1111]:443"} {
		res, err := c.LookupDomain(context.Background(), in)
		if err == nil {
			t.Errorf("LookupDomain(%q) debería rechazar una dirección", in)
		}
		if !strings.Contains(res.Err, "dirección IP") {
			t.Errorf("LookupDomain(%q) devolvió %q; se esperaba que hablara de una dirección IP", in, res.Err)
		}
	}
}

func TestLookupDomainRejectsEmptyAndSingleLabel(t *testing.T) {
	c := NewClient()
	for _, in := range []string{"", "   ", "localhost"} {
		if _, err := c.LookupDomain(context.Background(), in); err == nil {
			t.Errorf("LookupDomain(%q) debería devolver error", in)
		}
	}
}

// El contrato con el frontend: notes siempre es un arreglo. Un slice nil
// marshalea a null y la vista hace .join()/.length sobre él.
func TestDomainResultNotesIsNeverNull(t *testing.T) {
	c := NewClient()
	for _, in := range []string{"", "localhost", "1.1.1.1"} {
		res, _ := c.LookupDomain(context.Background(), in)
		raw, err := json.Marshal(res)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if strings.Contains(string(raw), `"notes":null`) {
			t.Errorf("LookupDomain(%q) devuelve notes:null y rompe la vista: %s", in, raw)
		}
	}
}

// El caso que motivó la función: preguntar por un subdominio devuelve los datos
// del dominio registrado del que cuelga, diciéndolo explícitamente en vez de
// hacerlos pasar por datos del subdominio.
func TestLookupDomainWalksUpToRegisteredDomain(t *testing.T) {
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/domain/")
		asked = append(asked, name)
		if name != "ejemplo.com" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/rdap+json")
		w.Write([]byte(`{
			"handle": "H-1",
			"status": ["client transfer prohibited"],
			"nameservers": [{"ldhName": "NS1.EJEMPLO.COM"}, {"ldhName": "ns2.ejemplo.com"}],
			"events": [
				{"eventAction": "registration", "eventDate": "2000-11-26T16:51:43Z"},
				{"eventAction": "expiration", "eventDate": "2099-11-26T16:51:43Z"},
				{"eventAction": "last changed", "eventDate": "2025-12-16T10:23:08Z"}
			],
			"entities": [
				{"roles": ["registrar"], "vcardArray": ["vcard", [["version",{},"text","4.0"],["fn",{},"text","Registrador SA"]]]},
				{"roles": ["abuse"], "vcardArray": ["vcard", [["version",{},"text","4.0"],["email",{},"text","abuse@registrador.example"]]]}
			]
		}`))
	}))
	defer srv.Close()

	c := NewClient()
	c.dnsServices = map[string]string{"com": srv.URL + "/"}
	c.dnsBootstrapAt = time.Now()

	res, err := c.LookupDomain(context.Background(), "devacs.ejemplo.com")
	if err != nil {
		t.Fatalf("LookupDomain: %v", err)
	}
	if res.Err != "" {
		t.Fatalf("resultado con error: %s", res.Err)
	}
	if want := []string{"devacs.ejemplo.com", "ejemplo.com"}; len(asked) != 2 || asked[0] != want[0] || asked[1] != want[1] {
		t.Errorf("consultó %v, se esperaba %v", asked, want)
	}
	if res.Asked != "devacs.ejemplo.com" {
		t.Errorf("Asked = %q, se esperaba el nombre original", res.Asked)
	}
	if res.Registered != "ejemplo.com" {
		t.Errorf("Registered = %q, se esperaba ejemplo.com", res.Registered)
	}
	if res.IsExact {
		t.Error("IsExact debería ser false: lo preguntado no es lo registrado")
	}
	if len(res.Notes) == 0 || !strings.Contains(res.Notes[0], "devacs.ejemplo.com") {
		t.Errorf("falta la nota que explica la diferencia: %v", res.Notes)
	}
	if res.Registrar != "Registrador SA" {
		t.Errorf("Registrar = %q", res.Registrar)
	}
	if res.AbuseEmail != "abuse@registrador.example" {
		t.Errorf("AbuseEmail = %q", res.AbuseEmail)
	}
	if len(res.Nameservers) != 2 || res.Nameservers[0] != "ns1.ejemplo.com" {
		t.Errorf("Nameservers = %v, se esperaban en minúscula", res.Nameservers)
	}
	if !strings.HasPrefix(res.Created, "2000-11-26") || !strings.HasPrefix(res.Expires, "2099-11-26") {
		t.Errorf("fechas mal mapeadas: creado=%q vence=%q", res.Created, res.Expires)
	}
	if res.DaysToExpiry == nil || *res.DaysToExpiry <= 0 {
		t.Errorf("DaysToExpiry = %v, se esperaba positivo", res.DaysToExpiry)
	}
}

// Un nombre que no existe en ningún nivel no debe reportarse como registrado.
func TestLookupDomainReportsUnregistered(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := NewClient()
	c.dnsServices = map[string]string{"com": srv.URL + "/"}
	c.dnsBootstrapAt = time.Now()

	res, err := c.LookupDomain(context.Background(), "no-existe-jamas.com")
	if err != nil {
		t.Fatalf("LookupDomain: %v", err)
	}
	if res.Err == "" {
		t.Error("un dominio inexistente debería reportar el motivo, no venir vacío en silencio")
	}
	if res.Registered != "" {
		t.Errorf("Registered = %q para un dominio inexistente", res.Registered)
	}
}

// findDomainRegistry tiene que elegir el sufijo más largo: IANA publica
// entradas de varias etiquetas para algunos registros.
func TestFindDomainRegistryPrefersLongestSuffix(t *testing.T) {
	c := NewClient()
	c.dnsServices = map[string]string{
		"uk":    "https://rdap.uk/",
		"co.uk": "https://rdap.co.uk/",
	}
	base, tld, ok := c.findDomainRegistry("ejemplo.co.uk")
	if !ok || tld != "co.uk" || base != "https://rdap.co.uk/" {
		t.Errorf("findDomainRegistry devolvió base=%q tld=%q ok=%v", base, tld, ok)
	}
	if _, _, ok := c.findDomainRegistry("ejemplo.zz"); ok {
		t.Error("un TLD desconocido no debería coincidir")
	}
}
