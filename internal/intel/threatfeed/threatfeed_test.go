package threatfeed

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// seed writes a store directly, so the tests exercise lookup and reporting
// without touching the network.
func seed(t *testing.T, s store) *Engine {
	t.Helper()
	dir := t.TempDir()
	e := New(dir)
	s.Version = storeVersion
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, storeFile), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.Reload(); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestLookupReportsTheClaimNotJustTheHit(t *testing.T) {
	e := seed(t, store{
		Prefixes: []entry{{P: "203.0.113.0/24", C: CatMalicious, S: "spamhaus-drop", R: "SBL999"}},
		Sources:  []SourceInfo{{ID: "spamhaus-drop", FetchedAt: "2026-08-07T10:00:00Z", PrefixCount: 1}},
	})

	hits := e.Lookup(netip.MustParseAddr("203.0.113.9"))
	if len(hits) != 1 {
		t.Fatalf("se esperaba 1 coincidencia, hubo %d", len(hits))
	}
	h := hits[0]
	if h.Prefix != "203.0.113.0/24" {
		t.Errorf("prefijo = %q", h.Prefix)
	}
	if h.Ref != "SBL999" {
		t.Errorf("no se conserva la referencia de la fuente: %q", h.Ref)
	}
	// Sin esto, un informe diría "aparece en una lista" y nadie sabría qué
	// afirma esa lista.
	if h.Detail == "" || h.Name == "" {
		t.Errorf("la coincidencia no explica qué afirma la fuente: %+v", h)
	}
	if h.FetchedAt == "" {
		t.Error("falta la fecha de descarga: una lista vieja es evidencia más débil")
	}
}

func TestLookupMissesAddressesOutsideEveryRange(t *testing.T) {
	e := seed(t, store{Prefixes: []entry{{P: "203.0.113.0/24", C: CatMalicious, S: "spamhaus-drop"}}})
	if hits := e.Lookup(netip.MustParseAddr("8.8.8.8")); len(hits) != 0 {
		t.Errorf("8.8.8.8 no debería coincidir: %+v", hits)
	}
}

// "Está en DROP y además es salida Tor" es una situación distinta de cualquiera
// de las dos por separado, así que se devuelven ambas.
func TestLookupReturnsEverySourceThatCovers(t *testing.T) {
	e := seed(t, store{Prefixes: []entry{
		{P: "203.0.113.0/24", C: CatMalicious, S: "spamhaus-drop"},
		{P: "203.0.113.9/32", C: CatTor, S: "tor-exit"},
	}})
	hits := e.Lookup(netip.MustParseAddr("203.0.113.9"))
	if len(hits) != 2 {
		t.Fatalf("se esperaban 2 coincidencias, hubo %d: %+v", len(hits), hits)
	}
	// El prefijo más específico primero.
	if hits[0].Feed != "tor-exit" {
		t.Errorf("primero llegó %q; se esperaba el prefijo más específico (/32)", hits[0].Feed)
	}
}

// Una misma fuente con varios rangos que cubren la dirección no debe contarse
// dos veces: inflaría la penalización de reputación.
func TestLookupCountsEachSourceOnce(t *testing.T) {
	e := seed(t, store{Prefixes: []entry{
		{P: "203.0.113.0/24", C: CatMalicious, S: "spamhaus-drop"},
		{P: "203.0.0.0/16", C: CatMalicious, S: "spamhaus-drop"},
	}})
	hits := e.Lookup(netip.MustParseAddr("203.0.113.9"))
	if len(hits) != 1 {
		t.Fatalf("la misma fuente se contó %d veces", len(hits))
	}
	if hits[0].Prefix != "203.0.113.0/24" {
		t.Errorf("se reportó %q; se esperaba el rango más ajustado", hits[0].Prefix)
	}
}

func TestLookupNeverReturnsNull(t *testing.T) {
	e := seed(t, store{})
	for _, a := range []string{"8.8.8.8", "2001:db8::1"} {
		raw, err := json.Marshal(e.Lookup(netip.MustParseAddr(a)))
		if err != nil {
			t.Fatal(err)
		}
		if string(raw) == "null" {
			t.Errorf("Lookup(%s) marshalea a null y rompe el .map() de la vista", a)
		}
	}
	// Una dirección inválida tampoco debe entrar en pánico.
	if got := e.Lookup(netip.Addr{}); len(got) != 0 {
		t.Errorf("una dirección inválida devolvió %+v", got)
	}
}

// Sources tiene que listar el catálogo entero, también lo no descargado: si no,
// en Settings no habría nada que pulsar la primera vez.
func TestSourcesListsWholeCatalogEvenWhenEmpty(t *testing.T) {
	e := seed(t, store{})
	got := e.Sources()
	if len(got) != len(Catalog) {
		t.Fatalf("Sources devolvió %d de %d fuentes del catálogo", len(got), len(Catalog))
	}
	for _, s := range got {
		if s.Present {
			t.Errorf("%q se marca como presente sin haberse descargado", s.ID)
		}
		if s.Name == "" || s.URL == "" {
			t.Errorf("%q sin nombre o URL: %+v", s.ID, s)
		}
	}
}

func TestParseDROPReadsCIDRAndSBL(t *testing.T) {
	body := []byte(`{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}
{"cidr":"1.19.0.0/16","sblid":"SBL434604","rir":"apnic"}
{"type":"metadata","timestamp":1754500000}
basura que no es json
`)
	got, err := parseDROP(body)
	if err != nil {
		t.Fatalf("parseDROP: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("se leyeron %d rangos, se esperaban 2 (la línea de metadatos y la basura se descartan): %+v", len(got), got)
	}
	if got[0].P != "1.10.16.0/20" || got[0].R != "SBL256894" {
		t.Errorf("primera fila mal leída: %+v", got[0])
	}
	if got[0].C != CatMalicious {
		t.Errorf("categoría = %q", got[0].C)
	}
}

func TestParseAddressListHandlesBareIPsAndComments(t *testing.T) {
	def := SourceDef{ID: "tor-exit", Cat: CatTor}
	body := []byte("# comentario\n\n171.25.193.25\n80.67.167.81\n; otro comentario\n2001:db8::1\n10.0.0.0/8\nno-es-una-ip\n")
	got := parseAddressList(body, def)
	if len(got) != 4 {
		t.Fatalf("se leyeron %d filas, se esperaban 4: %+v", len(got), got)
	}
	// Una IP suelta se convierte en prefijo de host para que la búsqueda sea uniforme.
	if got[0].P != "171.25.193.25/32" {
		t.Errorf("una IPv4 suelta debería quedar como /32, quedó %q", got[0].P)
	}
	if got[2].P != "2001:db8::1/128" {
		t.Errorf("una IPv6 suelta debería quedar como /128, quedó %q", got[2].P)
	}
	if got[3].P != "10.0.0.0/8" {
		t.Errorf("un CIDR debería conservarse, quedó %q", got[3].P)
	}
}

// Si una fuente empieza a exigir clave de API y responde 200 con solo
// cabeceras, sustituir la lista buena por nada dejaría todo limpio sin avisar.
func TestParseRejectsHeaderOnlyBody(t *testing.T) {
	def, _ := FindSource("tor-exit")
	body := []byte("############\n# vacío     #\n############\n")
	if got := parseAddressList(body, def); len(got) != 0 {
		t.Errorf("un cuerpo de solo comentarios produjo %d filas", len(got))
	}
}
