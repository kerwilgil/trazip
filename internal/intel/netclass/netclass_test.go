package netclass

import (
	"net/netip"
	"path/filepath"
	"testing"
)

func TestHeuristicBrandVsGeneric(t *testing.T) {
	addr := netip.MustParseAddr("1.2.3.4")

	m, ok := heuristic(addr, "Cloudflare, Inc.")
	if !ok || m.Category != string(CDN) || m.Confidence != "media" || !m.Inferred {
		t.Errorf("marca conocida = %+v", m)
	}
	if m.Provider != "Cloudflare" {
		t.Errorf("Provider = %q, want Cloudflare", m.Provider)
	}

	// Una palabra genérica es evidencia mucho más débil y debe decirlo.
	m, ok = heuristic(addr, "Cable & Wireless Panama")
	if !ok || m.Category != string(ISP) || m.Confidence != "baja" {
		t.Errorf("palabra genérica = %+v", m)
	}
	if m.Provider != "Cable & Wireless Panama" {
		t.Errorf("sin marca conocida debe conservar el nombre original, got %q", m.Provider)
	}

	// Sin org no hay nada que inferir: no inventar una categoría.
	if _, ok := heuristic(addr, ""); ok {
		t.Error("org vacía no debería producir match")
	}
	if _, ok := heuristic(addr, "Empresa Anónima 1234"); ok {
		t.Error("un nombre sin señales no debería producir match")
	}
}

func TestLookupPrefersPublishedListOverHeuristic(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{dataDir: dir}
	if err := e.save(store{
		Version: storeVersion,
		Sources: []SourceInfo{{ID: "aws", Name: "Amazon Web Services"}},
		Prefixes: []entry{
			{P: "52.94.0.0/16", C: string(Cloud), R: "Amazon AWS", S: "EC2", G: "us-east-1"},
			{P: "52.94.1.0/24", C: string(Cloud), R: "Amazon AWS", S: "S3", G: "us-east-1"},
		},
	}); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := e.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	// El prefijo más específico gana: /24 sobre /16.
	m, ok := e.Lookup(netip.MustParseAddr("52.94.1.5"), "Cloudflare")
	if !ok {
		t.Fatal("debería encontrar el prefijo publicado")
	}
	if m.Service != "S3" || m.Prefix != "52.94.1.0/24" {
		t.Errorf("longest-prefix falló: %+v", m)
	}
	// Aunque la org diga Cloudflare, la lista publicada manda y no es inferido.
	if m.Inferred || m.Confidence != "alta" || m.Provider != "Amazon AWS" {
		t.Errorf("una lista publicada no es inferencia: %+v", m)
	}

	// Fuera de los prefijos, cae a la heurística.
	m, ok = e.Lookup(netip.MustParseAddr("8.8.8.8"), "Google LLC")
	if !ok || !m.Inferred {
		t.Errorf("fuera de lista debería ser inferido: %+v", m)
	}
}

func TestLookupPrefersGoogleCloudOverGoogleGlobalAtSamePrefix(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{dataDir: dir}
	if err := e.save(store{
		Version: storeVersion,
		Prefixes: []entry{
			{P: "34.0.0.0/16", C: string(Enterprise), R: "Google"},
			{P: "34.0.0.0/16", C: string(Cloud), R: "Google Cloud", S: "Google Cloud"},
		},
	}); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := e.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	m, ok := e.Lookup(netip.MustParseAddr("34.0.0.1"), "")
	if !ok || m.Provider != "Google Cloud" || m.Category != string(Cloud) {
		t.Fatalf("lookup = %+v, want Google Cloud", m)
	}
}

func TestEngineWithoutStoreDegrades(t *testing.T) {
	e := New(filepath.Join(t.TempDir(), "no-existe"))
	if e.Loaded() {
		t.Error("sin archivo no debería reportar listas cargadas")
	}
	// Debe seguir respondiendo por heurística, como GeoIP degrada sin .mmdb.
	if _, ok := e.Lookup(netip.MustParseAddr("1.1.1.1"), "Cloudflare"); !ok {
		t.Error("sin listas la heurística debería seguir funcionando")
	}
	// Y las fuentes se listan igual, marcadas como no instaladas.
	srcs := e.Sources()
	if len(srcs) != len(Catalog) {
		t.Fatalf("Sources() = %d, want %d", len(srcs), len(Catalog))
	}
	for _, s := range srcs {
		if s.Present {
			t.Errorf("%s no debería figurar como instalada", s.ID)
		}
	}
}

func TestParseAWS(t *testing.T) {
	body := []byte(`{
      "prefixes": [
        {"ip_prefix": "52.94.1.0/24", "region": "us-east-1", "service": "S3"},
        {"ip_prefix": "52.94.1.0/24", "region": "us-east-1", "service": "AMAZON"},
        {"ip_prefix": "52.94.2.0/24", "region": "us-east-1", "service": "AMAZON"},
        {"ip_prefix": "13.32.0.0/15", "region": "GLOBAL", "service": "CLOUDFRONT"},
        {"ip_prefix": "roto", "region": "x", "service": "EC2"}
      ],
      "ipv6_prefixes": [
        {"ipv6_prefix": "2600:1f00::/24", "region": "us-east-1", "service": "EC2"}
      ]
    }`)
	got, err := parseAWS(body)
	if err != nil {
		t.Fatalf("parseAWS: %v", err)
	}
	// AMAZON se descarta solo cuando duplica exactamente un servicio
	// específico; los rangos AMAZON-only deben conservarse.
	if len(got) != 4 {
		t.Fatalf("entries = %d (%+v), want 4", len(got), got)
	}
	if got[0].S != "S3" || got[0].G != "us-east-1" || got[0].C != string(Cloud) {
		t.Errorf("fila S3 = %+v", got[0])
	}
	if got[1].S != "AMAZON" || got[1].P != "52.94.2.0/24" {
		t.Errorf("AMAZON-only debería conservarse, got %+v", got[1])
	}
	// CloudFront es CDN, no cloud genérico.
	if got[2].C != string(CDN) {
		t.Errorf("CLOUDFRONT debería clasificarse como cdn, got %q", got[2].C)
	}
	if got[3].P != "2600:1f00::/24" {
		t.Errorf("IPv6 = %+v", got[3])
	}
}

func TestParsePlainListAndFastly(t *testing.T) {
	cf := parsePlainList([]byte("173.245.48.0/20\n\n# comentario\n103.21.244.0/22\nbasura\n"), string(CDN), "Cloudflare")
	if len(cf) != 2 {
		t.Fatalf("cloudflare = %d filas, want 2", len(cf))
	}
	if cf[0].R != "Cloudflare" || cf[0].C != string(CDN) {
		t.Errorf("fila = %+v", cf[0])
	}

	fa, err := parseFastly([]byte(`{"addresses":["23.235.32.0/20"],"ipv6_addresses":["2a04:4e40::/32"]}`))
	if err != nil {
		t.Fatalf("parseFastly: %v", err)
	}
	if len(fa) != 2 {
		t.Errorf("fastly = %d filas, want 2", len(fa))
	}
}

func TestGoogleGlobalIsOwnershipNotCloudWorkload(t *testing.T) {
	body := []byte(`{"prefixes":[{"ipv4Prefix":"8.8.8.0/24","service":"Google","scope":"global"}]}`)
	got, err := parseSource("google", body)
	if err != nil || len(got) != 1 {
		t.Fatalf("parseSource google: rows=%+v err=%v", got, err)
	}
	if got[0].C != string(Enterprise) {
		t.Fatalf("Google global category = %q, want %q", got[0].C, Enterprise)
	}
}

func TestUpdateReplacesOnlyItsOwnSource(t *testing.T) {
	dir := t.TempDir()
	e := &Engine{dataDir: dir}
	// Estado previo con dos fuentes distintas.
	if err := e.save(store{
		Version: storeVersion,
		Sources: []SourceInfo{{ID: "aws", Name: "AWS"}, {ID: "fastly", Name: "Fastly"}},
		Prefixes: []entry{
			{P: "52.94.0.0/16", C: string(Cloud), R: "Amazon AWS", S: "EC2"},
			{P: "23.235.32.0/20", C: string(CDN), R: "Fastly"},
		},
	}); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := e.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	// Quitar AWS no debe tocar Fastly.
	if err := e.Remove("aws"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, ok := e.Lookup(netip.MustParseAddr("52.94.0.1"), ""); ok {
		t.Error("el prefijo de AWS debería haber desaparecido")
	}
	if _, ok := e.Lookup(netip.MustParseAddr("23.235.32.1"), ""); !ok {
		t.Error("Fastly no debería haberse borrado al quitar AWS")
	}
}
