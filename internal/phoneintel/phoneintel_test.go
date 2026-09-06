package phoneintel

import (
	"encoding/json"
	"strings"
	"testing"
)

// El campo que más pesa operativamente es el tipo de línea: decide coste de
// interconexión, si el SMS llega, y si un "móvil" de la lista de un cliente es
// en realidad un DID de VoIP.
func TestAnalyzeClassifiesLineType(t *testing.T) {
	cases := []struct {
		name, input, region string
		wantKind            string
		wantCC              int
	}{
		{"móvil de Panamá", "+507 6123 4567", "", "móvil", 507},
		{"fijo de Panamá", "+507 236 0000", "", "fijo", 507},
		{"móvil sin prefijo, región por defecto", "61234567", "", "móvil", 507},
		{"gratuito de EE.UU.", "+1 800 555 0199", "", "gratuito", 1},
		{"móvil de España", "+34 612 345 678", "", "móvil", 34},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Analyze(c.input, c.region)
			if got.Err != "" {
				t.Fatalf("Analyze(%q) devolvió error: %s", c.input, got.Err)
			}
			if got.Kind != c.wantKind {
				t.Errorf("tipo = %q, se esperaba %q", got.Kind, c.wantKind)
			}
			if got.CountryCode != c.wantCC {
				t.Errorf("código de país = %d, se esperaba %d", got.CountryCode, c.wantCC)
			}
		})
	}
}

// El mismo número escrito de varias formas tiene que reducirse siempre al
// mismo E.164, que es la forma con la que se compara y se guarda.
func TestAnalyzeNormalizesToOneE164(t *testing.T) {
	forms := []string{
		"+507 6123-4567",
		"+50761234567",
		"00507 6123 4567",
		"6123 4567",
		"(507) 6123.4567",
	}
	const want = "+50761234567"
	for _, f := range forms {
		got := Analyze(f, "")
		if got.E164 != want {
			t.Errorf("Analyze(%q).E164 = %q, se esperaba %q", f, got.E164, want)
		}
	}
}

// El tel: URI es la forma que viaja en las cabeceras SIP, así que tiene que
// salir listo para pegar.
func TestAnalyzeGivesRFC3966(t *testing.T) {
	got := Analyze("+507 6123 4567", "")
	if got.RFC3966 != "tel:+507-6123-4567" {
		t.Errorf("RFC3966 = %q", got.RFC3966)
	}
}

// Un número mal transcrito no es lo mismo que uno de longitud imposible, y la
// diferencia decide si alguien vuelve a mirar el dato o lo descarta.
func TestAnalyzeSeparatesImpossibleFromUnassigned(t *testing.T) {
	short := Analyze("+507 12", "")
	if short.Valid {
		t.Error("un número demasiado corto no debería ser válido")
	}
	if len(short.Notes) == 0 {
		t.Error("falta la nota que explica por qué no es válido")
	}

	ok := Analyze("+507 6123 4567", "")
	if !ok.Valid {
		t.Error("un móvil panameño correcto debería ser válido")
	}
}

func TestAnalyzeRejectsGarbageWithoutPanicking(t *testing.T) {
	for _, in := range []string{"", "   ", "abc", "+", "++++", "0", strings.Repeat("9", 40)} {
		got := Analyze(in, "")
		if got.Err == "" && !got.Valid {
			continue // interpretado pero no válido: también es una respuesta
		}
		if got.Err == "" && got.Valid {
			t.Errorf("Analyze(%q) dio por válido un disparate", in)
		}
	}
}

// Sin prefijo internacional se asume una región, y eso hay que decirlo: el
// mismo número puede existir en varios países.
func TestAnalyzeWarnsWhenRegionWasAssumed(t *testing.T) {
	got := Analyze("abc", "")
	if got.Err == "" {
		t.Fatal("se esperaba error de interpretación")
	}
	joined := strings.Join(got.Notes, " ")
	if !strings.Contains(joined, "prefijo internacional") {
		t.Errorf("no se avisa de la región asumida: %v", got.Notes)
	}
}

// Contrato con el frontend: los arreglos nunca llegan como null.
func TestResultArraysAreNeverNull(t *testing.T) {
	for _, in := range []string{"", "abc", "+507 6123 4567"} {
		raw, err := json.Marshal(Analyze(in, ""))
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		s := string(raw)
		for _, f := range []string{"timezones", "notes"} {
			if strings.Contains(s, `"`+f+`":null`) {
				t.Errorf("Analyze(%q) devuelve %q como null: %s", in, f, s)
			}
		}
	}
}

// La portabilidad numérica no está en ninguna base offline, así que el dato de
// operador tiene que ir siempre acompañado de esa advertencia — y viajar junto
// al propio operador, no en las notas generales: como aplica siempre, ocuparía
// permanentemente el sitio destacado de la vista.
func TestCarrierAlwaysCarriesPortabilityCaveat(t *testing.T) {
	got := Analyze("+507 6123 4567", "")
	if got.Carrier == "" {
		t.Skip("esta versión del dataset no trae operador para este rango")
	}
	if !strings.Contains(got.CarrierNote, "portado") {
		t.Errorf("se muestra el operador %q sin advertir de la portabilidad: %q", got.Carrier, got.CarrierNote)
	}
	if strings.Contains(strings.Join(got.Notes, " "), "portado") {
		t.Error("la advertencia de portabilidad no debe ir en Notes: aplica siempre y taparía las notas excepcionales")
	}
}

// Sin operador no hay nada que advertir.
func TestNoCarrierNoteWhenNoCarrier(t *testing.T) {
	got := Analyze("+1 800 555 0199", "")
	if got.Carrier == "" && got.CarrierNote != "" {
		t.Errorf("hay advertencia de portabilidad sin operador: %q", got.CarrierNote)
	}
}
