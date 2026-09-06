package api

import (
	"encoding/json"
	"strings"
	"testing"
)

// El contrato con el frontend: un campo declarado como arreglo tiene que
// llegar como arreglo, también en los caminos de error.
//
// Un slice nil de Go marshalea a null, y las vistas hacen .length y .map()
// sobre estos campos sin comprobarlo antes, así que un null no da un resultado
// vacío: tumba la vista entera con "Cannot read properties of null".
//
// Ya ocurrió tres veces —findings del Scanner, findings de netdiag y addrs de
// Quick Diagnose con un dominio inexistente— siempre en un retorno temprano
// donde el slice nunca llegó a llenarse. Estas pruebas cubren justamente esos
// caminos, que son los que ninguna prueba del camino feliz toca.

// hasNullArray informa si el JSON declara alguno de esos campos como null.
func hasNullArray(t *testing.T, v any, fields ...string) {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	s := string(raw)
	for _, f := range fields {
		if strings.Contains(s, `"`+f+`":null`) {
			t.Errorf("%q llega al frontend como null y rompe el .length/.map() de la vista: %s", f, s)
		}
	}
}

func TestQuickDiagnoseKeepsAddrsAsArrayOnFailure(t *testing.T) {
	s := NewService()
	defer s.Close()

	// Entrada vacía: retorno temprano con error, sin tocar la red.
	res, err := s.QuickDiagnose("")
	if err == nil {
		t.Error("una entrada vacía debería devolver error")
	}
	if res.Addrs == nil {
		t.Error("Addrs es nil en el camino de error")
	}
	hasNullArray(t, res, "addrs")

	// Espacios en blanco: mismo camino, misma garantía.
	res, _ = s.QuickDiagnose("   ")
	hasNullArray(t, res, "addrs")
}

func TestConnMonSnapshotKeepsConnectionsAsArray(t *testing.T) {
	s := NewService()
	defer s.Close()

	snap, err := s.ConnMonSnapshot()
	if err != nil {
		t.Skipf("no se pudieron leer los sockets en este entorno: %v", err)
	}
	if snap.Connections == nil {
		t.Error("Connections es nil: la vista de Conexiones hace .map() sobre él")
	}
	hasNullArray(t, snap, "connections")
}

func TestMACLookupNeverPanicsOnJunk(t *testing.T) {
	s := NewService()
	defer s.Close()

	// La consulta acepta lo que el operador escriba, incluida una entrada a
	// medio teclear: no debe entrar en pánico ni con cadenas cortas ni con
	// caracteres que no son hexadecimales.
	for _, in := range []string{"", " ", "z", "74", "74:4d", "74:4d:28", "no-es-una-mac", "ffffffffffffffffff"} {
		d := s.MACLookup(in)
		if d.Input != strings.TrimSpace(in) {
			t.Errorf("MACLookup(%q) perdió la entrada original: %q", in, d.Input)
		}
	}
}
