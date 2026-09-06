package api

import (
	"strings"
	"testing"

	"trazip/internal/intel/threatfeed"
	"trazip/internal/reputation"
)

// El veredicto que sale de una coincidencia tiene que corresponder a lo que la
// fuente afirma. Spamhaus DROP dice literalmente "no curses tráfico con este
// rango": eso es alto riesgo, no "sospechoso".
//
// Se comprueba sobre los pesos y el mismo cálculo que usa ReputationAssess, no
// sobre una descarga real, para que la prueba no dependa de la red ni de que
// una IP concreta siga estando en la lista mañana.
func TestFeedWeightsLandOnTheRightVerdict(t *testing.T) {
	cases := []struct {
		cat       threatfeed.Category
		wantLevel string
		why       string
	}{
		{threatfeed.CatMalicious, "alto riesgo", "Spamhaus DROP recomienda descartar el tráfico del rango"},
		{threatfeed.CatTor, "sospechoso", "un nodo de salida Tor no es abuso: solo origen inatribuible"},
	}
	for _, c := range cases {
		w, ok := feedWeight[c.cat]
		if !ok {
			t.Errorf("no hay peso definido para la categoría %q", c.cat)
			continue
		}
		// Partiendo de una dirección sin ninguna otra señal (100 puntos).
		base := reputation.Score{Value: 100}
		got := reputation.WithAdapterSignal(base, reputation.Signal{
			Source: "feed:test", Label: string(c.cat), Confidence: "alta",
		}, w)
		if got.Level != c.wantLevel {
			t.Errorf("una coincidencia en %q da %q (%d/100); se esperaba %q — %s",
				c.cat, got.Level, got.Value, c.wantLevel, c.why)
		}
	}
}

// Estar en dos listas es peor que estar en una, y el resultado no puede
// desbordar por abajo.
func TestMultipleFeedHitsAccumulateWithoutUnderflow(t *testing.T) {
	score := reputation.Score{Value: 100}
	for _, cat := range []threatfeed.Category{threatfeed.CatMalicious, threatfeed.CatTor} {
		score = reputation.WithAdapterSignal(score, reputation.Signal{
			Source: "feed:" + string(cat), Label: string(cat),
		}, feedWeight[cat])
	}
	if score.Value != 0 {
		t.Errorf("puntuación = %d; con ambas señales debería tocar fondo en 0", score.Value)
	}
	if score.Level != "alto riesgo" {
		t.Errorf("nivel = %q con dos listas activas", score.Level)
	}
	if len(score.Signals) != 2 {
		t.Errorf("se registraron %d señales; deben quedar las dos como evidencia", len(score.Signals))
	}
}

// Sin listas descargadas, "limpio" no puede leerse como "se comprobó y no
// aparece": hay que decir que no se comprobó nada.
func TestCleanScoreSaysWhenNothingWasChecked(t *testing.T) {
	s := NewService()
	defer s.Close()

	score, err := s.ReputationAssess("8.8.8.8")
	if err != nil {
		t.Fatalf("ReputationAssess: %v", err)
	}
	if s.threatFeed != nil && s.threatFeed.Loaded() {
		t.Skip("hay listas instaladas en este perfil: el caso a cubrir es el contrario")
	}
	if !strings.Contains(score.Freshness, "sin listas de amenazas descargadas") {
		t.Errorf("no se advierte que no hay listas contra las que comprobar: %q", score.Freshness)
	}
}

func TestReputationRejectsInvalidAddress(t *testing.T) {
	s := NewService()
	defer s.Close()
	for _, in := range []string{"", "  ", "no-es-una-ip", "999.1.1.1"} {
		if _, err := s.ReputationAssess(in); err == nil {
			t.Errorf("ReputationAssess(%q) debería fallar", in)
		}
	}
}
