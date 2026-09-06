package voip

import "math"

// EstimateMOS computes a coarse Mean Opinion Score from RTP loss and jitter
// using a simplified ITU-T G.107 E-model. Constants (Ie=0, Bpl=4.3) are the
// published G.711 baseline from ITU-T G.113 Appendix I. This is deliberately
// NOT a full E-model: it has no measured one-way delay (not observable from a
// passive capture), a single loss-impairment curve for all codecs, and a
// jitter penalty that is an added heuristic, not part of the original model.
// Treat the result as a directional indicator, not a precise measurement.
func EstimateMOS(lossPct, jitterMs float64) MOSEstimate {
	const ie, bpl = 0.0, 4.3

	limitations := []string{
		"No incluye retardo de un solo sentido (no medible de forma pasiva desde una captura)",
		"Constantes de pérdida (Ie/Bpl) calibradas para G.711; se usan como aproximación para otros códecs",
		"La penalización por jitter es una heurística añadida, no parte del E-model original",
	}

	if lossPct < 0 {
		lossPct = 0
	}
	ieEff := ie
	if lossPct > 0 {
		ieEff = ie + (95-ie)*(lossPct/(lossPct+bpl))
	}
	r := 93.2 - ieEff

	if jitterMs > 30 {
		penalty := math.Min(10, (jitterMs-30)/7)
		r -= penalty
	}
	if r < 0 {
		r = 0
	}
	if r > 100 {
		r = 100
	}

	mos := 1 + 0.035*r + 7e-6*r*(r-60)*(100-r)
	if mos < 1 {
		mos = 1
	}
	if mos > 4.5 {
		mos = 4.5
	}

	return MOSEstimate{
		Score:       math.Round(mos*100) / 100,
		Formula:     "E-model simplificado (ITU-T G.107/G.113, línea base G.711)",
		Limitations: limitations,
	}
}
