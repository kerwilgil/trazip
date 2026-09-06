package diagnosis

import "trazip/internal/model"

// stagePriority is the fixed tie-break order correlate() walks when more
// than one stage shares the same severity — Resolution first because every
// later stage's own result is conditioned on it (no IP, no reachability/
// route/ownership/reputation to speak of), then roughly the order a human
// diagnosing a failure would ask questions in.
var stagePriority = []string{
	StageIDResolution, StageIDHTTP, StageIDRoutingSecurity,
	StageIDReachability, StageIDRoute, StageIDTLS, StageIDOwnership, StageIDReputation,
}

// availabilityStages are the checks that speak to "is this endpoint actually
// up and answering" — the only ones counterEvidenceFor draws from. Ownership,
// Routing Security and Reputation are posture/context findings, not
// availability signals: an RPKI-invalid finding isn't "contradicted" by HTTP
// answering (both can be true at once), so a Warning driven by one of those
// gets no automatic counter-evidence at all — see counterEvidenceFor.
var availabilityStages = []string{StageIDResolution, StageIDReachability, StageIDRoute, StageIDTLS, StageIDHTTP}

func isAvailabilityStage(id string) bool {
	for _, a := range availabilityStages {
		if a == id {
			return true
		}
	}
	return false
}

func severity(st StageStatus) int {
	switch st {
	case StageProblem:
		return 4
	case StageWarning:
		return 3
	case StageUnknown, StageError:
		return 2
	case StageOK:
		return 1
	default: // StageSkipped
		return 0
	}
}

// correlate turns every stage's own (already-hedged) Status/Summary into
// the report's single global conclusion — reading each stage's structured
// Status, never re-parsing its Summary string, so this never confuses
// correlation-in-time with causation (master plan: "Usar hechos
// estructurados. NO basarse solo en strings.", "no confundir correlación
// temporal con causa").
//
// The single most severe stage drives the headline Level/Summary.
// Evidence/CounterEvid follow the verdict, not a blanket "Warning/Problem
// stages are Evidence, OK stages are CounterEvid" rule — that would
// misrepresent a clean run as a negative conclusion surrounded by
// "contradicting" proof, when there is no negative conclusion to contradict
// (Phase B.1 fix #1):
//
//   - Healthy verdict (nothing worse than OK ran): every OK stage's evidence
//     IS the positive finding — it becomes Evidence, and CounterEvid stays
//     empty because there is no negative claim to counter.
//   - Warning/Problem verdict: every Warning/Problem stage's evidence
//     supports the finding (Evidence); only OK stages that are themselves an
//     availability signal (see availabilityStages) become CounterEvid —
//     never every unrelated OK stage, which would bury the one fact that
//     actually matters (e.g. "HTTP 200" next to an unanswered ping) under
//     irrelevant noise (e.g. a clean reputation score).
//   - Inconclusive (Unknown/Error) verdict: Evidence reflects whatever that
//     stage itself produced (usually little to nothing — the whole point of
//     "inconclusive"); CounterEvid stays empty on purpose, because dressing
//     an inconclusive result up with unrelated "proof of health" would make
//     it read as a confirmed-clean verdict, not the "couldn't tell" it is.
func correlate(stages []DiagnosticStage, rt resolvedTarget, haveIP bool) (summary string, level model.Level, confidence model.Confidence, evidence, counter []model.Evidence, limitations []string) {
	byID := make(map[string]DiagnosticStage, len(stages))
	for _, s := range stages {
		byID[s.ID] = s
		limitations = append(limitations, s.Limitations...)
	}

	// Pick the driving stage: highest severity, ties broken by stagePriority.
	var driver DiagnosticStage
	driverSeverity := -1
	for _, id := range stagePriority {
		s, ok := byID[id]
		if !ok {
			continue
		}
		sev := severity(s.Status)
		if sev > driverSeverity {
			driver, driverSeverity = s, sev
		}
	}

	ran := 0
	unknownOrError := 0
	for _, s := range stages {
		if s.Status == StageSkipped {
			continue
		}
		ran++
		if s.Status == StageUnknown || s.Status == StageError {
			unknownOrError++
		}
	}

	conf := 80
	if !haveIP && rt.kind != "ip" {
		conf -= 20
	}
	if ran > 0 {
		conf -= (unknownOrError * 10) / ran
	}

	switch {
	case ran == 0:
		summary = "No se ejecutó ninguna prueba activa (modo offline, o sin dirección resoluble)."
		level = model.LevelInfo

	case driverSeverity <= 1:
		level = model.LevelInfo
		conf += 10
		for _, s := range stages {
			if s.Status == StageOK {
				evidence = append(evidence, s.Evidence...)
			}
		}
		// Prefer the most user-relevant positive result (HTTP/TLS: "is it
		// actually accessible") over Resolution's own summary, which is
		// technically true but tells a reader the least when nothing went
		// wrong (master plan example: "TLS válido + HTTP 200: servicio web
		// accesible").
		if ok, found := bestOKSummary(byID); found {
			summary = ok
		} else {
			summary = "Sin hallazgos: " + driver.Summary
		}

	case driver.Status == StageWarning:
		summary = driver.Summary
		level = model.LevelLow
		if driver.ID == StageIDReputation || driver.ID == StageIDRoutingSecurity {
			level = model.LevelMedium
		}
		evidence = collectFindingEvidence(stages)
		counter = counterEvidenceFor(driver, byID)

	case driver.Status == StageProblem:
		summary = driver.Summary
		level = model.LevelMedium
		evidence = collectFindingEvidence(stages)
		counter = counterEvidenceFor(driver, byID)

	default: // Unknown/Error driving — inconclusive, not negative.
		summary = "Resultado inconcluso: " + driver.Summary
		level = model.LevelLow
		evidence = collectFindingEvidence(stages)
		limitations = append(limitations, "Al menos una etapa no pudo completarse ni confirmar ni descartar un problema; el resultado es inconcluso, no negativo.")
	}

	confidence = model.Confidence(clampConf(conf))
	return summary, level, confidence, evidence, counter, dedupStrings(limitations)
}

// collectFindingEvidence pools every Warning/Problem stage's own evidence —
// there can be more than one simultaneously (e.g. HTTP 500 AND RPKI invalid
// at once), so this is never limited to just the single driving stage.
func collectFindingEvidence(stages []DiagnosticStage) []model.Evidence {
	var out []model.Evidence
	for _, s := range stages {
		if severity(s.Status) >= 3 { // Warning or Problem
			out = append(out, s.Evidence...)
		}
	}
	return out
}

// counterEvidenceFor returns the OK-status availability signals that
// materially bear on driver's own finding — e.g. an unanswered ping (driver)
// next to a clean HTTP 200 (counter), which is exactly the fact that keeps
// the ping finding from reading as "the service is down". Stages outside
// availabilityStages (Ownership, Routing Security, Reputation) never
// auto-populate CounterEvid: their OK status doesn't contradict a Warning
// found elsewhere, so folding it in would just be irrelevant noise (master
// plan: "No meter automáticamente todos los OK irrelevantes como
// contraevidencia."). And when the driver itself isn't an availability
// signal (e.g. RPKI invalid), there is no natural counter-signal to offer at
// all — an HTTP 200 doesn't contradict a routing-security finding, both can
// be true simultaneously — so this returns nil rather than reaching for an
// unrelated stage just to have something to show.
func counterEvidenceFor(driver DiagnosticStage, byID map[string]DiagnosticStage) []model.Evidence {
	if !isAvailabilityStage(driver.ID) {
		return nil
	}
	var out []model.Evidence
	for _, id := range availabilityStages {
		if id == driver.ID {
			continue
		}
		if s, ok := byID[id]; ok && s.Status == StageOK {
			out = append(out, s.Evidence...)
		}
	}
	return out
}

// okPriority is the "everything's fine" headline preference — deliberately
// separate from stagePriority (which orders severity tie-breaks): the most
// reassuring, user-relevant fact ("the web service answers") beats a merely
// necessary precondition ("the name resolved").
var okPriority = []string{
	StageIDHTTP, StageIDTLS, StageIDReachability, StageIDRoute,
	StageIDOwnership, StageIDRoutingSecurity, StageIDReputation, StageIDResolution,
}

func bestOKSummary(byID map[string]DiagnosticStage) (string, bool) {
	for _, id := range okPriority {
		if s, ok := byID[id]; ok && s.Status == StageOK {
			return s.Summary, true
		}
	}
	return "", false
}

func clampConf(v int) int {
	if v < 10 {
		return 10
	}
	if v > 95 {
		return 95
	}
	return v
}

func dedupStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
