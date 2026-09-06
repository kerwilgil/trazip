package voip

// Thresholds shared by AuditCalls and Diagnose, so the two judgements this
// package makes about the same capture — a per-finding audit flag and a
// per-call overall diagnosis — never disagree about what counts as
// "elevated". Centralizing these named constants is as far as this needs to
// go; a shared struct or config layer would be more machinery than a handful
// of numbers warrant.
const (
	// lossWarnPct is the loss percentage AuditCalls flags as a finding and
	// Diagnose treats as the boundary into "degraded". lossHighPct is double
	// that: the point Diagnose calls the quality poor rather than just degraded.
	lossWarnPct  = 5.0
	lossHighPct  = 10.0
	mosLowScore  = 3.5 // matches the frontend's mosClass() bad/warn boundary
	mosPoorScore = 2.5
	// sipRetransWarn matches AuditCalls' "retransmisiones elevadas" finding.
	sipRetransWarn = 3
	// jitterElevatedMs is the same boundary EstimateMOS (mos.go) starts
	// penalizing jitter at — not an independently chosen number.
	jitterElevatedMs = 30.0
	// clockSkewWarnMs has no prior threshold anywhere in TRAZIP to reuse; this
	// is a new, deliberately conservative value introduced for Diagnose only.
	clockSkewWarnMs = 50.0
)
