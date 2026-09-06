package diagnosis

import "trazip/internal/intel/external"

// Destination classes — a reader doesn't need protocol knowledge to
// understand these, unlike "resolver at 1.1.1.1:53" or a RIPEstat URL.
const (
	DestSystemResolver = "system_resolver"
	DestPublicResolver = "public_resolver"
	DestTarget         = "target"
	DestTargetPath     = "target_path"
	DestRIR            = "rir"
	DestRIPEstat       = "ripestat"
)

// aggregateNetworkDisclosure flattens every stage's own NetworkOut/
// NetworkActions into the report-level view — extracted as its own pure
// function purely for unit-testability (Phase B.1 fix #5) without needing a
// live DiagnoseTarget run.
func aggregateNetworkDisclosure(stages []DiagnosticStage) (networkOut bool, actions []NetworkAction) {
	for _, s := range stages {
		if s.NetworkOut {
			networkOut = true
		}
		actions = append(actions, s.NetworkActions...)
	}
	return networkOut, actions
}

// netAction builds one NetworkAction with a consistent timestamp source —
// external.Now() (RFC3339), the same one rdap/bgp's own Disclosure envelope
// already uses, so every "when did this leave the host" timestamp in the
// app is formatted identically (Phase B.1 fix #5).
func netAction(stageID, kind, subject, destClass, dataSent string) NetworkAction {
	return NetworkAction{
		StageID: stageID, Kind: kind, Subject: subject,
		DestinationClass: destClass, DataSent: dataSent, QueriedAt: external.Now(),
	}
}
