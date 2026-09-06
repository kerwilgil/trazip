package voip

import (
	"strings"

	"trazip/internal/protocol/sdp"
)

// streamAudioStatus classifies ONE RTP stream for audio reconstruction using
// only the media metadata that stream's own m= section negotiated (rm, from
// resolveMediaForStream) — never any other audio section of the same
// Call-ID. A dialog that offers a clear RTP/AVP m-line and a separate
// RTP/SAVP(F) m-line must leave the clear one reconstructable.
func streamAudioStatus(rm resolvedMedia, call *Call) (string, string) {
	if rm.mediaType != "" && rm.mediaType != "audio" {
		return AudioStatusUnsupportedCodec, "media no es audio"
	}
	if call == nil || (call.SDPOffer == nil && call.SDPAnswer == nil) {
		return AudioStatusMissingSDP, "no se observó SDP para confirmar la negociación"
	}
	// Encryption and Annex B are read from THIS stream's own m= section.
	if strings.EqualFold(rm.proto, "RTP/SAVP") || strings.EqualFold(rm.proto, "RTP/SAVPF") {
		return AudioStatusEncryptedUnavailable, "SRTP DETECTED"
	}
	if strings.EqualFold(rm.codecName, "G729") && strings.Contains(strings.ToLower(rm.fmtp), "annexb=yes") {
		return AudioStatusUnsupportedG729AnnexB, "G.729 Annex B/SID/CNG no soportado"
	}
	if !codecSupported(rm.codecName) {
		return AudioStatusUnsupportedCodec, "codec no implementado"
	}
	return AudioStatusReconstructable, ""
}

// callPtime is the whole-call ptime fallback, used only when a stream's own
// m= section did not carry an a=ptime (resolvedMedia.ptimeMs == 0).
func callPtime(call *Call) int {
	if call == nil {
		return 0
	}
	for _, desc := range []*sdp.SDP{call.SDPOffer, call.SDPAnswer} {
		if desc == nil {
			continue
		}
		for _, m := range desc.Media {
			if strings.EqualFold(m.Type, "audio") && m.PtimeMs > 0 {
				return m.PtimeMs
			}
		}
	}
	return 0
}
