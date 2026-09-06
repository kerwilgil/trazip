package voip

import (
	"strings"
	"trazip/internal/protocol/sdp"
)

// mediaDirection usa la dirección media anunciada por offer/answer; no la IP
// de señalización. Cuando la evidencia no basta, mantiene unknown_direction.
func mediaDirection(call *Call, src string) string {
	if call == nil {
		return "unknown_direction"
	}
	if hasMediaSource(call.SDPOffer, src) {
		return "caller"
	}
	if hasMediaSource(call.SDPAnswer, src) {
		return "callee"
	}
	return "unknown_direction"
}

func hasMediaSource(desc *sdp.SDP, src string) bool {
	if desc == nil {
		return false
	}
	for _, m := range desc.Media {
		if strings.HasPrefix(src, m.ConnAddr+":") {
			return true
		}
	}
	return false
}
