package voip

import (
	"fmt"
	"strings"
)

type audioDecoder interface{ Decode([]byte) ([]int16, error) }

// decoderForStream is the single point where a codec name becomes a concrete
// decoder. It is a var, not a plain func, so isolation tests can wrap it with a
// call counter and prove that encrypted (SRTP) and non-voice (telephone-event)
// streams never reach a decoder at all.
var decoderForStream = func(s StreamInfo) (audioDecoder, error) {
	switch strings.ToUpper(s.CodecName) {
	case "PCMU":
		return pcmuDecoder{}, nil
	case "PCMA":
		return pcmaDecoder{}, nil
	case "G729", "G.729":
		return newG729Decoder()
	default:
		return nil, fmt.Errorf("códec no soportado para reconstrucción: %s", s.CodecName)
	}
}

func codecSupported(name string) bool {
	switch strings.ToUpper(name) {
	case "PCMU", "PCMA", "G729", "G.729":
		return true
	}
	return false
}
