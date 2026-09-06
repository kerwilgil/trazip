package voip

import (
	"fmt"
	"github.com/hunydev/g729"
)

// g729Decoder es el único adaptador que conoce tipos de la dependencia.
// Cada stream recibe su propia instancia porque el decoder mantiene estado.
type g729Decoder struct{ decoder *g729.Decoder }

func newG729Decoder() (audioDecoder, error) { return &g729Decoder{decoder: g729.NewDecoder()}, nil }
func (d *g729Decoder) Decode(payload []byte) ([]int16, error) {
	if len(payload) == 2 {
		return nil, fmt.Errorf("%s", AudioStatusUnsupportedG729AnnexB)
	}
	if len(payload) == 0 || len(payload)%g729.FrameBytes != 0 {
		return nil, fmt.Errorf("trama G.729 inválida: %d bytes", len(payload))
	}
	out := make([]int16, 0, len(payload)/g729.FrameBytes*g729.FrameSamples)
	for len(payload) > 0 {
		pcm := make([]int16, g729.FrameSamples)
		if err := d.decoder.DecodeFrame(payload[:g729.FrameBytes], pcm); err != nil {
			return nil, err
		}
		out = append(out, pcm...)
		payload = payload[g729.FrameBytes:]
	}
	return out, nil
}
