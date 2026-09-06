package voip

import (
	"testing"
	"trazip/internal/protocol/rtp"
)

func FuzzG729FrameSlicing(f *testing.F) {
	f.Add([]byte{0})
	f.Add(make([]byte, 10))
	f.Add(make([]byte, 20))
	f.Fuzz(func(t *testing.T, payload []byte) {
		d, err := newG729Decoder()
		if err != nil {
			t.Fatal(err)
		}
		_, _ = d.Decode(payload) // El adaptador debe devolver error, nunca panic.
	})
}

func FuzzRTPReconstructionInputs(f *testing.F) {
	f.Add([]byte{0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1})
	f.Add([]byte{0x80})
	f.Fuzz(func(t *testing.T, raw []byte) {
		h, err := rtp.ParseHeader(raw)
		if err != nil {
			return
		}
		_ = rtp.Payload(raw, h)
	})
}

func FuzzExtendedSequence(f *testing.F) {
	f.Add(uint16(65534), uint16(0), uint16(1))
	f.Fuzz(func(t *testing.T, a, b, c uint16) {
		var s sequenceTracker
		_ = s.extend(a)
		_ = s.extend(b)
		_ = s.extend(c)
		if s.highest < uint64(a) && s.highest < uint64(b) && s.highest < uint64(c) {
			t.Fatal("highest invalid")
		}
	})
}

func FuzzWAVLengthCalculations(f *testing.F) {
	f.Add(8000, 1, 8)
	f.Add(8000, 2, 16)
	f.Fuzz(func(t *testing.T, rate, channels, n int) {
		if rate < 1 || rate > 192000 || channels < 1 || channels > 2 || n < 0 || n > 100000 {
			return
		}
		wav := WriteWAVChannels(rate, channels, make([]int16, n))
		if len(wav) > 0 && len(wav) != 44+n*2 {
			t.Fatalf("longitud WAV inválida")
		}
	})
}
