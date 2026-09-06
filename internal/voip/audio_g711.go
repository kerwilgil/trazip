package voip

type pcmuDecoder struct{}

func (pcmuDecoder) Decode(payload []byte) ([]int16, error) {
	out := make([]int16, len(payload))
	for i, b := range payload {
		out[i] = ulaw2linear(b)
	}
	return out, nil
}

type pcmaDecoder struct{}

func (pcmaDecoder) Decode(payload []byte) ([]int16, error) {
	out := make([]int16, len(payload))
	for i, b := range payload {
		out[i] = alaw2linear(b)
	}
	return out, nil
}

func ulaw2linear(u byte) int16 {
	u = ^u
	sign, exponent, mantissa := u&0x80, (u>>4)&7, u&15
	s := ((int32(mantissa) << 3) + 0x84) << exponent
	s -= 0x84
	if sign != 0 {
		s = -s
	}
	return int16(s)
}

// alaw2linear sigue la ecuación G.711 A-law, sin dependencia externa.
func alaw2linear(a byte) int16 {
	a ^= 0x55
	t := int32(a&0x0f) << 4
	seg := (a & 0x70) >> 4
	switch seg {
	case 0:
		t += 8
	case 1:
		t += 0x108
	default:
		t += 0x108
		t <<= seg - 1
	}
	if a&0x80 == 0 {
		return int16(-t)
	}
	return int16(t)
}
