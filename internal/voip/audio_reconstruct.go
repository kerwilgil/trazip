package voip

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/gopacket/gopacket"
	"trazip/internal/pcap"
	"trazip/internal/protocol/rtp"
)

type audioFrame struct {
	ext       uint64
	seq       uint16
	timestamp uint32
	payload   []byte
	arrival   time.Time
	index     int
}

const (
	maxAudioPackets      = 200000
	maxEncodedAudioBytes = 32 << 20
	maxOutputWAVBytes    = maxAudioSamples * 4 // estéreo PCM16
)

// acceptEncodedFrame is the single decision point for the RTP-ingest
// ceilings: reconstructStream calls it once per candidate frame, and the
// boundary tests call it with the real constants above so "MAX allowed /
// MAX+1 rejected" is proven against the exact code path production runs —
// never a copy of the condition. Both checks are ordered so the rejection
// happens BEFORE any allocation proportional to the input.
func acceptEncodedFrame(packetCount, encodedBytes, nextPayloadBytes int) bool {
	if packetCount >= maxAudioPackets {
		return false
	}
	if nextPayloadBytes > maxEncodedAudioBytes-encodedBytes {
		return false
	}
	return true
}

type audioTrack struct {
	samples  []int16
	filled   int
	start    time.Time
	degraded bool
}

// reconstructStream vuelve a leer exclusivamente el flujo seleccionado. No
// conserva payloads durante Analyze y, por tanto, mantiene acotado el consumo.
func reconstructStream(ctx context.Context, path string, stream StreamInfo) (audioTrack, error) {
	if stream.AudioStatus == AudioStatusSRTPDetected || stream.AudioStatus == AudioStatusEncryptedUnavailable {
		return audioTrack{}, fmt.Errorf("SRTP DETECTED: ENCRYPTED AUDIO: AUDIO RECONSTRUCTION UNAVAILABLE")
	}
	if stream.AudioStatus == AudioStatusUnsupportedG729AnnexB {
		return audioTrack{}, fmt.Errorf("G.729 Annex B/SID/CNG no soportado")
	}
	if !codecSupported(stream.CodecName) {
		return audioTrack{}, fmt.Errorf("códec no soportado para reconstrucción: %s", stream.CodecName)
	}
	decoder, err := decoderForStream(stream)
	if err != nil {
		return audioTrack{}, err
	}
	frames := make([]audioFrame, 0, 128)
	encodedBytes := 0
	var limitErr error
	_, err = pcap.ReadPackets(ctx, path, func(_ int, p gopacket.Packet) {
		srcIP, dstIP, srcPort, dstPort, raw, ok := udpTuple(p)
		if !ok || len(raw) == 0 {
			return
		}
		src, dst := fmt.Sprintf("%s:%d", srcIP, srcPort), fmt.Sprintf("%s:%d", dstIP, dstPort)
		if stream.Src != "" && stream.Src != src {
			return
		}
		if stream.Dst != "" && stream.Dst != dst {
			return
		}
		arrival := p.Metadata().Timestamp
		if !stream.FirstSeen.IsZero() && arrival.Before(stream.FirstSeen.Add(-2*time.Second)) {
			return
		}
		if !stream.LastSeen.IsZero() && arrival.After(stream.LastSeen.Add(2*time.Second)) {
			return
		}
		h, e := rtp.ParseHeader(raw)
		if e != nil || h.SSRC != stream.SSRC || (stream.PayloadType >= 0 && h.PayloadType != stream.PayloadType) {
			return
		}
		body := rtp.Payload(raw, h)
		if len(body) == 0 {
			return
		}
		if limitErr != nil {
			return
		}
		if !acceptEncodedFrame(len(frames), encodedBytes, len(body)) {
			limitErr = fmt.Errorf("%s", AudioStatusResourceLimit)
			return
		}
		encodedBytes += len(body)
		frames = append(frames, audioFrame{seq: h.SeqNum, timestamp: h.Timestamp, payload: append([]byte(nil), body...), arrival: arrival, index: len(frames)})
	})
	if err != nil {
		return audioTrack{}, err
	}
	if limitErr != nil {
		return audioTrack{}, limitErr
	}
	if len(frames) == 0 {
		return audioTrack{}, fmt.Errorf("no se encontraron paquetes RTP para ese stream")
	}

	// Extiende secuencias alrededor de la primera llegada, permite wraparound y
	// mantiene un solo paquete para duplicados antes de ordenar.
	var tracker sequenceTracker
	seen := make(map[uint64]bool, len(frames))
	unique := frames[:0]
	for _, f := range frames {
		f.ext = tracker.extend(f.seq)
		if seen[f.ext] {
			continue
		}
		seen[f.ext] = true
		unique = append(unique, f)
	}
	frames = unique
	sort.SliceStable(frames, func(i, j int) bool {
		if frames[i].ext == frames[j].ext {
			return frames[i].index < frames[j].index
		}
		return frames[i].ext < frames[j].ext
	})

	clock := stream.ClockRate
	if clock <= 0 {
		clock = audioSampleRate
	}
	if clock != audioSampleRate {
		return audioTrack{}, fmt.Errorf("clock rate no soportado para audio: %d", clock)
	}
	baseTS := frames[0].timestamp
	capacity := len(frames) * 160
	if capacity > maxAudioSamples {
		capacity = maxAudioSamples
	}
	out := make([]int16, 0, capacity)
	track := audioTrack{start: frames[0].arrival}
	for _, f := range frames {
		offset := int(uint32(f.timestamp - baseTS))
		if offset > maxAudioSamples || offset > maxOutputWAVBytes/2 {
			return audioTrack{}, fmt.Errorf("el audio reconstruido excede el máximo exportable de 30 minutos")
		}
		if offset > len(out) {
			gap := offset - len(out)
			if len(out)+gap > maxAudioSamples {
				return audioTrack{}, fmt.Errorf("el audio reconstruido excede el máximo exportable de 30 minutos")
			}
			out = append(out, make([]int16, gap)...)
			track.filled += gap
			track.degraded = true
		}
		pcm, e := decoder.Decode(f.payload)
		if e != nil {
			if stream.CodecName == "G729" && len(f.payload) == 2 {
				return audioTrack{}, fmt.Errorf("%s", AudioStatusUnsupportedG729AnnexB)
			}
			return audioTrack{}, fmt.Errorf("no se pudo decodificar RTP seq=%d: %w", f.seq, e)
		}
		if len(out)+len(pcm) > maxAudioSamples {
			return audioTrack{}, fmt.Errorf("el audio reconstruido excede el máximo exportable de 30 minutos")
		}
		if offset < len(out) { // RTP retransmitido tardío: no sobrescribe audio ya estable.
			continue
		}
		out = append(out, pcm...)
	}
	track.samples = out
	return track, nil
}

// sequenceTracker elige la época de 16 bits más cercana al mayor paquete visto.
// Es estable para reordenamientos razonables y soporta múltiples wraps.
type sequenceTracker struct {
	highest uint64
	started bool
}

func (s *sequenceTracker) extend(seq uint16) uint64 {
	if !s.started {
		s.started = true
		s.highest = uint64(seq)
		return s.highest
	}
	base := s.highest &^ 0xffff
	candidates := []uint64{base | uint64(seq)}
	if base >= 1<<16 {
		candidates = append(candidates, (base-(1<<16))|uint64(seq))
	}
	candidates = append(candidates, (base+(1<<16))|uint64(seq))
	best := candidates[0]
	dist := absSeq(best, s.highest)
	for _, c := range candidates[1:] {
		if d := absSeq(c, s.highest); d < dist {
			best, dist = c, d
		}
	}
	if best > s.highest {
		s.highest = best
	}
	return best
}
func absSeq(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}
