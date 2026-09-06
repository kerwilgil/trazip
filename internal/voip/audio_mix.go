package voip

import (
	"context"
	"fmt"
)

type AudioMode string

const (
	AudioModeCaller AudioMode = "caller"
	AudioModeCallee AudioMode = "callee"
	AudioModeMono   AudioMode = "mono"
	AudioModeStereo AudioMode = "stereo"
)

type AudioResult struct {
	WAV           []byte `json:"-"`
	Channels      int    `json:"channels"`
	Samples       int    `json:"samples"`
	FilledSamples int    `json:"filledSamples"`
	Degraded      bool   `json:"degraded"`
	Status        string `json:"status"`
}

const maxMixTimelineSamples = maxAudioSamples

// previewAllowed usa metadatos RTP ya validados para cortar antes de releer,
// decodificar, construir WAV o codificar base64.
func PreviewAllowed(call Call, channels int, maxBytes int) error {
	var maxMs float64
	for _, s := range call.Streams {
		if s.Stats.RTPDurationMs > maxMs {
			maxMs = s.Stats.RTPDurationMs
		}
	}
	samples := int64(maxMs/1000*audioSampleRate) + audioSampleRate
	if samples < 0 || samples > int64(maxMixTimelineSamples) || samples > int64(maxBytes/(channels*2)) {
		return fmt.Errorf("%s", AudioStatusResourceLimit)
	}
	return nil
}

func ReconstructCallAudio(ctx context.Context, path string, call Call, mode AudioMode) (AudioResult, error) {
	if len(call.Streams) == 0 {
		return AudioResult{}, fmt.Errorf("la llamada no contiene streams RTP")
	}
	var caller, callee []audioTrack
	sawEncrypted := false
	for _, s := range call.Streams {
		if s.MediaType != "" && s.MediaType != "audio" {
			continue
		}
		// An encrypted (SRTP) m= section never blocks a clear RTP/AVP sibling
		// in the same dialog — it is skipped, and only surfaces as the call's
		// error if it turns out to be the ONLY audio media.
		if s.AudioStatus == AudioStatusSRTPDetected || s.AudioStatus == AudioStatusEncryptedUnavailable {
			sawEncrypted = true
			continue
		}
		if !codecSupported(s.CodecName) {
			continue
		}
		track, err := reconstructStream(ctx, path, s)
		if err != nil {
			return AudioResult{}, err
		}
		if s.Direction == "caller" {
			caller = append(caller, track)
		} else if s.Direction == "callee" {
			callee = append(callee, track)
		} else if mode == AudioModeCaller || mode == AudioModeCallee {
			return AudioResult{}, fmt.Errorf("unknown_direction")
		} else {
			// En conversación desconocida se conserva audio sin inventar canal.
			caller = append(caller, track)
		}
	}
	if mode == AudioModeCaller && len(caller) == 0 {
		if sawEncrypted {
			return AudioResult{}, fmt.Errorf("SRTP DETECTED: ENCRYPTED AUDIO: AUDIO RECONSTRUCTION UNAVAILABLE")
		}
		return AudioResult{}, fmt.Errorf("no hay audio caller reconstruible")
	}
	if mode == AudioModeCallee && len(callee) == 0 {
		if sawEncrypted {
			return AudioResult{}, fmt.Errorf("SRTP DETECTED: ENCRYPTED AUDIO: AUDIO RECONSTRUCTION UNAVAILABLE")
		}
		return AudioResult{}, fmt.Errorf("no hay audio callee reconstruible")
	}
	var tracks []audioTrack
	if mode == AudioModeCaller {
		tracks = caller
	} else if mode == AudioModeCallee {
		tracks = callee
	} else {
		tracks = append(caller, callee...)
	}
	if len(tracks) == 0 {
		if sawEncrypted {
			return AudioResult{}, fmt.Errorf("SRTP DETECTED: ENCRYPTED AUDIO: AUDIO RECONSTRUCTION UNAVAILABLE")
		}
		return AudioResult{}, fmt.Errorf("no hay audio reconstruible")
	}
	start := tracks[0].start
	for _, t := range tracks[1:] {
		if t.start.Before(start) {
			start = t.start
		}
	}
	combine := func(group []audioTrack) ([]int16, int, bool) {
		var out []int16
		filled := 0
		degraded := false
		for _, t := range group {
			off := int(t.start.Sub(start).Seconds() * audioSampleRate)
			if off < 0 {
				off = 0
			}
			if off > maxMixTimelineSamples || len(t.samples) > maxMixTimelineSamples-off {
				return nil, 0, true
			}
			if len(out) < off+len(t.samples) {
				out = append(out, make([]int16, off+len(t.samples)-len(out))...)
			}
			for i, v := range t.samples {
				n := int(out[off+i]) + int(v)
				if n > 32767 {
					n = 32767
				}
				if n < -32768 {
					n = -32768
				}
				out[off+i] = int16(n)
			}
			filled += t.filled
			degraded = degraded || t.degraded
		}
		return out, filled, degraded
	}
	left, filledL, degradedL := combine(caller)
	right, filledR, degradedR := combine(callee)
	if left == nil && len(caller) > 0 || right == nil && len(callee) > 0 {
		return AudioResult{}, fmt.Errorf("%s", AudioStatusResourceLimit)
	}
	if mode == AudioModeCaller {
		left, filledL, degradedL = combine(caller)
		return audioResult(left, 1, filledL, degradedL), nil
	}
	if mode == AudioModeCallee {
		right, filledR, degradedR = combine(callee)
		return audioResult(right, 1, filledR, degradedR), nil
	}
	if mode == AudioModeMono {
		mono := mixMono(left, right)
		return audioResult(mono, 1, filledL+filledR, degradedL || degradedR), nil
	}
	n := len(left)
	if len(right) > n {
		n = len(right)
	}
	if n > maxMixTimelineSamples || n > maxOutputWAVBytes/4 {
		return AudioResult{}, fmt.Errorf("%s", AudioStatusResourceLimit)
	}
	inter := make([]int16, n*2)
	for i := 0; i < n; i++ {
		if i < len(left) {
			inter[2*i] = left[i]
		}
		if i < len(right) {
			inter[2*i+1] = right[i]
		}
	}
	return audioResult(inter, 2, filledL+filledR, degradedL || degradedR), nil
}

func audioResult(samples []int16, channels, filled int, degraded bool) AudioResult {
	status := AudioStatusReconstructable
	if degraded {
		status = AudioStatusDegraded
	}
	return AudioResult{WAV: WriteWAVChannels(audioSampleRate, channels, samples), Channels: channels, Samples: len(samples) / channels, FilledSamples: filled, Degraded: degraded, Status: status}
}
func mixMono(a, b []int16) []int16 {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	out := make([]int16, n)
	for i := 0; i < n; i++ {
		x := 0
		if i < len(a) {
			x += int(a[i])
		}
		if i < len(b) {
			x += int(b[i])
		}
		if x > 32767 {
			x = 32767
		}
		if x < -32768 {
			x = -32768
		}
		out[i] = int16(x)
	}
	return out
}
