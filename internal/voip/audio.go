package voip

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
)

const audioSampleRate = 8000
const maxAudioSamples = audioSampleRate * 60 * 30 // 30 minutos mono por stream

// WriteWAV conserva la API histórica para exportaciones mono.
func WriteWAV(sampleRate int, samples []int16) []byte {
	return WriteWAVChannels(sampleRate, 1, samples)
}

// WriteWAVChannels serializa PCM signed 16-bit intercalado en RIFF/WAVE.
func WriteWAVChannels(sampleRate, channels int, samples []int16) []byte {
	if sampleRate <= 0 || channels < 1 || channels > 2 || len(samples) > (int(^uint32(0))-36)/2 {
		return nil
	}
	dataLen := len(samples) * 2
	buf := bytes.NewBuffer(make([]byte, 0, 44+dataLen))
	buf.WriteString("RIFF")
	writeU32(buf, uint32(36+dataLen))
	buf.WriteString("WAVEfmt ")
	writeU32(buf, 16)
	writeU16(buf, 1)
	writeU16(buf, uint16(channels))
	writeU32(buf, uint32(sampleRate))
	blockAlign := channels * 2
	writeU32(buf, uint32(sampleRate*blockAlign))
	writeU16(buf, uint16(blockAlign))
	writeU16(buf, 16)
	buf.WriteString("data")
	writeU32(buf, uint32(dataLen))
	for _, s := range samples {
		writeU16(buf, uint16(s))
	}
	return buf.Bytes()
}

func writeU32(buf *bytes.Buffer, v uint32) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	buf.Write(b[:])
}
func writeU16(buf *bytes.Buffer, v uint16) {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], v)
	buf.Write(b[:])
}

// ExportStreamAudio mantiene el flujo PCMU ya publicado. El nuevo
// reconstruidor usa identidad de flujo completa cuando la UI conoce la llamada.
func ExportStreamAudio(ctx context.Context, pcapPath string, ssrc uint32, srcHostPort string) ([]byte, int, error) {
	stream := StreamInfo{SSRC: ssrc, Src: srcHostPort, PayloadType: 0, CodecName: "PCMU", ClockRate: audioSampleRate, AudioStatus: AudioStatusReconstructable}
	track, err := reconstructStream(ctx, pcapPath, stream)
	if err != nil {
		return nil, 0, err
	}
	return WriteWAV(audioSampleRate, track.samples), track.filled, nil
}

func invalidWAVError() error { return fmt.Errorf("parámetros WAV no válidos") }
