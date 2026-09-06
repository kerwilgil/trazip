// Package throughput implements TRAZIP's own bandwidth-measurement protocol
// (prompt maestro §9 Fase 5, módulo 24). It deliberately does NOT shell out
// to iperf3: a small self-contained client/server protocol measures TCP and
// UDP throughput in download, upload and bidirectional modes, with
// configurable duration, parallel streams and buffer size, reporting
// throughput plus (for UDP) loss and RFC 3550-style jitter, as a
// reproducible JSON Result.
//
// Wire model: the client opens one TCP control connection to negotiate a
// Params handshake and to receive the server's final summary. Data then
// flows on dedicated channels (extra TCP connections for TCP tests, a UDP
// socket for UDP tests) so measurement bytes never mix with control JSON.
package throughput

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Direction selects who sends the bulk data.
type Direction string

const (
	Download Direction = "download" // server → client
	Upload   Direction = "upload"   // client → server
	Bidir    Direction = "bidir"    // both
)

// Proto selects the transport under test.
type Proto string

const (
	TCP Proto = "tcp"
	UDP Proto = "udp"
)

// DefaultControlPort is the TRAZIP throughput control port (unassigned by
// IANA; chosen to avoid clashing with iperf3's 5201).
const DefaultControlPort = 5330

const (
	maxControlLine = 16 << 10
	maxDurationMs  = 5 * 60 * 1000
	maxBufferKB    = 1024
	maxUDPPacket   = 65507
)

// Params are the negotiated test parameters sent by the client over control.
type Params struct {
	SessionID  string    `json:"sessionId"`
	Proto      Proto     `json:"proto"`
	Direction  Direction `json:"direction"`
	DurationMs int       `json:"durationMs"`
	Streams    int       `json:"streams"`    // TCP parallel streams (>=1)
	BufferKB   int       `json:"bufferKB"`   // per-write buffer
	UDPPacket  int       `json:"udpPacket"`  // UDP payload bytes
	TargetMbps float64   `json:"targetMbps"` // UDP send rate (0 = unthrottled)
	AccessCode string    `json:"accessCode,omitempty"`
}

// GenerateAccessCode returns a random 6-digit code a server shows in its own
// UI when it starts listening — anyone running a client against it has to
// type the same code back. This is not real authentication (no identity, no
// crypto handshake): the wire protocol only ever moves synthetic bytes, so
// the actual goal is raising "anyone on the LAN who guesses the port" to
// "someone the operator explicitly told the code to", proportional to what's
// actually at risk here.
var cryptoRandRead = rand.Read

func GenerateAccessCode() (string, error) {
	var b [4]byte
	if _, err := cryptoRandRead(b[:]); err != nil {
		return "", fmt.Errorf("no se pudo generar el código de acceso: %w", err)
	}
	n := (uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])) % 1000000
	return fmt.Sprintf("%06d", n), nil
}

func (p *Params) withDefaults() {
	if p.DurationMs <= 0 {
		p.DurationMs = 10000
	}
	if p.Streams <= 0 {
		p.Streams = 1
	}
	if p.Streams > 32 {
		p.Streams = 32
	}
	if p.BufferKB <= 0 {
		p.BufferKB = 128
	}
	if p.UDPPacket <= 0 {
		p.UDPPacket = 1200
	}
	if p.UDPPacket < 32 {
		p.UDPPacket = 32
	}
	if p.Direction == "" {
		p.Direction = Download
	}
	if p.Proto == "" {
		p.Proto = TCP
	}
}

func (p Params) validate() error {
	if strings.TrimSpace(p.SessionID) == "" {
		return fmt.Errorf("sessionId requerido")
	}
	if p.Proto != TCP && p.Proto != UDP {
		return fmt.Errorf("protocolo no soportado: %q", p.Proto)
	}
	if p.Direction != Download && p.Direction != Upload && p.Direction != Bidir {
		return fmt.Errorf("dirección no soportada: %q", p.Direction)
	}
	if p.DurationMs < 100 || p.DurationMs > maxDurationMs {
		return fmt.Errorf("duración fuera de rango (100..%d ms)", maxDurationMs)
	}
	if p.BufferKB < 1 || p.BufferKB > maxBufferKB {
		return fmt.Errorf("buffer fuera de rango (1..%d KB)", maxBufferKB)
	}
	if p.UDPPacket < 32 || p.UDPPacket > maxUDPPacket {
		return fmt.Errorf("paquete UDP fuera de rango (32..%d bytes)", maxUDPPacket)
	}
	if p.TargetMbps < 0 || p.TargetMbps > 100000 {
		return fmt.Errorf("tasa UDP fuera de rango")
	}
	return nil
}

// DirectionResult is throughput for one direction of the test.
type DirectionResult struct {
	Bytes       int64   `json:"bytes"`
	DurationSec float64 `json:"durationSec"`
	Mbps        float64 `json:"mbps"`
	// UDP-only fields (zero for TCP).
	PacketsSent int64   `json:"packetsSent,omitempty"`
	PacketsRecv int64   `json:"packetsRecv,omitempty"`
	LossPct     float64 `json:"lossPct,omitempty"`
	JitterMs    float64 `json:"jitterMs,omitempty"`
}

// Result is the full, reproducible outcome of a throughput test.
type Result struct {
	Params     Params           `json:"params"`
	ServerAddr string           `json:"serverAddr"`
	StartedAt  string           `json:"startedAt"` // RFC3339
	DownStream *DirectionResult `json:"downstream,omitempty"`
	UpStream   *DirectionResult `json:"upstream,omitempty"`
	Streams    int              `json:"streams"`
	Err        string           `json:"err,omitempty"`
}

func mbps(bytes int64, sec float64) float64 {
	if sec <= 0 {
		return 0
	}
	return (float64(bytes) * 8) / sec / 1e6
}

// --- shared framing -------------------------------------------------------

func writeLine(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	return err
}

func readLine(r *bufio.Reader, v any) error {
	line, err := r.ReadSlice('\n')
	if err == bufio.ErrBufferFull || len(line) > maxControlLine {
		return fmt.Errorf("mensaje de control demasiado grande")
	}
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(strings.TrimSpace(string(line))), v)
}

func jsonUnmarshalTrim(line []byte, v any) error {
	return json.Unmarshal([]byte(strings.TrimSpace(string(line))), v)
}

// dataHeader identifies an incoming TCP data connection to its session.
type dataHeader struct {
	SessionID string `json:"sessionId"`
	StreamID  int    `json:"streamId"`
	Token     string `json:"token"`
}

// serverSummary is what the server reports back over control after a test.
type serverSummary struct {
	BytesRecv   int64   `json:"bytesRecv"`   // bytes the server received (client upload)
	BytesSent   int64   `json:"bytesSent"`   // bytes the server sent (client download)
	PacketsSent int64   `json:"packetsSent"` // UDP download packets sent by server
	PacketsRecv int64   `json:"packetsRecv"` // UDP upload
	HighestSeq  int64   `json:"highestSeq"`  // UDP upload
	JitterMs    float64 `json:"jitterMs"`    // UDP upload
}
