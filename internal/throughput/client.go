package throughput

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// Run executes a throughput test against a server at addr ("host:port") and
// returns a reproducible Result. It is the single authority for the returned
// numbers, combining its own local byte counts with the server's summary.
func Run(ctx context.Context, addr string, p Params) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{Err: err.Error()}, err
	}
	p.withDefaults()
	if p.SessionID == "" {
		p.SessionID = uuid.NewString()
	}
	resultParams := p
	resultParams.AccessCode = ""
	res := Result{Params: resultParams, ServerAddr: addr, StartedAt: time.Now().Format(time.RFC3339), Streams: p.Streams}
	if err := p.validate(); err != nil {
		res.Err = err.Error()
		return res, err
	}

	dialer := net.Dialer{Timeout: 8 * time.Second}
	control, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		res.Err = "no se pudo conectar al servidor: " + err.Error()
		return res, err
	}
	defer control.Close()
	if err := writeLine(control, p); err != nil {
		res.Err = err.Error()
		return res, err
	}
	br := bufio.NewReader(control)
	_ = control.SetReadDeadline(nextDeadline(ctx, time.Now().Add(8*time.Second)))

	var ready map[string]any
	if err := readLine(br, &ready); err != nil {
		res.Err = "handshake falló: " + err.Error()
		return res, err
	}
	if e, ok := ready["err"].(string); ok && e != "" {
		res.Err = "servidor: " + e
		return res, errors.New(res.Err)
	}
	_ = control.SetReadDeadline(time.Time{})

	if p.Proto == UDP {
		return runUDPClient(ctx, control, br, addr, p, res, ready)
	}
	return runTCPClient(ctx, control, br, addr, p, res, ready)
}

func runTCPClient(ctx context.Context, control net.Conn, br *bufio.Reader, addr string, p Params, res Result, ready map[string]any) (Result, error) {
	dur := time.Duration(p.DurationMs) * time.Millisecond
	dataToken, _ := ready["dataToken"].(string)
	if dataToken == "" {
		return res, errors.New("servidor no entregó token para los streams TCP")
	}
	var localRecv, localSent atomic.Int64

	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < p.Streams; i++ {
		dialer := net.Dialer{Timeout: 5 * time.Second}
		dc, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			continue
		}
		if err := writeLine(dc, dataHeader{SessionID: p.SessionID, StreamID: i, Token: dataToken}); err != nil {
			dc.Close()
			continue
		}
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer c.Close()
			clientTCPStream(ctx, c, p, dur, &localRecv, &localSent)
		}(dc)
	}
	wg.Wait()
	elapsed := time.Since(start).Seconds()
	if err := ctx.Err(); err != nil {
		res.Err = err.Error()
		return res, err
	}

	var sum serverSummary
	control.SetReadDeadline(nextDeadline(ctx, time.Now().Add(5*time.Second)))
	if err := readLine(br, &sum); err != nil {
		res.Err = "resumen del servidor: " + err.Error()
		return res, err
	}

	// download: client received (localRecv); upload: server received (sum.BytesRecv).
	if p.Direction == Download || p.Direction == Bidir {
		b := localRecv.Load()
		res.DownStream = &DirectionResult{Bytes: b, DurationSec: elapsed, Mbps: mbps(b, elapsed)}
	}
	if p.Direction == Upload || p.Direction == Bidir {
		b := sum.BytesRecv
		res.UpStream = &DirectionResult{Bytes: b, DurationSec: elapsed, Mbps: mbps(b, elapsed)}
	}
	return res, nil
}

func clientTCPStream(ctx context.Context, conn net.Conn, p Params, dur time.Duration, recv, sent *atomic.Int64) {
	buf := make([]byte, p.BufferKB*1024)
	stopAt := time.Now().Add(dur)

	sends := p.Direction == Upload || p.Direction == Bidir
	recvs := p.Direction == Download || p.Direction == Bidir

	var wg sync.WaitGroup
	if sends {
		wg.Add(1)
		go func() {
			defer wg.Done()
			payload := make([]byte, p.BufferKB*1024)
			for time.Now().Before(stopAt) && ctx.Err() == nil {
				conn.SetWriteDeadline(nextDeadline(ctx, stopAt))
				n, err := conn.Write(payload)
				sent.Add(int64(n))
				if err != nil {
					return
				}
			}
		}()
	}
	if recvs {
		for {
			if ctx.Err() != nil || time.Now().After(stopAt) {
				break
			}
			conn.SetReadDeadline(nextDeadline(ctx, stopAt))
			n, err := conn.Read(buf)
			recv.Add(int64(n))
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() && ctx.Err() == nil && time.Now().Before(stopAt) {
					continue
				}
				break
			}
		}
	}
	wg.Wait()
}

func runUDPClient(ctx context.Context, control net.Conn, br *bufio.Reader, addr string, p Params, res Result, ready map[string]any) (Result, error) {
	portF, _ := ready["udpPort"].(float64)
	udpPort := int(portF)
	if udpPort == 0 {
		res.Err = "el servidor no asignó puerto UDP"
		return res, errors.New(res.Err)
	}
	udpToken, _ := ready["udpToken"].(string)
	if udpToken == "" {
		return res, errors.New("servidor no entregó token UDP")
	}
	host, _, _ := net.SplitHostPort(addr)
	serverUDP := net.JoinHostPort(host, fmt.Sprintf("%d", udpPort))
	raddr, err := net.ResolveUDPAddr("udp", serverUDP)
	if err != nil {
		res.Err = err.Error()
		return res, err
	}
	pc, err := net.ListenPacket("udp", ":0")
	if err != nil {
		res.Err = err.Error()
		return res, err
	}
	defer pc.Close()

	// Hello so the server learns our address.
	hello := []byte(udpToken)
	if _, err := pc.WriteTo(hello, raddr); err != nil {
		res.Err = err.Error()
		return res, err
	}

	dur := time.Duration(p.DurationMs) * time.Millisecond
	start := time.Now()

	var downPackets, downHighest int64
	var downJitter float64
	var upSent int64
	var wg sync.WaitGroup
	if p.Direction == Upload || p.Direction == Bidir {
		wg.Add(1)
		go func() { defer wg.Done(); upSent = udpSend(ctx, pc, raddr, dur, p) }()
	}
	if p.Direction == Download || p.Direction == Bidir {
		wg.Add(1)
		go func() { defer wg.Done(); downPackets, downHighest, downJitter = udpRecv(ctx, pc, dur) }()
	}
	wg.Wait()
	elapsed := time.Since(start).Seconds()
	if err := ctx.Err(); err != nil {
		res.Err = err.Error()
		return res, err
	}

	var sum serverSummary
	control.SetReadDeadline(nextDeadline(ctx, time.Now().Add(5*time.Second)))
	if err := readLine(br, &sum); err != nil {
		res.Err = "resumen del servidor: " + err.Error()
		return res, err
	}

	if p.Direction == Upload || p.Direction == Bidir {
		expected := upSent
		lost := expected - sum.PacketsRecv
		if lost < 0 {
			lost = 0
		}
		bytes := sum.PacketsRecv * int64(p.UDPPacket)
		dr := &DirectionResult{
			Bytes: bytes, DurationSec: elapsed, Mbps: mbps(bytes, elapsed),
			PacketsSent: expected, PacketsRecv: sum.PacketsRecv, JitterMs: sum.JitterMs,
		}
		if expected > 0 {
			dr.LossPct = float64(lost) / float64(expected) * 100
		}
		res.UpStream = dr
	}
	if p.Direction == Download || p.Direction == Bidir {
		expected := sum.PacketsSent
		if expected == 0 {
			expected = downHighest + 1
		}
		lost := expected - downPackets
		if lost < 0 {
			lost = 0
		}
		bytes := downPackets * int64(p.UDPPacket)
		dr := &DirectionResult{
			Bytes: bytes, DurationSec: elapsed, Mbps: mbps(bytes, elapsed),
			PacketsSent: expected, PacketsRecv: downPackets, JitterMs: round2(downJitter),
		}
		if expected > 0 {
			dr.LossPct = float64(lost) / float64(expected) * 100
		}
		res.DownStream = dr
	}
	return res, nil
}

func udpSend(ctx context.Context, pc net.PacketConn, addr net.Addr, dur time.Duration, p Params) int64 {
	pkt := make([]byte, p.UDPPacket)
	stopAt := time.Now().Add(dur)
	interval := udpInterval(p)
	var seq int64
	next := time.Now()
	for time.Now().Before(stopAt) {
		if ctx.Err() != nil {
			return seq
		}
		binary.BigEndian.PutUint64(pkt[0:8], uint64(seq))
		binary.BigEndian.PutUint64(pkt[8:16], uint64(time.Now().UnixNano()))
		pc.SetWriteDeadline(nextDeadline(ctx, stopAt))
		if _, err := pc.WriteTo(pkt, addr); err != nil {
			return seq
		}
		seq++
		if interval > 0 {
			next = next.Add(interval)
			if d := time.Until(next); d > 0 {
				select {
				case <-time.After(d):
				case <-ctx.Done():
					return seq
				}
			}
		}
	}
	return seq
}

func udpRecv(ctx context.Context, pc net.PacketConn, dur time.Duration) (packets, highestSeq int64, jitter float64) {
	buf := make([]byte, 65535)
	stopAt := time.Now().Add(dur)
	var prevTransit float64
	haveTransit := false
	for {
		if ctx.Err() != nil || time.Now().After(stopAt) {
			break
		}
		pc.SetReadDeadline(nextDeadline(ctx, stopAt))
		n, _, err := pc.ReadFrom(buf)
		now := float64(time.Now().UnixNano()) / 1e6
		if n >= 16 {
			seq := int64(binary.BigEndian.Uint64(buf[0:8]))
			sendMs := float64(binary.BigEndian.Uint64(buf[8:16])) / 1e6
			packets++
			if seq > highestSeq {
				highestSeq = seq
			}
			transit := now - sendMs
			if haveTransit {
				d := transit - prevTransit
				if d < 0 {
					d = -d
				}
				jitter += (d - jitter) / 16
			}
			prevTransit = transit
			haveTransit = true
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && ctx.Err() == nil && time.Now().Before(stopAt) {
				continue
			}
			break
		}
	}
	return packets, highestSeq, jitter
}

func round2(v float64) float64 {
	return float64(int64(v*100+0.5)) / 100
}
