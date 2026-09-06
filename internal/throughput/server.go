package throughput

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Server accepts TRAZIP throughput tests. It is safe for concurrent sessions.
type Server struct {
	mu       sync.Mutex
	sessions map[string]*serverSession
	// accessCode, when non-empty, must be echoed back by the client's Params
	// (see GenerateAccessCode) — set once at construction, never mutated, so
	// no lock is needed to read it.
	accessCode string

	attemptMu sync.Mutex
	attempts  map[string]*accessAttempts // keyed by remote IP (no port)
	active    chan struct{}
}

// accessAttempts tracks failed access-code handshakes from one remote IP, so
// FIND-003 (unbounded brute force of the 6-digit code) can't be automated
// past a handful of guesses.
type accessAttempts struct {
	failures     int
	blockedUntil time.Time
	lastSeen     time.Time
}

const (
	maxAccessFailures = 5
	accessBlockFor    = 30 * time.Second
	maxConnections    = 128
)

type serverSession struct {
	params    Params
	bytesRecv atomic.Int64 // TCP: bytes read from client (upload)
	bytesSent atomic.Int64 // TCP: bytes written to client (download)
	dataConns chan net.Conn
	dataToken string
	udpMu     sync.Mutex
	udp       udpStats
}

type udpStats struct {
	packetsRecv int64
	highestSeq  int64
	jitterMs    float64
}

// NewServer creates an idle throughput server. accessCode, when non-empty,
// gates every control handshake — pass "" to accept any client (e.g. tests).
func NewServer(accessCode string) *Server {
	return &Server{
		sessions:   make(map[string]*serverSession),
		accessCode: accessCode,
		attempts:   make(map[string]*accessAttempts),
		active:     make(chan struct{}, maxConnections),
	}
}

// remoteIP strips the port from a connection's remote address, falling back
// to the raw string if it isn't a host:port pair (e.g. some test dialers).
func remoteIP(conn net.Conn) string {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}
	return host
}

// accessBlocked reports whether ip is currently locked out and, if so, how
// much longer.
func (s *Server) accessBlocked(ip string) (time.Duration, bool) {
	s.attemptMu.Lock()
	defer s.attemptMu.Unlock()
	a := s.attempts[ip]
	if a == nil || a.blockedUntil.IsZero() {
		return 0, false
	}
	if remaining := time.Until(a.blockedUntil); remaining > 0 {
		return remaining, true
	}
	return 0, false
}

// recordAccessFailure counts one wrong access code from ip, locking it out
// for accessBlockFor once maxAccessFailures is reached.
func (s *Server) recordAccessFailure(ip string) {
	s.attemptMu.Lock()
	defer s.attemptMu.Unlock()
	now := time.Now()
	for key, candidate := range s.attempts {
		if !candidate.lastSeen.IsZero() && now.Sub(candidate.lastSeen) > 10*time.Minute && now.After(candidate.blockedUntil) {
			delete(s.attempts, key)
		}
	}
	a := s.attempts[ip]
	if a == nil {
		a = &accessAttempts{}
		s.attempts[ip] = a
	}
	a.failures++
	a.lastSeen = now
	if a.failures >= maxAccessFailures {
		a.blockedUntil = time.Now().Add(accessBlockFor)
		a.failures = 0
	}
}

// resetAccessFailures clears ip's record after a successful handshake.
func (s *Server) resetAccessFailures(ip string) {
	s.attemptMu.Lock()
	defer s.attemptMu.Unlock()
	delete(s.attempts, ip)
}

// ListenAndServe binds the TCP control listener and serves until ctx is
// cancelled. UDP data sockets are created per session and their ephemeral port
// is returned over the authenticated control channel.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return s.Serve(ctx, ln)
}

// Serve accepts control connections from an already-bound listener. It lets the
// desktop app report the concrete address (including a port chosen by the OS)
// before serving requests.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	defer ln.Close()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		select {
		case s.active <- struct{}{}:
			go func() {
				defer func() { <-s.active }()
				s.handleConn(ctx, conn)
			}()
		default:
			conn.Close()
		}
	}
}

// handleConn peeks the first line: a Params line starts a control session; a
// dataHeader line attaches a data stream to an existing session.
func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReaderSize(conn, maxControlLine)
	line, err := br.ReadSlice('\n')
	if err != nil || len(line) > maxControlLine {
		conn.Close()
		return
	}
	// Disambiguate control vs data by attempting Params first.
	var p Params
	if e := jsonUnmarshalTrim(line, &p); e == nil && p.SessionID != "" && p.Proto != "" {
		s.handleControl(ctx, conn, br, p)
		return
	}
	var dh dataHeader
	if e := jsonUnmarshalTrim(line, &dh); e == nil && dh.SessionID != "" {
		s.handleData(ctx, conn, dh)
		return
	}
	conn.Close()
}

func (s *Server) handleControl(ctx context.Context, conn net.Conn, br *bufio.Reader, p Params) {
	defer conn.Close()
	p.withDefaults()
	if err := p.validate(); err != nil {
		_ = writeLine(conn, map[string]any{"err": err.Error()})
		return
	}
	if s.accessCode != "" {
		ip := remoteIP(conn)
		if remaining, blocked := s.accessBlocked(ip); blocked {
			_ = writeLine(conn, map[string]any{"err": fmt.Sprintf("demasiados intentos fallidos, reintentá en %ds", int(remaining.Seconds())+1)})
			return
		}
		if subtle.ConstantTimeCompare([]byte(p.AccessCode), []byte(s.accessCode)) != 1 {
			s.recordAccessFailure(ip)
			_ = writeLine(conn, map[string]any{"err": "código de acceso incorrecto"})
			return
		}
		s.resetAccessFailures(ip)
	}
	_ = conn.SetReadDeadline(time.Time{})

	dataToken, err := generateSessionToken()
	if err != nil {
		_ = writeLine(conn, map[string]any{"err": err.Error()})
		return
	}
	sess := &serverSession{params: p, dataConns: make(chan net.Conn, p.Streams), dataToken: dataToken}
	s.mu.Lock()
	if _, exists := s.sessions[p.SessionID]; exists {
		s.mu.Unlock()
		_ = writeLine(conn, map[string]any{"err": "sessionId ya está en uso"})
		return
	}
	s.sessions[p.SessionID] = sess
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.sessions, p.SessionID)
		s.mu.Unlock()
	}()

	if p.Proto == UDP {
		s.runUDPServer(ctx, conn, sess)
		return
	}

	// TCP: acknowledge readiness, then wait for the client's data conns.
	if err := writeLine(conn, map[string]any{"ready": true, "dataToken": sess.dataToken}); err != nil {
		return
	}
	dur := time.Duration(p.DurationMs) * time.Millisecond
	deadline := time.Now().Add(dur + 2*time.Second)

	var wg sync.WaitGroup
	for i := 0; i < p.Streams; i++ {
		var dc net.Conn
		select {
		case dc = <-sess.dataConns:
		case <-time.After(time.Until(deadline)):
			// Missing data conns; proceed with what we have.
			i = p.Streams
			continue
		case <-ctx.Done():
			return
		}
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			s.runTCPStream(ctx, c, sess, dur)
		}(dc)
	}
	wg.Wait()

	// Report what the server observed so the client can build the Result.
	writeLine(conn, serverSummary{
		BytesRecv: sess.bytesRecv.Load(),
		BytesSent: sess.bytesSent.Load(),
	})
}

func (s *Server) handleData(ctx context.Context, conn net.Conn, dh dataHeader) {
	s.mu.Lock()
	sess := s.sessions[dh.SessionID]
	s.mu.Unlock()
	if sess == nil {
		conn.Close()
		return
	}
	if subtle.ConstantTimeCompare([]byte(dh.Token), []byte(sess.dataToken)) != 1 {
		conn.Close()
		return
	}
	select {
	case sess.dataConns <- conn:
	case <-time.After(3 * time.Second):
		conn.Close()
	case <-ctx.Done():
		conn.Close()
	}
}

// runTCPStream moves data on one stream in the session's direction until the
// duration elapses, accumulating byte counters on the session.
func (s *Server) runTCPStream(ctx context.Context, conn net.Conn, sess *serverSession, dur time.Duration) {
	defer conn.Close()
	buf := make([]byte, sess.params.BufferKB*1024)
	stopAt := time.Now().Add(dur)

	var wg sync.WaitGroup
	sends := sess.params.Direction == Download || sess.params.Direction == Bidir
	recvs := sess.params.Direction == Upload || sess.params.Direction == Bidir

	if sends {
		wg.Add(1)
		go func() {
			defer wg.Done()
			payload := make([]byte, sess.params.BufferKB*1024)
			for time.Now().Before(stopAt) && ctx.Err() == nil {
				conn.SetWriteDeadline(nextDeadline(ctx, stopAt))
				n, err := conn.Write(payload)
				sess.bytesSent.Add(int64(n))
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
			sess.bytesRecv.Add(int64(n))
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

// runUDPServer handles a UDP test's server side. It opens a UDP socket, learns
// the client address from the first packet, and either receives (upload) or
// sends (download) for the duration, then reports a summary over control.
func (s *Server) runUDPServer(ctx context.Context, control net.Conn, sess *serverSession) {
	pc, err := net.ListenPacket("udp", ":0")
	if err != nil {
		writeLine(control, map[string]any{"err": err.Error()})
		return
	}
	defer pc.Close()
	stopClose := make(chan struct{})
	defer close(stopClose)
	go func() {
		select {
		case <-ctx.Done():
			_ = pc.Close()
		case <-stopClose:
		}
	}()

	udpPort := pc.LocalAddr().(*net.UDPAddr).Port
	if err := writeLine(control, map[string]any{"ready": true, "udpPort": udpPort, "udpToken": sess.dataToken}); err != nil {
		return
	}

	dur := time.Duration(sess.params.DurationMs) * time.Millisecond
	p := sess.params

	// The authenticated control peer must prove knowledge of the random token
	// on UDP before its address becomes the download target.
	buf := make([]byte, 65535)
	pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	var clientAddr net.Addr
	for {
		n, candidate, readErr := pc.ReadFrom(buf)
		if readErr != nil {
			return
		}
		if packetHost(candidate) == remoteIP(control) &&
			subtle.ConstantTimeCompare(buf[:n], []byte(sess.dataToken)) == 1 {
			clientAddr = candidate
			break
		}
	}

	var wg sync.WaitGroup
	var sentPackets atomic.Int64
	if p.Direction == Upload || p.Direction == Bidir {
		wg.Add(1)
		go func() { defer wg.Done(); recvUDP(ctx, pc, clientAddr, dur, sess) }()
	}
	if p.Direction == Download || p.Direction == Bidir {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sentPackets.Store(sendUDP(ctx, pc, clientAddr, dur, p))
		}()
	}
	wg.Wait()
	stats := sess.udpSummary()

	writeLine(control, serverSummary{
		PacketsSent: sentPackets.Load(),
		PacketsRecv: stats.packetsRecv,
		HighestSeq:  stats.highestSeq,
		JitterMs:    stats.jitterMs,
	})
}

func (sess *serverSession) udpSummary() udpStats {
	sess.udpMu.Lock()
	defer sess.udpMu.Unlock()
	return sess.udp
}

// recvUDP receives datagrams for dur, tracking packet count, highest seq and
// RFC 3550 jitter. Counters are stashed on the session's atomics (reused).
func recvUDP(ctx context.Context, pc net.PacketConn, allowed net.Addr, dur time.Duration, sess *serverSession) {
	buf := make([]byte, 65535)
	stopAt := time.Now().Add(dur)
	var packets, highestSeq int64
	var jitter float64
	var prevTransit float64
	haveTransit := false

	for {
		if ctx.Err() != nil || time.Now().After(stopAt) {
			break
		}
		pc.SetReadDeadline(nextDeadline(ctx, stopAt))
		n, from, err := pc.ReadFrom(buf)
		if err == nil && from.String() != allowed.String() {
			continue
		}
		now := float64(time.Now().UnixNano()) / 1e6 // ms
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
	sess.udpMu.Lock()
	sess.udp = udpStats{packetsRecv: packets, highestSeq: highestSeq, jitterMs: jitter}
	sess.udpMu.Unlock()
}

func packetHost(addr net.Addr) string {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

func generateSessionToken() (string, error) {
	var raw [16]byte
	if _, err := cryptoRandRead(raw[:]); err != nil {
		return "", fmt.Errorf("no se pudo generar token de sesión: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

// sendUDP blasts datagrams to addr for dur at the params' target rate.
func sendUDP(ctx context.Context, pc net.PacketConn, addr net.Addr, dur time.Duration, p Params) int64 {
	pkt := make([]byte, p.UDPPacket)
	stopAt := time.Now().Add(dur)
	var seq int64
	interval := udpInterval(p)
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
			d := time.Until(next)
			if d > 0 {
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

func nextDeadline(ctx context.Context, stopAt time.Time) time.Time {
	d := time.Now().Add(250 * time.Millisecond)
	if d.After(stopAt) {
		d = stopAt
	}
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(d) {
		d = deadline
	}
	return d
}

// udpInterval converts a target Mbps + packet size into an inter-packet delay.
func udpInterval(p Params) time.Duration {
	if p.TargetMbps <= 0 {
		return 0
	}
	bitsPerPacket := float64(p.UDPPacket) * 8
	packetsPerSec := (p.TargetMbps * 1e6) / bitsPerPacket
	if packetsPerSec <= 0 {
		return 0
	}
	return time.Duration(float64(time.Second) / packetsPerSec)
}
