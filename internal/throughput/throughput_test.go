package throughput

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

// startServer boots a throughput server on an ephemeral port and returns its
// address, cancelling on test cleanup. Fully in-process over loopback.
func startServer(t *testing.T) string {
	t.Helper()
	return startServerWithCode(t, "")
}

// startServerWithCode is startServer but the server requires accessCode on
// every control handshake (see GenerateAccessCode) — pass "" for the same
// behavior as startServer.
func startServerWithCode(t *testing.T, accessCode string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv := NewServer(accessCode)
	go func() { _ = srv.Serve(ctx, ln) }()
	deadline := time.Now().Add(time.Second)
	for {
		conn, dialErr := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if dialErr == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("servidor no inició: %v", dialErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return addr
}

func TestTCPDownload(t *testing.T) {
	addr := startServer(t)
	res, err := Run(context.Background(), addr, Params{
		Proto: TCP, Direction: Download, DurationMs: 400, Streams: 2, BufferKB: 64,
	})
	if err != nil {
		t.Fatalf("Run: %v (%s)", err, res.Err)
	}
	if res.DownStream == nil || res.DownStream.Bytes == 0 {
		t.Fatalf("expected downstream bytes > 0, got %+v", res.DownStream)
	}
	if res.DownStream.Mbps <= 0 {
		t.Errorf("expected positive Mbps, got %f", res.DownStream.Mbps)
	}
	if res.UpStream != nil {
		t.Errorf("download test should not report upstream: %+v", res.UpStream)
	}
}

func TestTCPUpload(t *testing.T) {
	addr := startServer(t)
	res, err := Run(context.Background(), addr, Params{
		Proto: TCP, Direction: Upload, DurationMs: 400, Streams: 1, BufferKB: 64,
	})
	if err != nil {
		t.Fatalf("Run: %v (%s)", err, res.Err)
	}
	if res.UpStream == nil || res.UpStream.Bytes == 0 {
		t.Fatalf("expected upstream bytes > 0 (server-measured), got %+v", res.UpStream)
	}
}

func TestTCPBidir(t *testing.T) {
	addr := startServer(t)
	res, err := Run(context.Background(), addr, Params{
		Proto: TCP, Direction: Bidir, DurationMs: 400, Streams: 2, BufferKB: 64,
	})
	if err != nil {
		t.Fatalf("Run: %v (%s)", err, res.Err)
	}
	if res.DownStream == nil || res.DownStream.Bytes == 0 {
		t.Errorf("bidir should report downstream bytes, got %+v", res.DownStream)
	}
	if res.UpStream == nil || res.UpStream.Bytes == 0 {
		t.Errorf("bidir should report upstream bytes, got %+v", res.UpStream)
	}
}

func TestUDPUpload(t *testing.T) {
	addr := startServer(t)
	res, err := Run(context.Background(), addr, Params{
		Proto: UDP, Direction: Upload, DurationMs: 400, UDPPacket: 1000, TargetMbps: 20,
	})
	if err != nil {
		t.Fatalf("Run: %v (%s)", err, res.Err)
	}
	if res.UpStream == nil {
		t.Fatalf("expected upstream result for UDP upload")
	}
	if res.UpStream.PacketsRecv == 0 {
		t.Errorf("expected server to receive UDP packets, got %+v", res.UpStream)
	}
	if res.UpStream.LossPct < 0 || res.UpStream.LossPct > 100 {
		t.Errorf("loss pct out of range: %f", res.UpStream.LossPct)
	}
}

func TestUDPDownload(t *testing.T) {
	addr := startServer(t)
	res, err := Run(context.Background(), addr, Params{
		Proto: UDP, Direction: Download, DurationMs: 400, UDPPacket: 1000, TargetMbps: 20,
	})
	if err != nil {
		t.Fatalf("Run: %v (%s)", err, res.Err)
	}
	if res.DownStream == nil || res.DownStream.PacketsRecv == 0 {
		t.Fatalf("expected client to receive UDP packets on download, got %+v", res.DownStream)
	}
}

func TestUDPBidir(t *testing.T) {
	addr := startServer(t)
	res, err := Run(context.Background(), addr, Params{
		Proto: UDP, Direction: Bidir, DurationMs: 500, UDPPacket: 1000, TargetMbps: 20,
	})
	if err != nil {
		t.Fatalf("Run: %v (%s)", err, res.Err)
	}
	if res.UpStream == nil || res.UpStream.PacketsRecv == 0 {
		t.Fatalf("bidir debe recibir upload en el servidor: %+v", res.UpStream)
	}
	if res.DownStream == nil || res.DownStream.PacketsRecv == 0 {
		t.Fatalf("bidir debe recibir download en el cliente: %+v", res.DownStream)
	}
	if res.UpStream.DurationSec > 1.2 || res.DownStream.DurationSec > 1.2 {
		t.Fatalf("bidir no fue simultáneo: up=%fs down=%fs", res.UpStream.DurationSec, res.DownStream.DurationSec)
	}
}

func TestConnectionRefused(t *testing.T) {
	// Nothing listening on this port.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	_, err := Run(context.Background(), addr, Params{Proto: TCP, Direction: Download, DurationMs: 200})
	if err == nil {
		t.Error("expected an error connecting to a closed port")
	}
}

func TestRunHonorsCancellation(t *testing.T) {
	addr := startServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		time.Sleep(150 * time.Millisecond)
		cancel()
	}()
	started := time.Now()
	_, err := Run(ctx, addr, Params{Proto: TCP, Direction: Download, DurationMs: 5000})
	if err == nil {
		t.Fatal("Run debe devolver context cancellation")
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("cancelación tardó demasiado: %v", elapsed)
	}
}

func TestInvalidParamsAreRejectedBeforeDial(t *testing.T) {
	_, err := Run(context.Background(), "127.0.0.1:1", Params{Proto: "bogus", DurationMs: 400})
	if err == nil {
		t.Fatal("se esperaba rechazo de protocolo inválido")
	}
	_, err = Run(context.Background(), "127.0.0.1:1", Params{Proto: UDP, Direction: Download, DurationMs: 400, UDPPacket: 70000})
	if err == nil {
		t.Fatal("se esperaba rechazo de paquete UDP demasiado grande")
	}
}

func TestServerRejectsInvalidHandshake(t *testing.T) {
	addr := startServer(t)
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := writeLine(conn, Params{SessionID: "invalid", Proto: "bad", Direction: Download, DurationMs: 400}); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	var reply map[string]any
	if err := readLine(bufio.NewReader(conn), &reply); err != nil {
		t.Fatal(err)
	}
	if msg, _ := reply["err"].(string); msg == "" {
		t.Fatalf("se esperaba error de handshake, got %#v", reply)
	}
}

func TestAccessCodeRejectsWrongCode(t *testing.T) {
	addr := startServerWithCode(t, "123456")
	res, err := Run(context.Background(), addr, Params{
		Proto: TCP, Direction: Download, DurationMs: 200, Streams: 1, BufferKB: 64,
		AccessCode: "000000",
	})
	if err == nil && res.Err == "" {
		t.Fatal("expected the wrong access code to be rejected")
	}
	if res.DownStream != nil {
		t.Errorf("no data should have flowed with a rejected handshake, got %+v", res.DownStream)
	}
}

func TestAccessCodeAcceptsCorrectCode(t *testing.T) {
	addr := startServerWithCode(t, "123456")
	res, err := Run(context.Background(), addr, Params{
		Proto: TCP, Direction: Download, DurationMs: 200, Streams: 1, BufferKB: 64,
		AccessCode: "123456",
	})
	if err != nil {
		t.Fatalf("Run: %v (%s)", err, res.Err)
	}
	if res.DownStream == nil || res.DownStream.Bytes == 0 {
		t.Fatalf("expected downstream bytes with the correct access code, got %+v", res.DownStream)
	}
	if res.Params.AccessCode != "" {
		t.Fatal("result must not echo the access code back to the UI or reports")
	}
}

func TestAccessCodeRateLimitBlocksAfterFailures(t *testing.T) {
	addr := startServerWithCode(t, "123456")
	for i := 0; i < maxAccessFailures; i++ {
		res, err := Run(context.Background(), addr, Params{
			Proto: TCP, Direction: Download, DurationMs: 100, Streams: 1, BufferKB: 64,
			AccessCode: "000000",
		})
		if err == nil && res.Err == "" {
			t.Fatalf("attempt %d: expected wrong code to be rejected", i)
		}
	}
	// maxAccessFailures reached: even the correct code must now be rejected
	// while the lockout is in effect.
	res, err := Run(context.Background(), addr, Params{
		Proto: TCP, Direction: Download, DurationMs: 100, Streams: 1, BufferKB: 64,
		AccessCode: "123456",
	})
	if err == nil && res.Err == "" {
		t.Fatal("expected the correct code to be rejected while rate-limited")
	}
	if res.DownStream != nil {
		t.Errorf("no data should flow while rate-limited, got %+v", res.DownStream)
	}
}

func TestGenerateAccessCodeIsSixDigits(t *testing.T) {
	for i := 0; i < 20; i++ {
		code, err := GenerateAccessCode()
		if err != nil {
			t.Fatal(err)
		}
		if len(code) != 6 {
			t.Fatalf("GenerateAccessCode() = %q, want 6 digits", code)
		}
		for _, c := range code {
			if c < '0' || c > '9' {
				t.Fatalf("GenerateAccessCode() = %q, want only digits", code)
			}
		}
	}
}

func TestGenerateAccessCodeFailsClosed(t *testing.T) {
	original := cryptoRandRead
	cryptoRandRead = func([]byte) (int, error) { return 0, errors.New("entropy unavailable") }
	t.Cleanup(func() { cryptoRandRead = original })
	if code, err := GenerateAccessCode(); err == nil || code != "" {
		t.Fatalf("GenerateAccessCode() = %q, %v; want empty code and error", code, err)
	}
}

func TestUDPIntervalRate(t *testing.T) {
	// 10 Mbps at 1250-byte packets = 1000 pkt/s = 1ms interval.
	iv := udpInterval(Params{TargetMbps: 10, UDPPacket: 1250})
	if iv < 900*time.Microsecond || iv > 1100*time.Microsecond {
		t.Errorf("interval = %v, want ~1ms", iv)
	}
	if udpInterval(Params{TargetMbps: 0, UDPPacket: 1250}) != 0 {
		t.Error("unthrottled (0 Mbps) should yield 0 interval")
	}
}

func TestDataStreamRejectsWrongSessionToken(t *testing.T) {
	s := NewServer("")
	sess := &serverSession{dataToken: "correct", dataConns: make(chan net.Conn, 1)}
	s.sessions["session"] = sess
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()
	s.handleData(context.Background(), serverSide, dataHeader{SessionID: "session", Token: "wrong"})
	if len(sess.dataConns) != 0 {
		t.Fatal("a stream with the wrong token consumed a data slot")
	}
}

func TestUDPDownloadIgnoresRogueHello(t *testing.T) {
	addr := startServer(t)
	control, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	p := Params{SessionID: "udp-token-test", Proto: UDP, Direction: Download, DurationMs: 250, UDPPacket: 1000, TargetMbps: 1}
	if err := writeLine(control, p); err != nil {
		t.Fatal(err)
	}
	var ready map[string]any
	if err := readLine(bufio.NewReader(control), &ready); err != nil {
		t.Fatal(err)
	}
	port := int(ready["udpPort"].(float64))
	token := ready["udpToken"].(string)
	host, _, _ := net.SplitHostPort(addr)
	serverAddr, _ := net.ResolveUDPAddr("udp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	rogue, _ := net.ListenUDP("udp", nil)
	defer rogue.Close()
	legit, _ := net.ListenUDP("udp", nil)
	defer legit.Close()
	if _, err := rogue.WriteToUDP([]byte("wrong-token"), serverAddr); err != nil {
		t.Fatal(err)
	}
	if _, err := legit.WriteToUDP([]byte(token), serverAddr); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	_ = legit.SetReadDeadline(time.Now().Add(time.Second))
	if n, _, err := legit.ReadFromUDP(buf); err != nil || n == 0 {
		t.Fatalf("authenticated UDP peer received no download: n=%d err=%v", n, err)
	}
	_ = rogue.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if n, _, err := rogue.ReadFromUDP(buf); err == nil || n != 0 {
		t.Fatalf("rogue UDP peer received reflected traffic: n=%d err=%v", n, err)
	}
}
