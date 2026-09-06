package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"trazip/internal/api"
	"trazip/internal/bgp"
	"trazip/internal/capture"
	"trazip/internal/detection/netdiag"
	"trazip/internal/detection/scandetect"
	"trazip/internal/diagnosis"
	"trazip/internal/events"
	"trazip/internal/httpload"
	"trazip/internal/lan"
	"trazip/internal/monitor"
	"trazip/internal/notify"
	"trazip/internal/packet"
	"trazip/internal/paths"
	"trazip/internal/probe/mtr"
	"trazip/internal/probe/ping"
	"trazip/internal/probe/portscan"
	"trazip/internal/probe/trace"
	"trazip/internal/report"
	"trazip/internal/serviceaudit"
	"trazip/internal/session"
	"trazip/internal/systheme"
	"trazip/internal/throughput"
	"trazip/internal/tzsp"
	"trazip/internal/voip"
	"trazip/internal/voip/quality"
)

// App is the Wails application root. It owns the backend Service (domain logic
// shared with the CLI) and bridges streaming engines to the frontend via events.
type App struct {
	ctx         context.Context
	svc         *api.Service
	sessions    *session.Manager
	monitorMgr  *monitor.Manager // shared with Service (dependency injection, see NewServiceWithSessions)
	voipQualMgr *quality.Manager // shared with Service, ingested after every VoIP analysis

	throughputMu     sync.Mutex
	throughputCancel context.CancelFunc
	throughputAddr   string
	throughputCode   string
	throughputGen    uint64
}

// NewApp creates the application with its backend service.
func NewApp() *App {
	sessions := session.NewManager()
	monitorMgr := monitor.NewManager()
	voipQualMgr := quality.NewManager()
	return &App{
		svc:         api.NewServiceWithSessions(sessions, monitorMgr, voipQualMgr),
		sessions:    sessions,
		monitorMgr:  monitorMgr,
		voipQualMgr: voipQualMgr,
	}
}

// startup stores the runtime context for later use.
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	api.StartGeoAutoUpdate(a.svc, ctx)
	// The self-update engine (internal/update + cmd/trazip-updater) only
	// knows how to replace a Windows .exe — starting its background check
	// on another platform would just produce a recurring, silently
	// swallowed "no update asset published for darwin yet" error for no
	// benefit. Settings tells the user this plainly rather than staying
	// quiet about why the toggle does nothing there.
	if runtime.GOOS == "windows" {
		api.StartUpdateAutoCheck(a.svc, ctx)
	}
}

// shutdown cancels all work rooted in the desktop application.
func (a *App) shutdown(context.Context) {
	a.sessions.CancelAll()
	a.StopThroughputServer()
	a.monitorMgr.StopAll()
	a.svc.Close()
}

func (a *App) beginActive(module, target string, authorized bool) (*session.Session, error) {
	parent := a.ctx
	if parent == nil {
		parent = context.Background()
	}
	sess, err := a.sessions.BeginActive(parent, module, target, authorized)
	if err != nil {
		return nil, err
	}
	a.bridgeSession(sess)
	return sess, nil
}

func (a *App) bridgeSession(sess *session.Session) {
	ch, unsubscribe := sess.Bus.Subscribe(256, nil)
	go func() {
		defer unsubscribe()
		emit := func(e events.Event) {
			if e.Topic != "" {
				// A stable bridge topic is subscribed when the frontend module loads.
				// It buffers events until the per-session callback is registered,
				// closing the Start* -> EventsOn race for very short operations.
				wruntime.EventsEmit(a.ctx, "trazip:event", e)
				wruntime.EventsEmit(a.ctx, e.Topic+":"+sess.ID, e.Payload)
			}
		}
		for {
			select {
			case e := <-ch:
				emit(e)
				if e.Kind == events.KindDone {
					return
				}
			case <-sess.Context().Done():
				for {
					select {
					case e := <-ch:
						emit(e)
					default:
						return
					}
				}
			}
		}
	}()
}

func publish(sess *session.Session, topic string, kind events.Kind, payload any) {
	sess.Bus.Publish(events.Event{
		SessionID: sess.ID,
		Module:    sess.Label,
		Topic:     topic,
		Kind:      kind,
		Payload:   payload,
	})
}

func (a *App) stopOperation(id string) { a.sessions.Cancel(id) }

// publishResolved emite la dirección de destino antes de la primera sonda.
//
// Ping, Traceroute y MTR resuelven el objetivo de todos modos, pero solo lo
// comunicaban al terminar: con un destino que no contesta, eso deja al
// operador mirando un panel vacío durante todos los timeouts, cuando el dato
// —a qué IP se está enviando— ya se conocía. `ping` de consola imprime
// "host [ip]" de entrada por esta misma razón, y un fallo de DNS también sale
// de inmediato en vez de al final.
//
// El motor vuelve a resolver por su cuenta después; el resolver del sistema
// lo sirve de caché, así que no se alteró su contrato por ahorrar una consulta.
func publishResolved(sess *session.Session, topic, target string) {
	if addr, err := ping.Resolve(sess.Context(), target, ""); err == nil {
		publish(sess, topic, events.KindProbe, map[string]any{"addr": addr.String()})
	} else {
		publish(sess, topic, events.KindError, map[string]any{"err": err.Error()})
	}
}

// SetWindowBackground keeps the native window's background colour in sync with
// the active UI theme. The colour passed to options.App at startup is static,
// so on its own a theme switch leaves the window painting the *other* theme's
// colour underneath — WebView2 fills the window with it before the page
// content paints, which shows up as an intermittent flash on repaints and
// resizes rather than a permanent wrong colour (hence "a veces parpadea").
func (a *App) SetWindowBackground(theme string) {
	if a.ctx == nil {
		return
	}
	if theme == "light" {
		wruntime.WindowSetBackgroundColour(a.ctx, 244, 247, 251, 255) // --bg light #F4F7FB
		return
	}
	wruntime.WindowSetBackgroundColour(a.ctx, 6, 18, 37, 255) // --bg dark #061225
}

// SystemThemePreference reports Windows' own light/dark app theme —
// "dark", "light", or "" when unknown (unsupported platform, or the
// registry value couldn't be read). Never a bool: false would otherwise
// mean both "Windows is set to light" and "this platform can't say",
// which the frontend must treat differently — the second case falls back
// to matchMedia rather than asserting a preference nobody confirmed. See
// frontend/src/lib/theme.ts.
func (a *App) SystemThemePreference() string { return systheme.Preference() }

// InstallUpdate launches the external updater helper and exits TRAZIP so it
// can replace this process's own executable — Windows does not allow a
// running .exe to overwrite its own bytes. Requires a verified download
// already at update.StatusReady (see api.PrepareUpdateInstall). The
// updater binary spawned here is always the freshly downloaded and
// SHA-256-verified one from that same download — never something merely
// found on disk, since a standalone .exe install has no other helper to
// fall back on and a stale bundled copy would be exactly the kind of
// unverified binary this whole design exists to avoid running. Only the
// app-lifecycle part lives here — spawning the helper and quitting —
// since that belongs with the other Wails-runtime calls, not in the
// platform-agnostic Service facade.
func (a *App) InstallUpdate() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("no se pudo determinar la ruta del ejecutable actual: %w", err)
	}
	targetDir := filepath.Dir(exe)
	if err := checkWritableDir(targetDir); err != nil {
		return fmt.Errorf("sin permisos de escritura en %s — descargá la nueva versión manualmente desde la página de releases: %w", targetDir, err)
	}
	args, err := api.PrepareUpdateInstall(a.svc, exe, paths.Portable())
	if err != nil {
		return err
	}
	if args.UpdaterPath == "" {
		return fmt.Errorf("no hay un actualizador verificado disponible — repetí la descarga")
	}

	cmdArgs := []string{
		"-pid", strconv.Itoa(args.PID),
		"-source", args.Source,
		"-target", args.Final,
		"-expected-sha256", args.ExpectedSHA256,
		"-restart",
	}
	if args.Cleanup != "" {
		cmdArgs = append(cmdArgs, "-cleanup", args.Cleanup)
	}
	if err := exec.Command(args.UpdaterPath, cmdArgs...).Start(); err != nil {
		return fmt.Errorf("no se pudo iniciar el actualizador: %w", err)
	}
	api.MarkUpdateInstalling(a.svc)

	wruntime.Quit(a.ctx)
	return nil
}

// checkWritableDir catches a Program Files-style install (no admin rights,
// no elevation pipeline yet — see CONTEXT-trazip.md) before InstallUpdate
// ever spawns the updater, rather than letting it fail mid-replace.
func checkWritableDir(dir string) error {
	f, err := os.CreateTemp(dir, ".trazip-update-write-test-*")
	if err != nil {
		return err
	}
	name := f.Name()
	f.Close()
	return os.Remove(name)
}

// Service exposes the backend facade so main can bind it to the frontend.
func (a *App) Service() *api.Service { return a.svc }

// PickPcapFile opens a native file dialog for a capture file and returns its
// path (empty if cancelled).
func (a *App) PickPcapFile() string {
	path, err := wruntime.OpenFileDialog(a.ctx, wruntime.OpenDialogOptions{
		Title: "Abrir captura PCAP/PCAPNG",
		Filters: []wruntime.FileFilter{
			{DisplayName: "Capturas (*.pcap;*.pcapng;*.cap)", Pattern: "*.pcap;*.pcapng;*.cap"},
			{DisplayName: "Todos los archivos (*.*)", Pattern: "*.*"},
		},
	})
	if err != nil {
		return ""
	}
	return path
}

// ExportCallAudio reconstructs one RTP stream (G.711 μ-law only) to a WAV file
// the user explicitly chooses via a native save dialog — audio reconstruction
// is never automatic (prompt maestro §16). Returns the saved path, or a path
// with a trailing loss warning when packets had to be filled with silence.
func (a *App) ExportCallAudio(pcapPath string, ssrc uint32, srcHostPort string) (string, error) {
	ctx := a.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	wav, filled, err := voip.ExportStreamAudio(ctx, pcapPath, ssrc, srcHostPort)
	if err != nil {
		return "", err
	}
	savePath, err := wruntime.SaveFileDialog(a.ctx, wruntime.SaveDialogOptions{
		Title:           "Guardar audio exportado",
		DefaultFilename: fmt.Sprintf("rtp_%08x.wav", ssrc),
		Filters:         []wruntime.FileFilter{{DisplayName: "Audio WAV (*.wav)", Pattern: "*.wav"}},
	})
	if err != nil || savePath == "" {
		return "", err
	}
	if err := os.WriteFile(savePath, wav, 0o644); err != nil {
		return "", err
	}
	if filled > 0 {
		return fmt.Sprintf("%s|%d muestras rellenadas con silencio (paquetes perdidos)", savePath, filled), nil
	}
	return savePath, nil
}

// PreviewVoIPCallAudio prepara WAV en memoria únicamente tras una acción
// explícita del usuario. El data URL evita rutas Windows y funciona igual en
// el WebView de macOS cuando la fase de port llegue.
func (a *App) PreviewVoIPCallAudio(pcapPath string, call voip.Call, mode string) (string, error) {
	ctx := a.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	const maxPreviewWAVBytes = 8 * 1024 * 1024
	channels := 1
	if mode == string(voip.AudioModeStereo) {
		channels = 2
	}
	if err := voip.PreviewAllowed(call, channels, maxPreviewWAVBytes); err != nil {
		return "", fmt.Errorf("Vista previa no disponible por tamaño. Puede exportar el audio a WAV.")
	}
	result, err := voip.ReconstructCallAudio(ctx, pcapPath, call, voip.AudioMode(mode))
	if err != nil {
		return "", err
	}
	if len(result.WAV) > maxPreviewWAVBytes {
		return "", fmt.Errorf("%s: use Export WAV for audio longer than the preview limit", voip.AudioStatusResourceLimit)
	}
	return "data:audio/wav;base64," + base64.StdEncoding.EncodeToString(result.WAV), nil
}

// ExportVoIPCallAudio exporta caller, callee, conversación mono o estéreo
// con el diálogo nativo de Wails; no asume rutas ni extensiones de Windows.
func (a *App) ExportVoIPCallAudio(pcapPath string, call voip.Call, mode string) (string, error) {
	ctx := a.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	result, err := voip.ReconstructCallAudio(ctx, pcapPath, call, voip.AudioMode(mode))
	if err != nil {
		return "", err
	}
	filename := fmt.Sprintf("voip_%s.wav", mode)
	savePath, err := wruntime.SaveFileDialog(a.ctx, wruntime.SaveDialogOptions{Title: "Guardar audio VoIP", DefaultFilename: filename, Filters: []wruntime.FileFilter{{DisplayName: "Audio WAV (*.wav)", Pattern: "*.wav"}}})
	if err != nil || savePath == "" {
		return "", err
	}
	if err := os.WriteFile(savePath, result.WAV, 0o644); err != nil {
		return "", err
	}
	if result.Degraded {
		return fmt.Sprintf("%s|%d muestras rellenadas con silencio (paquetes perdidos)", savePath, result.FilledSamples), nil
	}
	return savePath, nil
}

// StartVoIPAnalysis runs the passive two-pass correlator in a cancellable
// session. It is ready for the VoIP GUI and keeps large captures off the UI
// thread. Completion is emitted as "voip:done:<id>".
func (a *App) StartVoIPAnalysis(pcapPath string) (string, error) {
	if pcapPath == "" {
		return "", fmt.Errorf("ruta vacía")
	}
	parent := a.ctx
	if parent == nil {
		parent = context.Background()
	}
	sess := a.sessions.New(parent, "voip")
	a.bridgeSession(sess)
	go func() {
		// Routes through api.RunVoIPAnalysis (which owns the shared
		// *geoip.Engine via a.svc) rather than calling voip.Analyze directly,
		// so this GUI path and Service's own AnalyzeVoIP (bound for a future
		// CLI) enrich Caller/Callee with the exact same engine and never
		// disagree about a capture. A package-level function, not a *Service
		// method — see RunVoIPAnalysis's own doc comment for why.
		result, err := api.RunVoIPAnalysis(sess.Context(), pcapPath, a.svc)
		errStr := ""
		if err != nil {
			errStr = err.Error()
		} else {
			a.voipQualMgr.IngestResult(result)
		}
		publish(sess, "voip:done", events.KindDone, map[string]any{"result": result, "err": errStr})
		a.sessions.Complete(sess.ID)
	}()
	return sess.ID, nil
}

// StopVoIPAnalysis cancels an in-flight passive capture analysis.
func (a *App) StopVoIPAnalysis(id string) { a.stopOperation(id) }

// StartDiagnose runs TRAZIP V1's correlated Diagnose 2.0 pipeline in a
// cancellable session. ModeOffline never sends anything off the host, so it
// runs like VoIP analysis — a plain session, no scope declaration; Standard
// and Full modes DO send active probes (ping/traceroute/RDAP/BGP/TLS/HTTP),
// so those route through beginActive exactly like StartPing/StartTrace,
// requiring the same explicit "authorized" confirmation from the UI before
// anything leaves the host (master plan "PRIVACIDAD": "Antes de modo
// Standard/Full: la UI debe explicar claramente que se harán consultas/
// probes"). Completion is emitted as "diagnose:done:<id>".
func (a *App) StartDiagnose(input, mode string, authorized bool) (string, error) {
	var sess *session.Session
	var err error
	if diagnosis.Mode(strings.TrimSpace(mode)) == diagnosis.ModeOffline {
		parent := a.ctx
		if parent == nil {
			parent = context.Background()
		}
		sess = a.sessions.New(parent, "diagnose")
	} else {
		sess, err = a.beginActive("diagnose", input, authorized)
		if err != nil {
			return "", err
		}
	}
	a.bridgeSession(sess)
	go func() {
		result, rerr := api.RunDiagnose(sess.Context(), input, mode, a.svc)
		errStr := ""
		if rerr != nil {
			errStr = rerr.Error()
		}
		publish(sess, "diagnose:done", events.KindDone, map[string]any{"report": result, "err": errStr})
		a.sessions.Complete(sess.ID)
	}()
	return sess.ID, nil
}

// StopDiagnose cancels an in-flight Diagnose 2.0 run.
func (a *App) StopDiagnose(id string) { a.stopOperation(id) }

// BGPRealtimeStart begins a v1.2 BGP realtime session for resource (IP or
// prefix — ASN is out of scope for v1.2 realtime, BGP_INTELLIGENCE_
// ROADMAP.md §23.2) — the explicit user-initiated action the roadmap
// requires; TRAZIP never auto-connects to RIS Live on its own. The heavy
// lifting (constructing the session, registering it so BGPRealtimeStop can
// find it again, installing the Wails event bridge at exactly the right
// point, and only then starting the supervisor) lives in
// api.BGPRealtimeStart, a package-level function rather than a *Service
// method specifically because it needs the raw *session.Session for
// bridging — see its own doc comment. This method owns exactly the one
// thing that has to live here: handing a.bridgeSession down as the
// bridge callback, so api.BGPRealtimeStart can install it (exactly once,
// never twice, never for a rejected Start) strictly BEFORE the session
// can produce its first event (v1.2 Gate 5 P1-2 closure) — the same
// pattern as every other streaming feature in this file, just sequenced
// one level down because the session itself is created one level down.
// Events publish on the stable "bgp:realtime" topic (v1.2 Gate 5 §23.8),
// scoped per-session by bridgeSession as "bgp:realtime:<SessionID>" — the
// frontend subscribes once and reads the actual event kind from the
// payload's own Type field.
func (a *App) BGPRealtimeStart(resource string) (bgp.RealtimeSessionInfo, error) {
	parent := a.ctx
	if parent == nil {
		parent = context.Background()
	}
	info, _, err := api.BGPRealtimeStart(parent, resource, a.svc, a.bridgeSession)
	if err != nil {
		return bgp.RealtimeSessionInfo{}, err
	}
	return info, nil
}

// BGPRealtimeStop cancels a running BGP realtime session by its
// backend-generated SessionID and blocks until it has fully stopped
// (bgp.RealtimeSession.Stop's deterministic join — never a fire-and-forget
// a.stopOperation cancel, which only cancels the context and returns
// immediately without waiting for the session's own goroutines to join).
func (a *App) BGPRealtimeStop(sessionID string) error {
	return api.BGPRealtimeStop(sessionID, a.svc)
}

// StartThroughput runs one cancellable TCP or UDP throughput test against a
// TRAZIP throughput server. Completion is emitted as "throughput:done:<id>".
func (a *App) StartThroughput(addr string, params throughput.Params) (string, error) {
	addr = strings.TrimSpace(addr)
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return "", fmt.Errorf("servidor inválido (usa host:puerto): %w", err)
	}
	sess, err := a.beginActive("throughput", addr, true)
	if err != nil {
		return "", err
	}
	go func() {
		result, runErr := throughput.Run(sess.Context(), addr, params)
		errStr := ""
		if runErr != nil {
			errStr = runErr.Error()
		}
		publish(sess, "throughput:done", events.KindDone, map[string]any{"result": result, "err": errStr})
		a.sessions.Complete(sess.ID)
	}()
	return sess.ID, nil
}

// StopThroughput cancels a currently running throughput measurement.
func (a *App) StopThroughput(id string) { a.stopOperation(id) }

// StartThroughputServer explicitly starts a local TRAZIP-only test server.
// The caller chooses the bind address; use 127.0.0.1 for local testing or a
// controlled LAN address when another authorized TRAZIP client must connect.
func (a *App) StartThroughputServer(bindAddr string) (string, error) {
	bindAddr = strings.TrimSpace(bindAddr)
	if bindAddr == "" {
		return "", fmt.Errorf("dirección de escucha vacía")
	}
	ln, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return "", err
	}
	parent := a.ctx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	addr := ln.Addr().String()
	code, err := throughput.GenerateAccessCode()
	if err != nil {
		cancel()
		ln.Close()
		return "", err
	}

	a.throughputMu.Lock()
	if a.throughputCancel != nil {
		a.throughputMu.Unlock()
		cancel()
		ln.Close()
		return "", fmt.Errorf("el servidor de throughput ya está activo en %s", a.throughputAddr)
	}
	a.throughputCancel = cancel
	a.throughputAddr = addr
	a.throughputCode = code
	a.throughputGen++
	gen := a.throughputGen
	a.throughputMu.Unlock()

	go func() {
		_ = throughput.NewServer(code).Serve(ctx, ln)
		a.throughputMu.Lock()
		if a.throughputGen == gen {
			a.throughputCancel = nil
			a.throughputAddr = ""
			a.throughputCode = ""
		}
		a.throughputMu.Unlock()
	}()
	return addr, nil
}

// StopThroughputServer stops the explicit local test server, if one is active.
func (a *App) StopThroughputServer() {
	a.throughputMu.Lock()
	cancel := a.throughputCancel
	a.throughputCancel = nil
	a.throughputAddr = ""
	a.throughputCode = ""
	a.throughputGen++
	a.throughputMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// ThroughputServerAddr reports the current local server address or an empty
// string when the app is not listening.
func (a *App) ThroughputServerAddr() string {
	a.throughputMu.Lock()
	defer a.throughputMu.Unlock()
	return a.throughputAddr
}

// ThroughputAccessCode reports the current server's access code (empty when
// the app is not listening) — the operator shares this out-of-band with
// whoever is going to run a client against this server.
func (a *App) ThroughputAccessCode() string {
	a.throughputMu.Lock()
	defer a.throughputMu.Unlock()
	return a.throughputCode
}

// StartHTTPLoad runs "Prueba de carga HTTP" — TRAZIP's own concurrent HTTP
// load test (own name, not a port of Apache JMeter, whose name is an Apache
// Software Foundation trademark). Progress is emitted as
// "httpload:progress:<id>"; completion as "httpload:done:<id>". Like any
// active operation that sends real traffic to a target, it goes through the
// same scope-authorization gate as Ping/Scanner/LAN — authorized must be
// true or the session is rejected before a single request is sent.
func (a *App) StartHTTPLoad(url, method string, concurrency, durationMs int, headers map[string]string, body string, targetRPS float64, authorized bool) (string, error) {
	sess, err := a.beginActive("httpload", url, authorized)
	if err != nil {
		return "", err
	}
	params := httpload.Params{
		URL:         url,
		Method:      method,
		Concurrency: concurrency,
		DurationMs:  durationMs,
		Headers:     headers,
		Body:        body,
		TargetRPS:   targetRPS,
	}
	go func() {
		result, runErr := httpload.Run(sess.Context(), params, func(t httpload.ProgressTick) {
			publish(sess, "httpload:progress", events.KindProbe, t)
		})
		errStr := ""
		if runErr != nil {
			errStr = runErr.Error()
		}
		publish(sess, "httpload:done", events.KindDone, map[string]any{"result": result, "err": errStr})
		a.sessions.Complete(sess.ID)
	}()
	return sess.ID, nil
}

// StopHTTPLoad cancels a running load test by id.
func (a *App) StopHTTPLoad(id string) { a.stopOperation(id) }

// StartPing launches a streaming ping. Replies and running stats are emitted as
// Wails events "ping:reply:<id>"; completion is emitted as "ping:done:<id>".
// It returns the run id used to subscribe and to stop the run.
func (a *App) StartPing(target string, count, intervalMs, timeoutMs, payload int, authorized bool) (string, error) {
	sess, err := a.beginActive("ping", target, authorized)
	if err != nil {
		return "", err
	}

	go func() {
		publishResolved(sess, "ping:resolved", target)

		cfg := ping.Config{
			Target:      target,
			Count:       count,
			Interval:    time.Duration(intervalMs) * time.Millisecond,
			Timeout:     time.Duration(timeoutMs) * time.Millisecond,
			PayloadSize: payload,
		}
		_, addr, err := ping.Run(sess.Context(), cfg, func(r ping.Reply, snap ping.Snapshot) {
			publish(sess, "ping:reply", events.KindProbe, map[string]any{"reply": r, "stats": snap})
		})

		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		publish(sess, "ping:done", events.KindDone, map[string]any{"addr": addr.String(), "err": errStr})
		a.sessions.Complete(sess.ID)
	}()

	return sess.ID, nil
}

// StopPing cancels a running ping by id.
func (a *App) StopPing(id string) {
	a.stopOperation(id)
}

// StartTrace launches a streaming traceroute. Hops are emitted as
// "trace:hop:<id>"; completion as "trace:done:<id>". Returns the run id.
func (a *App) StartTrace(target string, maxHops, probes, timeoutMs int, resolveDNS, authorized bool) (string, error) {
	sess, err := a.beginActive("trace", target, authorized)
	if err != nil {
		return "", err
	}

	go func() {
		// Mismo criterio que Ping: la IP de destino se conoce antes de la
		// primera sonda y es útil aunque después no conteste nada.
		publishResolved(sess, "trace:resolved", target)

		cfg := trace.Config{
			Target:     target,
			MaxHops:    maxHops,
			Probes:     probes,
			Timeout:    time.Duration(timeoutMs) * time.Millisecond,
			ResolveDNS: resolveDNS,
		}
		_, addr, err := trace.Run(sess.Context(), cfg, func(h trace.Hop) {
			if h.Addr != "" {
				g := a.svc.GeoLookup(h.Addr)
				h.Country, h.CountryCode, h.ASN, h.Org = g.Country, g.CountryCode, g.ASN, g.Org
				h.City, h.Region = g.City, g.Region
				h.Lat, h.Lon = g.Lat, g.Lon
			}
			publish(sess, "trace:hop", events.KindProbe, h)
		})

		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		publish(sess, "trace:done", events.KindDone, map[string]any{"addr": addr.String(), "err": errStr})
		a.sessions.Complete(sess.ID)
	}()

	return sess.ID, nil
}

// StopTrace cancels a running traceroute by id.
func (a *App) StopTrace(id string) {
	a.stopOperation(id)
}

// StartMTR launches a continuous per-hop MTR. Each round emits the full hop table
// as "mtr:update:<id>"; completion as "mtr:done:<id>". Returns the run id.
func (a *App) StartMTR(target string, maxHops, timeoutMs, roundMs int, resolveDNS, authorized bool) (string, error) {
	sess, err := a.beginActive("mtr", target, authorized)
	if err != nil {
		return "", err
	}

	go func() {
		publishResolved(sess, "mtr:resolved", target)

		cfg := mtr.Config{
			Target:        target,
			MaxHops:       maxHops,
			Timeout:       time.Duration(timeoutMs) * time.Millisecond,
			RoundInterval: time.Duration(roundMs) * time.Millisecond,
			ResolveDNS:    resolveDNS,
		}
		addr, err := mtr.Run(sess.Context(), cfg, func(hops []mtr.HopStat) {
			for i := range hops {
				if hops[i].Addr == "" {
					continue
				}
				g := a.svc.GeoLookup(hops[i].Addr)
				hops[i].Country, hops[i].CountryCode, hops[i].ASN, hops[i].Org = g.Country, g.CountryCode, g.ASN, g.Org
				hops[i].City, hops[i].Region = g.City, g.Region
				hops[i].Lat, hops[i].Lon = g.Lat, g.Lon
			}
			publish(sess, "mtr:update", events.KindProbe, hops)
		})

		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		publish(sess, "mtr:done", events.KindDone, map[string]any{"addr": addr.String(), "err": errStr})
		a.sessions.Complete(sess.ID)
	}()

	return sess.ID, nil
}

// StopMTR cancels a running MTR by id.
func (a *App) StopMTR(id string) {
	a.stopOperation(id)
}

// StartScan preserves the original binding with conservative defaults. New GUI
// callers use StartScanAdvanced to make every operational limit explicit.
func (a *App) StartScan(target, preset string, lo, hi int, authorized bool) (string, error) {
	return a.StartScanAdvanced(target, preset, lo, hi, 250, 128, 1500, authorized)
}

// StartScanAdvanced launches an unprivileged TCP connect scan with explicit,
// bounded dispatch rate, concurrency and connection timeout.
func (a *App) StartScanAdvanced(target, preset string, lo, hi, ratePerSec, concurrency, timeoutMs int, authorized bool) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", fmt.Errorf("objetivo vacío")
	}
	if ratePerSec < 1 || ratePerSec > 5000 {
		return "", fmt.Errorf("velocidad fuera de rango: use entre 1 y 5000 puertos/s")
	}
	if concurrency < 1 || concurrency > 512 {
		return "", fmt.Errorf("concurrencia fuera de rango: use entre 1 y 512")
	}
	if timeoutMs < 100 || timeoutMs > 10000 {
		return "", fmt.Errorf("timeout fuera de rango: use entre 100 y 10000 ms")
	}

	var ports []int
	switch preset {
	case "quick":
		ports = portscan.Quick()
	case "top100":
		ports = portscan.Top100()
	case "extended":
		ports = portscan.Extended()
	case "range":
		ports = portscan.ParseRange(lo, hi)
	default:
		return "", fmt.Errorf("perfil de escaneo no reconocido: %s", preset)
	}
	if len(ports) == 0 {
		return "", fmt.Errorf("rango de puertos inválido")
	}

	sess, err := a.beginActive("scan", target, authorized)
	if err != nil {
		return "", err
	}
	total := len(ports)

	go func() {
		var scanned int32
		sum, addr, err := portscan.Run(sess.Context(), portscan.Config{
			Target: target, Ports: ports, RatePerSec: ratePerSec, Concurrency: concurrency,
			Timeout: time.Duration(timeoutMs) * time.Millisecond,
		}, func(r portscan.PortResult) {
			n := atomic.AddInt32(&scanned, 1)
			publish(sess, "scan:result", events.KindProbe, map[string]any{"result": r, "scanned": n, "total": total})
		})

		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		publish(sess, "scan:done", events.KindDone, map[string]any{"summary": sum, "addr": addr.String(), "err": errStr})
		a.sessions.Complete(sess.ID)
	}()

	return sess.ID, nil
}

// StopScan cancels a running scan by id.
func (a *App) StopScan(id string) {
	a.stopOperation(id)
}

// ServiceAudit performs one protocol-safe, scope-guarded validation against a
// discovered service. It sends no credentials, exploits or brute-force data.
func (a *App) ServiceAudit(target string, port int, authorized bool) (serviceaudit.Result, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return serviceaudit.Result{}, fmt.Errorf("objetivo vacío")
	}
	if port < 1 || port > 65535 {
		return serviceaudit.Result{}, fmt.Errorf("puerto inválido")
	}
	sess, err := a.beginActive("service-audit", strings.TrimSpace(target), authorized)
	if err != nil {
		return serviceaudit.Result{}, err
	}
	defer a.sessions.Complete(sess.ID)
	return serviceaudit.Audit(sess.Context(), strings.TrimSpace(target), port), nil
}

// StartLanScan launches an active LAN discovery over a CIDR or IP range
// (unlike Service.LanDiscover, which only reads the system's existing
// ARP/NDP table). The caller must confirm authorization for the target
// range (scope guard, prompt maestro §3). Emits "lanscan:progress:<id>" per
// probed address and "lanscan:host:<id>" per host that replied, then
// "lanscan:done:<id>" with the summary. Returns the run id.
func (a *App) StartLanScan(rangeSpec, iface string, authorized bool) (string, error) {
	sess, err := a.beginActive("lanscan", rangeSpec, authorized)
	if err != nil {
		return "", err
	}

	go func() {
		sum, err := lan.Scan(sess.Context(), rangeSpec, iface,
			func(h lan.HostResult) {
				// internal/lan resuelve el fabricante con su tabla integrada de
				// 24 prefijos, así que sin esto casi todo host sale como
				// "desconocido" aunque los registros del IEEE estén instalados.
				if v := a.svc.MACVendor(h.MAC); v != "" {
					h.Vendor = v
				}
				publish(sess, "lanscan:host", events.KindProbe, h)
			},
			func(scanned, total int) {
				publish(sess, "lanscan:progress", events.KindProbe, map[string]any{"scanned": scanned, "total": total})
			},
		)
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		publish(sess, "lanscan:done", events.KindDone, map[string]any{"summary": sum, "err": errStr})
		a.sessions.Complete(sess.ID)
	}()

	return sess.ID, nil
}

// StopLanScan cancels a running LAN scan by id.
func (a *App) StopLanScan(id string) {
	a.stopOperation(id)
}

// StartConnMon begins polling this machine's own active TCP/UDP sockets
// (module "Conexiones") every intervalMs, emitting "connmon:snapshot:<id>"
// per tick and "connmon:done:<id>" on stop/error. Unlike Scanner/LAN
// Scan/Capture this sends nothing to anyone — it only reads OS socket
// tables — so "local" is a fixed, self-referential Scope Guard target: there
// is no remote scope to declare, the session ceremony stays uniform with
// every other cancellable run instead of special-casing passive ones.
func (a *App) StartConnMon(intervalMs int, authorized bool) (string, error) {
	if intervalMs < 500 {
		intervalMs = 500
	} else if intervalMs > 60000 {
		intervalMs = 60000
	}
	sess, err := a.beginActive("connmon", "local", authorized)
	if err != nil {
		return "", err
	}
	go a.runConnMon(sess, time.Duration(intervalMs)*time.Millisecond)
	return sess.ID, nil
}

// StopConnMon stops a running connection monitor by id.
func (a *App) StopConnMon(id string) {
	a.stopOperation(id)
}

func (a *App) runConnMon(sess *session.Session, interval time.Duration) {
	tick := func() bool {
		snap, err := a.svc.ConnMonSnapshot()
		if err != nil {
			publish(sess, "connmon:done", events.KindDone, map[string]any{"err": err.Error()})
			a.sessions.Complete(sess.ID)
			return false
		}
		publish(sess, "connmon:snapshot", events.KindProbe, snap)
		return true
	}
	if !tick() {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-sess.Context().Done():
			publish(sess, "connmon:done", events.KindDone, map[string]any{"err": ""})
			a.sessions.Complete(sess.ID)
			return
		case <-t.C:
			if !tick() {
				return
			}
		}
	}
}

// StartCapture begins live capture on a device, emitting batched packet summaries
// as "capture:batch:<id>" (~4/s) with a running proto breakdown, and
// "capture:done:<id>" on stop/error. Returns the run id. monitorMode requests
// raw 802.11 capture instead of the OS's Ethernet-translated view — it fails
// clearly (in the "capture:done" error) when the adapter/driver doesn't
// support it, rather than silently capturing something else.
func (a *App) StartCapture(device string, promisc, monitorMode, authorized bool) (string, error) {
	sess, err := a.beginActive("capture", device, authorized)
	if err != nil {
		return "", err
	}
	go a.runBatchedCapture(sess, func(ctx context.Context, onPacket func(packet.Summary)) error {
		return capture.Capture(ctx, device, 65535, promisc, monitorMode, onPacket)
	})
	return sess.ID, nil
}

// StartTZSPCapture listens for TZSP-encapsulated packets on bindAddr (UDP
// "host:port") — e.g. a MikroTik RouterOS "/tool sniffer" with
// streaming-server pointed at this machine — decoding them through the exact
// same pipeline as local Npcap capture. This is how Live Capture sees
// traffic beyond its own NIC: the operator's own router, which every packet
// on the segment already passes through, exports a copy — same events
// ("capture:batch:<id>" / "capture:done:<id>") as StartCapture, so the
// frontend treats both sources identically.
func (a *App) StartTZSPCapture(bindAddr string, authorized bool) (string, error) {
	sess, err := a.beginActive("capture", bindAddr, authorized)
	if err != nil {
		return "", err
	}
	go a.runBatchedCapture(sess, func(ctx context.Context, onPacket func(packet.Summary)) error {
		return tzsp.Listen(ctx, bindAddr, onPacket)
	})
	return sess.ID, nil
}

// runBatchedCapture wraps any packet source (Npcap live capture, TZSP
// receiver) in the same batch/flush/event contract, so Live Capture's
// frontend is source-agnostic — same table, same Flow correlation, same
// App/WS detection regardless of where the packets came from.
func (a *App) runBatchedCapture(sess *session.Session, capture func(ctx context.Context, onPacket func(packet.Summary)) error) {
	var mu sync.Mutex
	var batch []packet.Summary
	total := 0
	protos := map[string]int{}
	detector := scandetect.New()
	l2 := netdiag.New()

	flush := func() {
		mu.Lock()
		b := batch
		batch = nil
		tot := total
		pc := make(map[string]int, len(protos))
		for k, v := range protos {
			pc[k] = v
		}
		detections := detector.Result()
		l2res := l2.Result()
		mu.Unlock()
		// El enriquecimiento resuelve una MAC por hallazgo y por vecino contra
		// los registros del IEEE: fuera del mutex, porque mientras se sostiene
		// no entra ningún paquete a la captura.
		l2res = a.svc.EnrichNetDiag(l2res)
		publish(sess, "capture:batch", events.KindPacket, map[string]any{
			"packets": b, "total": tot, "protos": pc, "scanDetection": detections, "netDiag": l2res,
		})
	}

	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(250 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-sess.Context().Done():
				return
			case <-stop:
				return
			case <-t.C:
				flush()
			}
		}
	}()

	err := capture(sess.Context(), func(s packet.Summary) {
		mu.Lock()
		if len(batch) < 400 { // cap payload per flush
			batch = append(batch, s)
		}
		total++
		protos[s.Proto]++
		detector.Add(s)
		l2.Add(s)
		mu.Unlock()
	})
	close(stop)
	flush()

	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	publish(sess, "capture:done", events.KindDone, map[string]any{"err": errStr})
	a.sessions.Complete(sess.ID)
}

// StopCapture stops a running capture by id (works for both StartCapture and
// StartTZSPCapture sessions — both are plain cancellable sessions).
func (a *App) StopCapture(id string) {
	a.stopOperation(id)
}

// MonitorStart begins continuous Ping/MTR probing for an already-registered
// target (prompt maestro §9 Fase 5, módulo 25; see Service.MonitorAddTarget),
// streaming each sample as "monitor:sample:<id>" and each degradation event
// as "monitor:event:<id>" until MonitorStop is called or the app shuts down.
// Keyed by the target's own ID rather than a fresh run ID: a target either
// has one monitor running or none, so there is no separate "session" concept
// the way Ping/Trace/MTR use for ephemeral one-off runs.
func (a *App) MonitorStart(id string) error {
	ctx := a.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	// Resolve the target's label once so toasts can name it — the event
	// itself only carries kind/detail.
	label := id
	for _, t := range a.monitorMgr.ListTargets() {
		if t.ID == id {
			if t.Label != "" {
				label = t.Label
			} else if t.Address != "" {
				label = t.Address
			}
			break
		}
	}
	return a.monitorMgr.Start(ctx, id,
		func(s monitor.Sample) { wruntime.EventsEmit(a.ctx, "monitor:sample:"+id, s) },
		func(e monitor.DegradationEvent) {
			wruntime.EventsEmit(a.ctx, "monitor:event:"+id, e)
			// Native toast so degradation/route changes are visible with
			// TRAZIP minimized. Best-effort: a toast failure must never
			// affect the monitor.
			title := "TRAZIP · degradación en " + label
			switch e.Kind {
			case "recovery":
				title = "TRAZIP · " + label + " recuperado"
			case "route_change":
				title = "TRAZIP · cambio de ruta en " + label
			}
			_ = notify.Send(title, e.Detail)
		},
	)
}

// MonitorStop stops a running monitor for id. Idempotent.
func (a *App) MonitorStop(id string) {
	a.monitorMgr.Stop(id)
}

// MonitorExportReport builds a módulo-26 report from a monitor target's
// history and saves it in the requested format via a native save dialog —
// export is always an explicit, user-initiated action, never automatic.
// format is one of "json" | "csv" | "html" | "pdf".
func (a *App) MonitorExportReport(id, format string, sinceMs, windowMs int64) (string, error) {
	rep, err := a.svc.MonitorReport(id, sinceMs, windowMs)
	if err != nil {
		return "", err
	}
	idPrefix := id
	if len(idPrefix) > 8 {
		idPrefix = idPrefix[:8]
	}
	return a.saveReportDialog(rep, format, "trazip-monitor-"+idPrefix)
}

// LabExportReport builds a módulo-26/27 report from a lab scenario's most
// recent run and saves it in the requested format via a native save dialog
// — "exportación de evidencia para cursos."
func (a *App) LabExportReport(scenarioID, format string) (string, error) {
	rep, err := a.svc.LabReport(scenarioID)
	if err != nil {
		return "", err
	}
	return a.saveReportDialog(rep, format, "trazip-lab-"+scenarioID)
}

// InvestigationExportReport builds a módulo-26 report from a full
// investigation case and saves it in the requested format via a native
// save dialog (Phase E: "El usuario elige destino").
func (a *App) InvestigationExportReport(id, format string) (string, error) {
	rep, err := a.svc.InvestigationReport(id)
	if err != nil {
		return "", err
	}
	idPrefix := id
	if len(idPrefix) > 8 {
		idPrefix = idPrefix[:8]
	}
	return a.saveReportDialog(rep, format, "trazip-investigation-"+idPrefix)
}

// ExportSessionReport saves a report the frontend composed from the current
// session's in-memory results (PCAP, VoIP, LAN...). Those results live in
// the UI session, not in the backend, so the UI owns the composition and
// this binding only completes provenance metadata, renders and saves it.
func (a *App) ExportSessionReport(rep report.Report, format string) (string, error) {
	if rep.Title == "" {
		rep.Title = "Informe de sesión TRAZIP"
	}
	if rep.Meta.GeneratedAt == "" {
		rep.Meta.GeneratedAt = time.Now().Format(time.RFC3339)
	}
	if rep.Meta.TrazipVersion == "" {
		rep.Meta.TrazipVersion = api.Version
	}
	return a.saveReportDialog(rep, format, "trazip-informe-sesion")
}

// saveReportDialog renders rep in the requested format and prompts the user
// for a save location — shared by every module-26 export entry point so
// the format switch and dialog wiring exist exactly once.
func (a *App) saveReportDialog(rep report.Report, format, defaultBasename string) (string, error) {
	var body []byte
	var ext, display string
	var err error
	switch format {
	case "json":
		body, err = rep.ToJSON()
		ext, display = "json", "JSON (*.json)"
	case "csv":
		body, ext, display = rep.ToCSV(), "csv", "CSV (*.csv)"
	case "html":
		body, ext, display = rep.ToHTML(), "html", "HTML (*.html)"
	case "pdf":
		body, ext, display = rep.ToPDF(), "pdf", "PDF (*.pdf)"
	default:
		return "", fmt.Errorf("formato de reporte no soportado: %q", format)
	}
	if err != nil {
		return "", err
	}

	savePath, err := wruntime.SaveFileDialog(a.ctx, wruntime.SaveDialogOptions{
		Title:           "Guardar reporte",
		DefaultFilename: fmt.Sprintf("%s.%s", defaultBasename, ext),
		Filters:         []wruntime.FileFilter{{DisplayName: display, Pattern: "*." + ext}},
	})
	if err != nil || savePath == "" {
		return "", err
	}
	if err := os.WriteFile(savePath, body, 0o644); err != nil {
		return "", err
	}
	return savePath, nil
}
