// tzsp-sender is TRAZIP's headless capture forwarder: it captures on a local
// interface and streams every frame, TZSP-encapsulated over UDP, to a TRAZIP
// instance listening with "Recibir TZSP" (internal/tzsp.Listen) — the same
// wire format MikroTik's /tool sniffer uses, so Wireshark can also decode it.
//
// Typical use: run this on a second machine whose traffic you want to see
// from your main TRAZIP (e.g. a mini-PC plugged into a switch's mirror/SPAN
// port), pointing -destino at the TRAZIP machine.
//
// Scope: this build captures via Npcap, so it runs on Windows; on other OS
// it exits with a clear message (internal/capture has no live capture there
// yet). Like every active TRAZIP operation, it requires the operator to
// declare authorization explicitly (-autorizado) — same rule the GUI applies
// to captures and scans.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"time"

	"trazip/internal/capture"
	"trazip/internal/tzsp"
)

func main() {
	list := flag.Bool("listar", false, "listar interfaces de captura disponibles y salir")
	device := flag.String("interfaz", "", "nombre de la interfaz de captura (ver -listar)")
	dest := flag.String("destino", "", "host:puerto del TRAZIP receptor (ej. 192.168.1.10:37008)")
	promisc := flag.Bool("promiscuo", true, "capturar en modo promiscuo")
	snaplen := flag.Int("snaplen", 65535, "bytes máximos capturados por paquete")
	authorized := flag.Bool("autorizado", false, "confirmo que administro esta red y estoy autorizado a capturar y reenviar su tráfico")
	flag.Parse()

	if *list {
		devs, err := capture.Devices()
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		for _, d := range devs {
			fmt.Printf("%s\t%s\n", d.Name, d.Description)
		}
		return
	}

	if *device == "" || *dest == "" {
		fmt.Fprintln(os.Stderr, "uso: tzsp-sender -interfaz <nombre> -destino <host:puerto> -autorizado")
		fmt.Fprintln(os.Stderr, "     tzsp-sender -listar")
		os.Exit(2)
	}
	if !*authorized {
		fmt.Fprintln(os.Stderr, "falta -autorizado: igual que en la app, toda operación activa exige declarar que la red es propia o hay autorización explícita.")
		os.Exit(2)
	}

	raddr, err := net.ResolveUDPAddr("udp", *dest)
	if err != nil {
		fmt.Fprintln(os.Stderr, "destino inválido:", err)
		os.Exit(2)
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "no se pudo abrir el socket UDP:", err)
		os.Exit(1)
	}
	defer conn.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var pkts, bytes atomic.Int64
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				fmt.Printf("enviados: %d paquetes / %d bytes → %s\n", pkts.Load(), bytes.Load(), *dest)
			}
		}
	}()

	fmt.Printf("capturando en %q y reenviando TZSP a %s (Ctrl+C para detener)\n", *device, *dest)
	err = capture.CaptureRaw(ctx, *device, *snaplen, *promisc, func(frame []byte) {
		// Best-effort UDP, igual que un sniffer de router: un datagrama
		// perdido no debe frenar la captura.
		n, _ := conn.Write(tzsp.Encode(frame))
		pkts.Add(1)
		bytes.Add(int64(n))
	})
	if err != nil && ctx.Err() == nil {
		fmt.Fprintln(os.Stderr, "captura terminada con error:", err)
		os.Exit(1)
	}
	fmt.Printf("detenido. total: %d paquetes / %d bytes\n", pkts.Load(), bytes.Load())
}
