package main

import (
	"context"
	"testing"
	"time"

	"trazip/internal/detection/netdiag"
	"trazip/internal/detection/scandetect"
	"trazip/internal/events"
	"trazip/internal/packet"
)

// Este archivo prueba el *cableado* de la captura, no los detectores.
//
// Existe por un fallo real que llegó a publicarse en v0.6.5:
// runBatchedCapture creaba el detector de capa 2 y publicaba su resultado,
// pero nunca le pasaba los paquetes. Salud de red salía siempre vacía en
// Live Capture y en TZSP.
//
// Ninguna de las cuatro puertas de verificación lo señaló. Compila porque
// crear el detector y publicar su resultado son dos sentencias válidas por
// separado, y `go test ./...` pasaba porque los tests de netdiag prueban el
// detector alimentándolo a mano — justo lo que la cañería no hacía.
//
// La prueba que faltaba es esta: ejecutar la función real con una fuente de
// paquetes sintética y comprobar que *cada* detector conectado recibió datos.

// fakeSource devuelve una fuente de captura que no toca la red: emite n copias
// de s y termina, con la misma firma que capture.Capture y tzsp.Listen.
func fakeSource(n int, s packet.Summary) func(context.Context, func(packet.Summary)) error {
	return func(ctx context.Context, onPacket func(packet.Summary)) error {
		for i := 0; i < n; i++ {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			s.Index = i
			onPacket(s)
		}
		return nil
	}
}

// wiringProbe es una trama que dispara a los dos detectores a la vez: es un
// SYN inicial (lo único que cuenta scandetect) y trae capa 2 con destino de
// difusión (lo que netdiag necesita). Así un solo paquete ejercita ambas
// cañerías y el fallo de cualquiera de las dos deja su contador en cero.
func wiringProbe() packet.Summary {
	return packet.Summary{
		TimeUnix:  1000,
		Src:       "192.168.1.50",
		Dst:       "192.168.1.99",
		SrcMAC:    "74:4d:28:88:d9:a3",
		DstMAC:    "ff:ff:ff:ff:ff:ff",
		EtherType: "IPv4",
		IPID:      4242,
		Length:    120,
		Proto:     "TCP",
		Transport: "tcp",
		DstPort:   445,
		TCPFlags:  []string{"SYN"},
	}
}

// runCaptureForTest ejecuta runBatchedCapture con una fuente sintética y
// devuelve el último lote publicado antes de capture:done.
func runCaptureForTest(t *testing.T, packets int) map[string]any {
	t.Helper()

	app := NewApp()
	defer app.svc.Close()

	sess := app.sessions.New(context.Background(), "capture-wiring")
	// Se consume el bus directamente en vez de bridgeSession, que necesitaría
	// el runtime de Wails; publish() escribe en el bus igual en ambos casos.
	ch, unsubscribe := sess.Bus.Subscribe(256, nil)
	defer unsubscribe()

	go app.runBatchedCapture(sess, fakeSource(packets, wiringProbe()))

	var lastBatch map[string]any
	deadline := time.After(10 * time.Second)
	for {
		select {
		case e := <-ch:
			switch e.Topic {
			case "capture:batch":
				if payload, ok := e.Payload.(map[string]any); ok {
					lastBatch = payload
				}
			case "capture:done":
				if lastBatch == nil {
					t.Fatal("la captura terminó sin publicar ningún lote")
				}
				return lastBatch
			}
		case <-deadline:
			t.Fatal("la captura no terminó dentro del tiempo previsto")
		}
	}
}

// TestCaptureFeedsEveryDetector es la regresión del fallo de v0.6.5: si algún
// detector deja de recibir paquetes, su contador queda en cero aunque todo
// compile y el resto de la suite siga en verde.
func TestCaptureFeedsEveryDetector(t *testing.T) {
	const packets = 40
	batch := runCaptureForTest(t, packets)

	if got, _ := batch["total"].(int); got != packets {
		t.Errorf("total = %v, se esperaban %d paquetes", batch["total"], packets)
	}

	scan, ok := batch["scanDetection"].(scandetect.Result)
	if !ok {
		t.Fatalf("scanDetection ausente o de tipo inesperado: %T", batch["scanDetection"])
	}
	if scan.InitialSYN != packets {
		t.Errorf("scandetect vio %d SYN iniciales, se esperaban %d — revisá que detector.Add siga en el callback de captura", scan.InitialSYN, packets)
	}

	l2, ok := batch["netDiag"].(netdiag.Result)
	if !ok {
		t.Fatalf("netDiag ausente o de tipo inesperado: %T", batch["netDiag"])
	}
	if l2.Frames != packets {
		t.Errorf("netdiag vio %d tramas, se esperaban %d — revisá que l2.Add siga en el callback de captura (fallo de v0.6.5)", l2.Frames, packets)
	}
	if l2.Broadcasts != packets {
		t.Errorf("netdiag contó %d broadcasts, se esperaban %d", l2.Broadcasts, packets)
	}
}

// TestCapturePayloadArraysAreNeverNull protege el contrato con el frontend en
// el punto donde de verdad viaja: un slice nil de Go marshalea a null, y las
// vistas hacen .map() sobre estos arreglos sin comprobarlo antes.
func TestCapturePayloadArraysAreNeverNull(t *testing.T) {
	batch := runCaptureForTest(t, 1)

	l2, ok := batch["netDiag"].(netdiag.Result)
	if !ok {
		t.Fatalf("netDiag de tipo inesperado: %T", batch["netDiag"])
	}
	if l2.Findings == nil {
		t.Error("netDiag.findings es nil: llega al frontend como null y rompe el .map() de la vista")
	}
	if l2.Neighbors == nil {
		t.Error("netDiag.neighbors es nil: llega al frontend como null y rompe el .map() de la vista")
	}
}

// TestCaptureStopsOnCancel comprueba que cancelar la sesión detiene la
// captura: es lo que hace el botón Detener y lo que corta el trabajo al
// cerrar la aplicación.
func TestCaptureStopsOnCancel(t *testing.T) {
	app := NewApp()
	defer app.svc.Close()

	sess := app.sessions.New(context.Background(), "capture-cancel")
	ch, unsubscribe := sess.Bus.Subscribe(256, nil)
	defer unsubscribe()

	started := make(chan struct{})
	// Fuente infinita: solo termina si el contexto se cancela.
	source := func(ctx context.Context, onPacket func(packet.Summary)) error {
		close(started)
		for {
			select {
			case <-ctx.Done():
				return nil
			default:
				onPacket(wiringProbe())
				time.Sleep(time.Millisecond)
			}
		}
	}

	go app.runBatchedCapture(sess, source)
	<-started
	app.sessions.Cancel(sess.ID)

	deadline := time.After(10 * time.Second)
	for {
		select {
		case e := <-ch:
			if e.Kind == events.KindDone {
				return // la captura se detuvo, que es lo que se prueba
			}
		case <-deadline:
			t.Fatal("cancelar la sesión no detuvo la captura")
		}
	}
}
