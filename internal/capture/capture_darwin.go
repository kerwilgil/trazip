//go:build darwin

package capture

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"

	"trazip/internal/packet"
)

// macOS ships libpcap as part of the base system, so capture support is a
// question of permissions, not installation: the BPF devices (/dev/bpf*) are
// only readable by root or members of access_bpf (created by Wireshark's
// ChmodBPF helper). Available() therefore reports true and permission
// problems surface per-operation with a clear message.
func Available() bool { return true }

// Devices lists capturable interfaces via pcap_findalldevs. macOS device
// names (en0, awdl0, lo0…) carry no description, so one is synthesized from
// the interface's addresses to keep the picker as friendly as the Npcap one.
func Devices() ([]Device, error) {
	ifs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, bpfPermissionHint(err)
	}
	out := make([]Device, 0, len(ifs))
	for _, d := range ifs {
		desc := d.Description
		if desc == "" {
			var addrs []string
			for _, a := range d.Addresses {
				if a.IP != nil {
					addrs = append(addrs, a.IP.String())
				}
			}
			if len(addrs) > 0 {
				desc = strings.Join(addrs, ", ")
			}
		}
		out = append(out, Device{Name: d.Name, Description: desc})
	}
	return out, nil
}

// Capture opens the device and streams decoded packet summaries until the
// context is cancelled. onPacket is called from the capture goroutine.
//
// monitorMode requests raw 802.11 (Radiotap-prefixed) capture. Unlike most
// Windows drivers, macOS WiFi adapters do support RFMON via libpcap, but the
// interface leaves its network while monitoring. When unsupported, this fails
// clearly instead of silently falling back (same contract as Windows).
func Capture(ctx context.Context, device string, snaplen int, promisc, monitorMode bool, onPacket func(packet.Summary)) error {
	return run(ctx, device, snaplen, promisc, monitorMode, onPacket, nil)
}

// CaptureRaw streams the raw captured frames without decoding them — for
// forwarders like the TZSP sender. onFrame's slice is only valid for the
// duration of the call.
func CaptureRaw(ctx context.Context, device string, snaplen int, promisc bool, onFrame func(data []byte)) error {
	return run(ctx, device, snaplen, promisc, false, nil, onFrame)
}

func run(ctx context.Context, device string, snaplen int, promisc, monitorMode bool, onPacket func(packet.Summary), onFrame func(data []byte)) error {
	if snaplen <= 0 {
		snaplen = 65535
	}

	inactive, err := pcap.NewInactiveHandle(device)
	if err != nil {
		return fmt.Errorf("no se pudo crear el handle de captura: %w", err)
	}
	defer inactive.CleanUp()
	if err := inactive.SetSnapLen(snaplen); err != nil {
		return err
	}
	if err := inactive.SetPromisc(promisc); err != nil {
		return err
	}
	// 1s read timeout so the loop can poll ctx between batches.
	if err := inactive.SetTimeout(time.Second); err != nil {
		return err
	}
	if monitorMode {
		if err := inactive.SetRFMon(true); err != nil {
			return fmt.Errorf("este adaptador no soporta modo monitor (802.11 raw): %v — desactivá modo monitor para capturar normalmente", err)
		}
	}

	handle, err := inactive.Activate()
	if err != nil {
		return bpfPermissionHint(fmt.Errorf("no se pudo abrir %s: %w", device, err))
	}
	defer handle.Close()

	baseLayer := layers.LayerTypeEthernet
	switch handle.LinkType() {
	case layers.LinkTypeIEEE80211Radio:
		baseLayer = layers.LayerTypeRadioTap
	case layers.LinkTypeNull, layers.LinkTypeLoop:
		baseLayer = layers.LayerTypeLoopback // lo0 uses the BSD null/loopback header
	}

	idx := 0
	for {
		if ctx.Err() != nil {
			return nil
		}
		data, ci, err := handle.ReadPacketData()
		if err != nil {
			if errors.Is(err, pcap.NextErrorTimeoutExpired) {
				continue // poll ctx again
			}
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("captura finalizada: %w", err)
		}
		if len(data) == 0 {
			continue
		}
		buf := make([]byte, len(data))
		copy(buf, data)
		if onFrame != nil {
			onFrame(buf)
		}
		if onPacket != nil {
			p := gopacket.NewPacket(buf, baseLayer, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
			md := p.Metadata()
			md.Timestamp = ci.Timestamp
			md.CaptureInfo = ci
			s := packet.Summarize(idx, p)
			idx++
			onPacket(s)
		}
	}
}

// bpfPermissionHint wraps the "Permission denied" that libpcap returns when
// /dev/bpf* is not accessible with the actionable fix, since that is by far
// the most common capture failure on macOS.
func bpfPermissionHint(err error) error {
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "permission denied") {
		return fmt.Errorf("%w — sin acceso a /dev/bpf*: ejecutá TRAZIP con sudo, o instalá el helper ChmodBPF (incluido con Wireshark) para capturar sin privilegios", err)
	}
	return err
}
