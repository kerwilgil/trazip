//go:build windows

package capture

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/sys/windows"

	"trazip/internal/packet"
)

// init locates Npcap's install directory (wpcap.dll lives in
// %SystemRoot%\System32\Npcap, not System32 itself, and Npcap does not add
// itself to PATH) and adds it to the process DLL search path via
// SetDllDirectory. This must run before the first LazyDLL/LazyProc call below,
// and it also resolves wpcap.dll's own dependency on Packet.dll, which lives in
// the same directory.
func init() {
	if dir := npcapDir(); dir != "" {
		_ = windows.SetDllDirectory(dir)
	}
}

func npcapDir() string {
	root, err := windows.GetSystemWindowsDirectory()
	if err != nil || root == "" {
		return ""
	}
	for _, d := range []string{
		filepath.Join(root, "System32", "Npcap"),
		filepath.Join(root, "SysWOW64", "Npcap"),
	} {
		if _, err := os.Stat(filepath.Join(d, "wpcap.dll")); err == nil {
			return d
		}
	}
	return ""
}

func npcapDLLPath() string {
	if dir := npcapDir(); dir != "" {
		return filepath.Join(dir, "wpcap.dll")
	}
	// Keep the LazyDLL name absolute even when Npcap is absent so Windows never
	// falls back to the current directory or PATH.
	return `C:\__trazip_npcap_unavailable__\wpcap.dll`
}

var (
	wpcap           = windows.NewLazyDLL(npcapDLLPath())
	procFindAllDevs = wpcap.NewProc("pcap_findalldevs")
	procFreeAllDevs = wpcap.NewProc("pcap_freealldevs")
	procOpenLive    = wpcap.NewProc("pcap_open_live")
	procClose       = wpcap.NewProc("pcap_close")
	procNextEx      = wpcap.NewProc("pcap_next_ex")
	procCreate      = wpcap.NewProc("pcap_create")
	procSetSnaplen  = wpcap.NewProc("pcap_set_snaplen")
	procSetPromisc  = wpcap.NewProc("pcap_set_promisc")
	procCanSetRFMon = wpcap.NewProc("pcap_can_set_rfmon")
	procSetRFMon    = wpcap.NewProc("pcap_set_rfmon")
	procSetTimeout  = wpcap.NewProc("pcap_set_timeout")
	procActivate    = wpcap.NewProc("pcap_activate")
	procDatalink    = wpcap.NewProc("pcap_datalink")
)

// dltIEEE802_11Radio is DLT_IEEE802_11_RADIO — the libpcap link-layer type
// pcap_datalink() reports once monitor mode is active: raw 802.11 frames
// prefixed with a Radiotap header, not Ethernet. Decoding these as Ethernet
// (the assumption everywhere else in this package) would produce garbage.
const dltIEEE802_11Radio = 127

// pcapErrorRFMonNotSup is PCAP_ERROR_RFMON_NOTSUP — pcap_activate()'s
// specific "monitor mode requested but this device doesn't support it"
// error code, checked here to give a precise message instead of a bare
// libpcap error number for the single most common activation failure.
const pcapErrorRFMonNotSup = -6

// pcapIf mirrors pcap_if_t (64-bit).
type pcapIf struct {
	Next        *pcapIf
	Name        *byte
	Description *byte
	Addresses   uintptr
	Flags       uint32
}

// pcapPkthdr mirrors struct pcap_pkthdr on Windows x64 (timeval uses 32-bit longs).
type pcapPkthdr struct {
	TvSec  int32
	TvUsec int32
	Caplen uint32
	Len    uint32
}

// Available reports whether Npcap (wpcap.dll) is present.
func Available() bool {
	return wpcap.Load() == nil
}

// Devices lists capturable interfaces via pcap_findalldevs.
func Devices() ([]Device, error) {
	if err := wpcap.Load(); err != nil {
		return nil, fmt.Errorf("Npcap no está instalado (wpcap.dll no encontrado). Instálalo desde npcap.com")
	}
	var alldevs *pcapIf
	errbuf := make([]byte, 256)
	r, _, _ := procFindAllDevs.Call(uintptr(unsafe.Pointer(&alldevs)), uintptr(unsafe.Pointer(&errbuf[0])))
	if int32(r) != 0 {
		return nil, fmt.Errorf("pcap_findalldevs: %s", cstr(&errbuf[0]))
	}
	defer procFreeAllDevs.Call(uintptr(unsafe.Pointer(alldevs)))

	var out []Device
	for d := alldevs; d != nil; d = d.Next {
		out = append(out, Device{Name: cstr(d.Name), Description: cstr(d.Description)})
	}
	return out, nil
}

// Capture opens the device and streams decoded packet summaries until the context
// is cancelled. onPacket is called from the capture goroutine.
//
// monitorMode requests raw 802.11 (Radiotap-prefixed) capture instead of the
// OS's usual Ethernet-translated view — this only works when the adapter's
// own NDIS driver exposes it to Npcap (most stock Windows WiFi drivers
// don't; see internal/wifi and CONTEXT-trazip.md for the full explanation).
// When unsupported, this fails clearly instead of silently falling back, so
// the caller never mistakes "capturing my own traffic only" for "monitor
// mode is on".
func Capture(ctx context.Context, device string, snaplen int, promisc, monitorMode bool, onPacket func(packet.Summary)) error {
	return run(ctx, device, snaplen, promisc, monitorMode, onPacket, nil)
}

// CaptureRaw streams the raw captured frames (as libpcap hands them over,
// snaplen-truncated) without decoding them — for forwarders like the TZSP
// sender, where TRAZIP is only a conveyor belt and the receiving side does
// the decoding. onFrame's slice is only valid for the duration of the call.
func CaptureRaw(ctx context.Context, device string, snaplen int, promisc bool, onFrame func(data []byte)) error {
	return run(ctx, device, snaplen, promisc, false, nil, onFrame)
}

func run(ctx context.Context, device string, snaplen int, promisc, monitorMode bool, onPacket func(packet.Summary), onFrame func(data []byte)) error {
	if err := wpcap.Load(); err != nil {
		return fmt.Errorf("Npcap no está instalado")
	}
	if snaplen <= 0 {
		snaplen = 65535
	}
	promiscInt := 0
	if promisc {
		promiscInt = 1
	}
	dev := append([]byte(device), 0)
	errbuf := make([]byte, 256)

	var handle uintptr
	if monitorMode {
		h, _, _ := procCreate.Call(uintptr(unsafe.Pointer(&dev[0])), uintptr(unsafe.Pointer(&errbuf[0])))
		if h == 0 {
			return fmt.Errorf("no se pudo crear el handle de captura: %s", cstr(&errbuf[0]))
		}
		procSetSnaplen.Call(h, uintptr(snaplen))
		procSetPromisc.Call(h, uintptr(promiscInt))
		procSetTimeout.Call(h, uintptr(1000))

		if can, _, _ := procCanSetRFMon.Call(h); int32(can) != 1 {
			procClose.Call(h)
			return fmt.Errorf("este adaptador/driver no soporta modo monitor (802.11 raw) — probalo con otro adaptador WiFi, o desactivá modo monitor para capturar normalmente")
		}
		if r, _, _ := procSetRFMon.Call(h, 1); int32(r) != 0 {
			procClose.Call(h)
			return fmt.Errorf("no se pudo habilitar modo monitor (código libpcap %d)", int32(r))
		}
		if r, _, _ := procActivate.Call(h); int32(r) < 0 {
			procClose.Call(h)
			if int32(r) == pcapErrorRFMonNotSup {
				return fmt.Errorf("este adaptador/driver no soporta modo monitor (802.11 raw) — probalo con otro adaptador WiFi, o desactivá modo monitor")
			}
			return fmt.Errorf("no se pudo activar la captura en modo monitor (código libpcap %d)", int32(r))
		}
		handle = h
	} else {
		h, _, _ := procOpenLive.Call(
			uintptr(unsafe.Pointer(&dev[0])),
			uintptr(snaplen),
			uintptr(promiscInt),
			uintptr(1000), // read timeout ms
			uintptr(unsafe.Pointer(&errbuf[0])),
		)
		if h == 0 {
			return fmt.Errorf("no se pudo abrir %s: %s", device, cstr(&errbuf[0]))
		}
		handle = h
	}
	defer procClose.Call(handle)

	baseLayer := layers.LayerTypeEthernet
	if dlt, _, _ := procDatalink.Call(handle); int32(dlt) == dltIEEE802_11Radio {
		baseLayer = layers.LayerTypeRadioTap
	}

	idx := 0
	for {
		if ctx.Err() != nil {
			return nil
		}
		var hdr *pcapPkthdr
		var data *byte
		r, _, _ := procNextEx.Call(handle, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data)))
		switch int32(r) {
		case 0:
			continue // timeout, poll again
		case 1:
			if hdr == nil || data == nil || hdr.Caplen == 0 {
				continue
			}
			n := int(hdr.Caplen)
			buf := make([]byte, n)
			copy(buf, unsafe.Slice(data, n))
			if onFrame != nil {
				onFrame(buf)
			}
			if onPacket != nil {
				p := gopacket.NewPacket(buf, baseLayer, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
				md := p.Metadata()
				md.Timestamp = time.Unix(int64(hdr.TvSec), int64(hdr.TvUsec)*1000)
				md.CaptureInfo = gopacket.CaptureInfo{Timestamp: md.Timestamp, CaptureLength: n, Length: int(hdr.Len)}
				s := packet.Summarize(idx, p)
				idx++
				onPacket(s)
			}
		default:
			return fmt.Errorf("captura finalizada (código %d)", int32(r))
		}
	}
}

func cstr(p *byte) string {
	if p == nil {
		return ""
	}
	var b []byte
	for ptr := unsafe.Pointer(p); ; ptr = unsafe.Add(ptr, 1) {
		c := *(*byte)(ptr)
		if c == 0 {
			break
		}
		b = append(b, c)
	}
	return string(b)
}
