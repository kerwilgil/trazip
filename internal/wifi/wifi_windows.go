//go:build windows

package wifi

import (
	"fmt"
	"sort"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wlanapi                         = windows.NewLazyDLL("wlanapi.dll")
	procWlanOpenHandle              = wlanapi.NewProc("WlanOpenHandle")
	procWlanCloseHandle             = wlanapi.NewProc("WlanCloseHandle")
	procWlanEnumInterfaces          = wlanapi.NewProc("WlanEnumInterfaces")
	procWlanGetAvailableNetworkList = wlanapi.NewProc("WlanGetAvailableNetworkList")
	procWlanGetNetworkBssList       = wlanapi.NewProc("WlanGetNetworkBssList")
	procWlanQueryInterface          = wlanapi.NewProc("WlanQueryInterface")
	procWlanFreeMemory              = wlanapi.NewProc("WlanFreeMemory")
)

// wlan_interface_state_connected — the interface is associated to a network.
const wlanInterfaceStateConnected = 1

// wlan_intf_opcode_current_connection — WlanQueryInterface opcode returning a
// WLAN_CONNECTION_ATTRIBUTES for the interface's active connection.
const wlanIntfOpcodeCurrentConnection = 7

const wlanClientVersion = 2 // Windows Vista and later

// errorAccessDenied is ERROR_ACCESS_DENIED (winerror.h) — what
// WlanGetAvailableNetworkList/WlanGetNetworkBssList return when Windows'
// system-wide Location privacy toggle is off. Since Windows 10 1803, SSID
// names count as location data, so this gate applies to every process
// (Win32 or UWP, elevated or not) — confirmed on this machine: `netsh wlan
// show networks` hits the identical wall with the identical fix.
const errorAccessDenied = 5

// guid mirrors the Win32 GUID struct.
type guid struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// wlanInterfaceInfo mirrors WLAN_INTERFACE_INFO.
type wlanInterfaceInfo struct {
	InterfaceGUID        guid
	InterfaceDescription [256]uint16
	State                uint32
}

// dot11Ssid mirrors DOT11_SSID.
type dot11Ssid struct {
	Length uint32
	SSID   [32]byte
}

func (s dot11Ssid) string() string {
	n := s.Length
	if n > uint32(len(s.SSID)) {
		n = uint32(len(s.SSID))
	}
	return string(s.SSID[:n])
}

// wlanAvailableNetwork mirrors WLAN_AVAILABLE_NETWORK.
type wlanAvailableNetwork struct {
	ProfileName                 [256]uint16
	Dot11Ssid                   dot11Ssid
	Dot11BssType                uint32
	NumberOfBssids              uint32
	NetworkConnectable          int32
	NotConnectableReason        uint32
	NumberOfPhyTypes            uint32
	Dot11PhyTypes               [8]uint32
	MorePhyTypes                int32
	SignalQuality               uint32
	SecurityEnabled             int32
	Dot11DefaultAuthAlgorithm   uint32
	Dot11DefaultCipherAlgorithm uint32
	Flags                       uint32
	Reserved                    uint32
}

// wlanBssEntry mirrors WLAN_BSS_ENTRY. Field order (and therefore alignment
// padding) matters — see channelFromFrequencyKHz's caller below for how the
// frequency field is interpreted.
type wlanBssEntry struct {
	Dot11Ssid             dot11Ssid
	PhyID                 uint32
	Dot11BSSID            [6]byte
	Dot11BssType          uint32
	Dot11BssPhyType       uint32
	RSSI                  int32
	LinkQuality           uint32
	InRegDomain           byte
	BeaconPeriod          uint16
	Timestamp             uint64
	HostTimestamp         uint64
	CapabilityInformation uint16
	ChCenterFrequency     uint32
	RateSetLength         uint32
	RateSet               [126]uint16
	IeOffset              uint32
	IeSize                uint32
}

// Available reports whether wlanapi.dll loaded — present on essentially
// every consumer/desktop Windows install with the WLAN AutoConfig service,
// absent on e.g. Server Core without the wireless feature installed.
func Available() bool {
	return wlanapi.Load() == nil
}

// Scan lists nearby WiFi networks using Windows' own cached scan results
// (WlanGetAvailableNetworkList for SSID/security/signal, merged with
// WlanGetNetworkBssList for per-BSSID channel/RSSI) — the same data
// Windows' WiFi picker shows, refreshed by the OS's own periodic background
// scan (typically within the last ~60s), not a fresh scan TRAZIP triggers
// itself.
func Scan() ([]Network, error) {
	if err := wlanapi.Load(); err != nil {
		return nil, fmt.Errorf("wlanapi.dll no disponible (¿servicio de WLAN AutoConfig deshabilitado?)")
	}

	var handle windows.Handle
	var negotiated uint32
	if r, _, _ := procWlanOpenHandle.Call(uintptr(wlanClientVersion), 0, uintptr(unsafe.Pointer(&negotiated)), uintptr(unsafe.Pointer(&handle))); r != 0 {
		return nil, fmt.Errorf("WlanOpenHandle: código %d", r)
	}
	defer procWlanCloseHandle.Call(uintptr(handle), 0)

	var ifaceList *byte
	if r, _, _ := procWlanEnumInterfaces.Call(uintptr(handle), 0, uintptr(unsafe.Pointer(&ifaceList))); r != 0 {
		return nil, fmt.Errorf("WlanEnumInterfaces: código %d", r)
	}
	defer procWlanFreeMemory.Call(uintptr(unsafe.Pointer(ifaceList)))

	numIfaces := *(*uint32)(unsafe.Pointer(ifaceList))
	if numIfaces == 0 {
		return nil, fmt.Errorf("no se encontró ninguna interfaz WiFi")
	}

	var out []Network
	var lastErr error
	succeeded := 0
	for i := uint32(0); i < numIfaces; i++ {
		iface := (*wlanInterfaceInfo)(unsafe.Pointer(uintptr(unsafe.Pointer(ifaceList)) + 8 + uintptr(i)*unsafe.Sizeof(wlanInterfaceInfo{})))
		nets, err := scanInterface(handle, iface.InterfaceGUID)
		if err != nil {
			lastErr = err
			continue // try the next interface rather than failing the whole scan
		}
		succeeded++
		out = append(out, nets...)
	}
	if succeeded == 0 && lastErr != nil {
		return nil, lastErr
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SignalPct > out[j].SignalPct })
	return out, nil
}

func scanInterface(handle windows.Handle, ifaceGUID guid) ([]Network, error) {
	var netList *byte
	r, _, _ := procWlanGetAvailableNetworkList.Call(uintptr(handle), uintptr(unsafe.Pointer(&ifaceGUID)), 0, 0, uintptr(unsafe.Pointer(&netList)))
	if r == errorAccessDenied {
		return nil, fmt.Errorf("Windows bloqueó el acceso a nombres de red WiFi — activá Ubicación en Configuración > Privacidad y seguridad > Ubicación (afecta a cualquier app desde Windows 10 1803, no es específico de TRAZIP)")
	}
	if r != 0 || netList == nil {
		return nil, fmt.Errorf("WlanGetAvailableNetworkList: código %d", r)
	}
	defer procWlanFreeMemory.Call(uintptr(unsafe.Pointer(netList)))

	numNets := *(*uint32)(unsafe.Pointer(netList))
	networks := make([]Network, 0, numNets)
	bySSID := map[string]int{}
	for i := uint32(0); i < numNets; i++ {
		n := (*wlanAvailableNetwork)(unsafe.Pointer(uintptr(unsafe.Pointer(netList)) + 8 + uintptr(i)*unsafe.Sizeof(wlanAvailableNetwork{})))
		ssid := n.Dot11Ssid.string()
		net := Network{
			SSID:        ssid,
			SignalPct:   int(n.SignalQuality),
			Security:    securityLabel(n.SecurityEnabled != 0, n.Dot11DefaultAuthAlgorithm, n.Dot11DefaultCipherAlgorithm),
			Connectable: n.NetworkConnectable != 0,
			APCount:     int(n.NumberOfBssids),
		}
		networks = append(networks, net)
		bySSID[ssid] = len(networks) - 1
	}

	// WlanGetNetworkBssList(hClientHandle, pInterfaceGuid, pDot11Ssid, dot11BssType,
	// bSecurityEnabled, pReserved, ppWlanBssList) — 7 params. pDot11Ssid=NULL and
	// dot11BssType=dot11_BSS_type_any(3) return every visible BSS regardless of SSID/security.
	var bssList *byte
	r, _, _ = procWlanGetNetworkBssList.Call(uintptr(handle), uintptr(unsafe.Pointer(&ifaceGUID)), 0, 3, 0, 0, uintptr(unsafe.Pointer(&bssList)))
	if r == 0 && bssList != nil {
		defer procWlanFreeMemory.Call(uintptr(unsafe.Pointer(bssList)))
		numBss := *(*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(bssList)) + 4))
		for i := uint32(0); i < numBss; i++ {
			e := (*wlanBssEntry)(unsafe.Pointer(uintptr(unsafe.Pointer(bssList)) + 8 + uintptr(i)*unsafe.Sizeof(wlanBssEntry{})))
			ssid := e.Dot11Ssid.string()
			idx, ok := bySSID[ssid]
			if !ok {
				continue
			}
			net := &networks[idx]
			if net.BSSID == "" || int(e.RSSI) > net.RSSIdBm {
				net.BSSID = macString(e.Dot11BSSID)
				net.RSSIdBm = int(e.RSSI)
				net.Channel = channelFromFrequencyKHz(e.ChCenterFrequency)
				net.Band = bandFromFrequencyKHz(e.ChCenterFrequency)
			}
		}
	}

	return networks, nil
}

// Status reports the connection state of every WLAN interface. Connected is
// read from WLAN_INTERFACE_INFO.State (no extra call); the SSID is a
// best-effort WlanQueryInterface lookup — if it fails, Connected is still
// accurate and SSID is just left empty.
func Status() ([]IfaceStatus, error) {
	if err := wlanapi.Load(); err != nil {
		return nil, nil // no WLAN stack — treat as "no WiFi interfaces"
	}

	var handle windows.Handle
	var negotiated uint32
	if r, _, _ := procWlanOpenHandle.Call(uintptr(wlanClientVersion), 0, uintptr(unsafe.Pointer(&negotiated)), uintptr(unsafe.Pointer(&handle))); r != 0 {
		return nil, fmt.Errorf("WlanOpenHandle: código %d", r)
	}
	defer procWlanCloseHandle.Call(uintptr(handle), 0)

	var ifaceList *byte
	if r, _, _ := procWlanEnumInterfaces.Call(uintptr(handle), 0, uintptr(unsafe.Pointer(&ifaceList))); r != 0 {
		return nil, fmt.Errorf("WlanEnumInterfaces: código %d", r)
	}
	defer procWlanFreeMemory.Call(uintptr(unsafe.Pointer(ifaceList)))

	numIfaces := *(*uint32)(unsafe.Pointer(ifaceList))
	out := make([]IfaceStatus, 0, numIfaces)
	for i := uint32(0); i < numIfaces; i++ {
		iface := (*wlanInterfaceInfo)(unsafe.Pointer(uintptr(unsafe.Pointer(ifaceList)) + 8 + uintptr(i)*unsafe.Sizeof(wlanInterfaceInfo{})))
		st := IfaceStatus{
			Description: windows.UTF16ToString(iface.InterfaceDescription[:]),
			Connected:   iface.State == wlanInterfaceStateConnected,
		}
		if st.Connected {
			st.SSID = currentSSID(handle, iface.InterfaceGUID)
		}
		out = append(out, st)
	}
	return out, nil
}

// currentSSID reads the associated network's SSID via WlanQueryInterface.
// Returns "" on any failure — the caller only needs it for a friendlier
// message, never for correctness.
func currentSSID(handle windows.Handle, ifaceGUID guid) string {
	var dataSize uint32
	var data *byte
	// WlanQueryInterface(hClientHandle, pInterfaceGuid, OpCode, pReserved,
	// pdwDataSize, ppData, pWlanOpcodeValueType) — 7 params.
	r, _, _ := procWlanQueryInterface.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&ifaceGUID)),
		uintptr(wlanIntfOpcodeCurrentConnection),
		0,
		uintptr(unsafe.Pointer(&dataSize)),
		uintptr(unsafe.Pointer(&data)),
		0,
	)
	if r != 0 || data == nil {
		return ""
	}
	defer procWlanFreeMemory.Call(uintptr(unsafe.Pointer(data)))

	// WLAN_CONNECTION_ATTRIBUTES layout: isState(4) + wlanConnectionMode(4) +
	// strProfileName([256]uint16 = 512) then wlanAssociationAttributes, whose
	// first field is dot11Ssid (DOT11_SSID). So the SSID starts at offset 520.
	if dataSize < 520+uint32(unsafe.Sizeof(dot11Ssid{})) {
		return ""
	}
	ssid := (*dot11Ssid)(unsafe.Pointer(uintptr(unsafe.Pointer(data)) + 520))
	return ssid.string()
}

func macString(b [6]byte) string {
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", b[0], b[1], b[2], b[3], b[4], b[5])
}
