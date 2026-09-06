// Package ipcalc is TRAZIP's offline IP calculator: address breakdowns,
// subnetting, VLSM planning and prefix aggregation for IPv4 and IPv6.
//
// Everything here is pure computation over net/netip — no network calls, no
// datasets, no platform-specific code — so it behaves identically everywhere
// and is fully unit-testable. Counts cross into math/big because an IPv6 /64
// holds 2^64 addresses, which neither int64 nor JavaScript's number can
// represent exactly; they are returned as strings so the value that reaches
// the GUI is the value that was computed.
package ipcalc

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"trazip/internal/intel/classify"
)

// maxRows bounds how many subnet rows any single call will materialize, so a
// /8 split into /30s can't allocate four million structs.
const maxRows = 4096

// Info is the full breakdown of one address or prefix.
type Info struct {
	Input     string `json:"input"`
	Family    string `json:"family"`
	Addr      string `json:"addr"`
	Prefix    string `json:"prefix"`
	PrefixLen int    `json:"prefixLen"`

	Network   string `json:"network"`
	Broadcast string `json:"broadcast,omitempty"` // IPv4 only
	FirstHost string `json:"firstHost"`
	LastHost  string `json:"lastHost"`

	TotalCount  string `json:"totalCount"`
	UsableCount string `json:"usableCount"`

	Netmask  string `json:"netmask,omitempty"` // IPv4 dotted form
	Wildcard string `json:"wildcard,omitempty"`

	AddrBinary    string `json:"addrBinary"`
	NetworkBinary string `json:"networkBinary"`
	MaskBinary    string `json:"maskBinary,omitempty"`

	Class    string   `json:"class,omitempty"` // legacy IPv4 class
	Classes  []string `json:"classes"`         // classify.Classify (RFC-based)
	IsPublic bool     `json:"isPublic"`

	Decimal string `json:"decimal,omitempty"` // IPv4 as a 32-bit integer
	Hex     string `json:"hex"`

	Expanded   string `json:"expanded,omitempty"`   // IPv6 full form
	Compressed string `json:"compressed,omitempty"` // IPv6 :: form

	PTR         string `json:"ptr"`
	ReverseZone string `json:"reverseZone"`

	Notes []string `json:"notes,omitempty"`
}

// Subnet is one row of a split.
type Subnet struct {
	Index       int    `json:"index"`
	Prefix      string `json:"prefix"`
	Network     string `json:"network"`
	Broadcast   string `json:"broadcast,omitempty"`
	FirstHost   string `json:"firstHost"`
	LastHost    string `json:"lastHost"`
	UsableCount string `json:"usableCount"`
}

// SplitResult carries the rows plus the true total, which may exceed the rows
// actually returned (see maxRows) — the GUI must be able to say "showing N of M"
// rather than silently implying the split was smaller than it is.
type SplitResult struct {
	Rows      []Subnet `json:"rows"`
	Total     string   `json:"total"`
	Truncated bool     `json:"truncated"`
}

// VLSMRequest is one variable-length subnet the planner must fit.
type VLSMRequest struct {
	Label string `json:"label"`
	Hosts int    `json:"hosts"`
}

// VLSMAlloc is a satisfied VLSMRequest.
type VLSMAlloc struct {
	Label       string `json:"label"`
	HostsAsked  int    `json:"hostsAsked"`
	PrefixLen   int    `json:"prefixLen"`
	Prefix      string `json:"prefix"`
	Network     string `json:"network"`
	Broadcast   string `json:"broadcast,omitempty"`
	FirstHost   string `json:"firstHost"`
	LastHost    string `json:"lastHost"`
	UsableCount int    `json:"usableCount"`
	Waste       int    `json:"waste"`
	Note        string `json:"note,omitempty"`
}

// VLSMResult is the plan plus what is left over.
type VLSMResult struct {
	Allocations []VLSMAlloc `json:"allocations"`
	Remaining   []string    `json:"remaining"`
	UsedPct     float64     `json:"usedPct"`
}

// CustomerPlan describes the smallest conventional IPv4 subnet that can
// deliver the requested number of addresses to a customer. Network and
// broadcast are always reserved; the gateway is optional because some
// providers route a block instead of placing their router inside it.
type CustomerPlan struct {
	Requested             uint64 `json:"requested"`
	ReserveGateway        bool   `json:"reserveGateway"`
	PrefixLen             int    `json:"prefixLen"`
	Block                 string `json:"block"`
	Total                 uint64 `json:"total"`
	UsableInSubnet        uint64 `json:"usableInSubnet"`
	NetworkReserved       uint64 `json:"networkReserved"`
	BroadcastReserved     uint64 `json:"broadcastReserved"`
	GatewayReserved       uint64 `json:"gatewayReserved"`
	Spare                 uint64 `json:"spare"`
	NotAssignedToCustomer uint64 `json:"notAssignedToCustomer"`
}

// Analyze parses input and returns the full breakdown. It accepts
// "10.0.0.1/24", "10.0.0.1 255.255.255.0", "10.0.0.1/255.255.255.0",
// "10.0.0.1 0.0.0.255" (wildcard), a bare address, or any IPv6 equivalent.
func Analyze(input string) (Info, error) {
	addr, bits, err := parse(input)
	if err != nil {
		return Info{}, err
	}
	p := netip.PrefixFrom(addr, bits).Masked()
	network := p.Addr()
	last := lastAddr(p)
	is4 := addr.Is4()

	info := Info{
		Input:         strings.TrimSpace(input),
		Addr:          addr.String(),
		Prefix:        netip.PrefixFrom(addr, bits).String(),
		PrefixLen:     bits,
		Network:       network.String(),
		AddrBinary:    binaryOf(addr),
		NetworkBinary: binaryOf(network),
		Classes:       classStrings(addr),
		IsPublic:      classify.IsPublic(addr),
		Hex:           hexOf(addr),
		PTR:           ptrName(addr),
		ReverseZone:   reverseZone(p),
	}

	hostBits := addr.BitLen() - bits
	total := new(big.Int).Lsh(big.NewInt(1), uint(hostBits))
	info.TotalCount = total.String()

	if is4 {
		info.Family = "IPv4"
		mask := maskAddr(bits, 4)
		info.Netmask = mask.String()
		info.Wildcard = invertV4(mask).String()
		info.MaskBinary = binaryOf(mask)
		info.Broadcast = last.String()
		info.Class = legacyClass(addr)
		info.Decimal = strconv.FormatUint(uint64(v4uint(addr)), 10)

		switch {
		case bits == 32:
			info.FirstHost, info.LastHost = addr.String(), addr.String()
			info.UsableCount = "1"
			info.Broadcast = ""
			info.Notes = append(info.Notes, "/32 identifica un host único: no hay red ni broadcast que reservar.")
		case bits == 31:
			// RFC 3021: both addresses are usable on a point-to-point link.
			info.FirstHost, info.LastHost = network.String(), last.String()
			info.UsableCount = "2"
			info.Broadcast = ""
			info.Notes = append(info.Notes, "/31 es un enlace punto a punto (RFC 3021): las 2 direcciones son utilizables, no se reserva broadcast.")
		default:
			info.FirstHost = network.Next().String()
			info.LastHost = prev(last).String()
			usable := new(big.Int).Sub(total, big.NewInt(2))
			info.UsableCount = usable.String()
		}
	} else {
		info.Family = "IPv6"
		info.Expanded = expandV6(addr)
		info.Compressed = addr.String()
		info.MaskBinary = binaryOf(maskAddr(bits, 16))
		info.FirstHost = network.String()
		info.LastHost = last.String()
		info.UsableCount = total.String()
		if bits < 128 {
			info.Notes = append(info.Notes, "IPv6 no reserva broadcast; la primera dirección de la subred es el anycast subnet-router (RFC 4291).")
		}
	}

	if bits == 0 {
		info.Notes = append(info.Notes, "/0 abarca todo el espacio de direcciones.")
	}
	return info, nil
}

// Split divides prefix into equal subnets of newBits length.
func Split(input string, newBits int) (SplitResult, error) {
	addr, bits, err := parse(input)
	if err != nil {
		return SplitResult{}, err
	}
	base := netip.PrefixFrom(addr, bits).Masked()
	if newBits < bits {
		return SplitResult{}, fmt.Errorf("/%d es más grande que la red de origen /%d", newBits, bits)
	}
	if newBits > addr.BitLen() {
		return SplitResult{}, fmt.Errorf("/%d excede el máximo /%d de %s", newBits, addr.BitLen(), family(addr))
	}
	count := new(big.Int).Lsh(big.NewInt(1), uint(newBits-bits))
	res := SplitResult{Total: count.String()}

	cur := base.Addr()
	for i := 0; i < maxRows; i++ {
		if big.NewInt(int64(i)).Cmp(count) >= 0 {
			break
		}
		sp := netip.PrefixFrom(cur, newBits)
		res.Rows = append(res.Rows, subnetRow(i, sp))
		next := nextNetwork(sp)
		if !next.IsValid() {
			break
		}
		cur = next
	}
	res.Truncated = count.Cmp(big.NewInt(int64(len(res.Rows)))) > 0
	return res, nil
}

// VLSM allocates variable-length subnets inside input, largest request first
// (the only order that avoids fragmenting the space), and reports what is left.
func VLSM(input string, reqs []VLSMRequest) (VLSMResult, error) {
	addr, bits, err := parse(input)
	if err != nil {
		return VLSMResult{}, err
	}
	if !addr.Is4() {
		return VLSMResult{}, fmt.Errorf("el planificador VLSM está limitado a IPv4: en IPv6 la práctica es asignar /64 por segmento, no ajustar el prefijo al número de hosts")
	}
	if len(reqs) == 0 {
		return VLSMResult{}, fmt.Errorf("indicá al menos una subred con la cantidad de hosts que necesita")
	}
	base := netip.PrefixFrom(addr, bits).Masked()

	ordered := make([]VLSMRequest, len(reqs))
	copy(ordered, reqs)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Hosts > ordered[j].Hosts })

	var out VLSMResult
	cursor := base.Addr()
	baseEnd := lastAddr(base)
	var usedAddrs uint64

	for _, r := range ordered {
		if r.Hosts < 1 {
			return VLSMResult{}, fmt.Errorf("%q pide %d hosts: debe ser al menos 1", r.Label, r.Hosts)
		}
		need := neededBits(r.Hosts)
		if need < bits {
			return VLSMResult{}, fmt.Errorf("%q necesita %d hosts (/%d) y no cabe en %s", r.Label, r.Hosts, need, base)
		}
		// Align the cursor to the block size this prefix requires.
		aligned := alignUp(cursor, need)
		if !aligned.IsValid() || cmpAddr(aligned, baseEnd) > 0 {
			return VLSMResult{}, fmt.Errorf("no queda espacio en %s para %q (%d hosts)", base, r.Label, r.Hosts)
		}
		sp := netip.PrefixFrom(aligned, need)
		spEnd := lastAddr(sp)
		if cmpAddr(spEnd, baseEnd) > 0 {
			return VLSMResult{}, fmt.Errorf("no queda espacio en %s para %q (%d hosts)", base, r.Label, r.Hosts)
		}
		row := subnetRow(0, sp)
		usable := usableV4(need)
		alloc := VLSMAlloc{
			Label:       r.Label,
			HostsAsked:  r.Hosts,
			PrefixLen:   need,
			Prefix:      sp.String(),
			Network:     row.Network,
			Broadcast:   row.Broadcast,
			FirstHost:   row.FirstHost,
			LastHost:    row.LastHost,
			UsableCount: usable,
			Waste:       usable - r.Hosts,
		}
		if r.Hosts <= 2 {
			alloc.Note = "un enlace punto a punto también cabe en /31 (RFC 3021) si el equipo lo soporta, ahorrando 2 direcciones"
		}
		out.Allocations = append(out.Allocations, alloc)
		usedAddrs += uint64(1) << uint(32-need)
		next := nextNetwork(sp)
		if !next.IsValid() {
			cursor = spEnd
			break
		}
		cursor = next
	}

	out.Remaining = freeBlocks(cursor, baseEnd)
	totalAddrs := uint64(1) << uint(32-bits)
	if totalAddrs > 0 {
		out.UsedPct = float64(usedAddrs) / float64(totalAddrs) * 100
	}
	return out, nil
}

// PlanCustomerIPs returns the minimum traditional IPv4 block for a customer
// allocation. It deliberately does not suggest /31 or /32: those prefixes are
// useful for point-to-point links or host routes, not for a normal customer LAN
// with a distinct network, broadcast and (optionally) gateway address.
func PlanCustomerIPs(requested uint64, reserveGateway bool) (CustomerPlan, error) {
	if requested == 0 {
		return CustomerPlan{}, fmt.Errorf("la cantidad de IP para el cliente debe ser al menos 1")
	}

	gateway := uint64(0)
	if reserveGateway {
		gateway = 1
	}
	const maxTraditionalUsable = uint64(1)<<32 - 2
	if requested > maxTraditionalUsable-gateway {
		return CustomerPlan{}, fmt.Errorf("la cantidad solicitada no cabe en un bloque IPv4 convencional")
	}
	neededUsable := requested + gateway

	prefixLen := 30
	total := uint64(4)
	for prefixLen > 0 && total-2 < neededUsable {
		prefixLen--
		total <<= 1
	}
	usable := total - 2
	spare := usable - requested - gateway

	return CustomerPlan{
		Requested:             requested,
		ReserveGateway:        reserveGateway,
		PrefixLen:             prefixLen,
		Block:                 fmt.Sprintf("/%d", prefixLen),
		Total:                 total,
		UsableInSubnet:        usable,
		NetworkReserved:       1,
		BroadcastReserved:     1,
		GatewayReserved:       gateway,
		Spare:                 spare,
		NotAssignedToCustomer: total - requested,
	}, nil
}

// Aggregate merges a set of prefixes into the smallest equivalent set,
// collapsing containment and adjacent sibling pairs. Mixed families are kept
// separate — an IPv4 and an IPv6 prefix can never merge.
func Aggregate(inputs []string) ([]string, error) {
	var v4, v6 []netip.Prefix
	for _, in := range inputs {
		s := strings.TrimSpace(in)
		if s == "" {
			continue
		}
		addr, bits, err := parse(s)
		if err != nil {
			return nil, err
		}
		p := netip.PrefixFrom(addr, bits).Masked()
		if addr.Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}
	if len(v4) == 0 && len(v6) == 0 {
		return nil, fmt.Errorf("indicá al menos un prefijo")
	}
	out := append(collapse(v4), collapse(v6)...)
	res := make([]string, len(out))
	for i, p := range out {
		res[i] = p.String()
	}
	return res, nil
}

// Contains reports whether addrInput falls inside prefixInput.
func Contains(prefixInput, addrInput string) (bool, error) {
	pa, bits, err := parse(prefixInput)
	if err != nil {
		return false, err
	}
	p := netip.PrefixFrom(pa, bits).Masked()
	a, err := netip.ParseAddr(strings.TrimSpace(addrInput))
	if err != nil {
		return false, fmt.Errorf("dirección inválida: %s", addrInput)
	}
	a = a.Unmap()
	if a.Is4() != p.Addr().Is4() {
		return false, fmt.Errorf("no se pueden comparar IPv4 con IPv6")
	}
	return p.Contains(a), nil
}

// ---- parsing ----

func parse(input string) (netip.Addr, int, error) {
	s := strings.TrimSpace(input)
	if s == "" {
		return netip.Addr{}, 0, fmt.Errorf("entrada vacía")
	}
	var addrPart, maskPart string
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		addrPart, maskPart = s[:i], strings.TrimSpace(s[i+1:])
	} else if i := strings.LastIndex(s, "/"); i >= 0 {
		addrPart, maskPart = s[:i], s[i+1:]
	} else {
		addrPart = s
	}

	addr, err := netip.ParseAddr(strings.TrimSpace(addrPart))
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("dirección inválida: %q", strings.TrimSpace(addrPart))
	}
	addr = addr.Unmap()

	bits := addr.BitLen()
	if maskPart != "" {
		bits, err = parseMask(maskPart, addr)
		if err != nil {
			return netip.Addr{}, 0, err
		}
	}
	if bits < 0 || bits > addr.BitLen() {
		return netip.Addr{}, 0, fmt.Errorf("prefijo /%d fuera de rango para %s (máximo /%d)", bits, family(addr), addr.BitLen())
	}
	return addr, bits, nil
}

// parseMask accepts a prefix length, a dotted netmask (255.255.255.0) or a
// wildcard/ACL mask (0.0.0.255) — network gear and documentation use all three
// interchangeably, so refusing two of them would just make the tool annoying.
func parseMask(mask string, addr netip.Addr) (int, error) {
	mask = strings.TrimSpace(mask)
	if n, err := strconv.Atoi(mask); err == nil {
		return n, nil
	}
	m, err := netip.ParseAddr(mask)
	if err != nil || !m.Is4() || !addr.Is4() {
		return 0, fmt.Errorf("máscara inválida: %q", mask)
	}
	v := v4uint(m)
	if n, ok := leadingOnes(v); ok {
		return n, nil
	}
	if n, ok := leadingOnes(^v); ok { // wildcard form
		return n, nil
	}
	return 0, fmt.Errorf("máscara no contigua: %q (los bits de red deben ser consecutivos)", mask)
}

// leadingOnes returns how many 1 bits lead v, and whether every remaining bit
// is 0 (i.e. v is a valid contiguous netmask).
func leadingOnes(v uint32) (int, bool) {
	n := 0
	for n < 32 && v&(1<<uint(31-n)) != 0 {
		n++
	}
	if v<<uint(n) != 0 {
		return 0, false
	}
	return n, true
}

// ---- address math ----

func v4uint(a netip.Addr) uint32 {
	b := a.As4()
	return binary.BigEndian.Uint32(b[:])
}

func v4addr(v uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}

func invertV4(a netip.Addr) netip.Addr { return v4addr(^v4uint(a)) }

// maskAddr builds the netmask for a prefix length as an address.
func maskAddr(bits, size int) netip.Addr {
	b := make([]byte, size)
	for i := 0; i < size; i++ {
		start := i * 8
		switch {
		case start+8 <= bits:
			b[i] = 0xFF
		case start >= bits:
			b[i] = 0
		default:
			b[i] = ^byte(0xFF >> uint(bits-start))
		}
	}
	if size == 4 {
		return netip.AddrFrom4([4]byte(b))
	}
	return netip.AddrFrom16([16]byte(b))
}

// lastAddr returns the highest address inside p (broadcast, for IPv4).
func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr()
	if a.Is4() {
		b := a.As4()
		setHostBits(b[:], p.Bits())
		return netip.AddrFrom4(b)
	}
	b := a.As16()
	setHostBits(b[:], p.Bits())
	return netip.AddrFrom16(b)
}

// setHostBits turns every bit past prefixLen into 1, in place.
func setHostBits(b []byte, prefixLen int) {
	for i := range b {
		start := i * 8
		switch {
		case start >= prefixLen:
			b[i] = 0xFF
		case start+8 <= prefixLen:
			// entirely inside the prefix, untouched
		default:
			b[i] |= 0xFF >> uint(prefixLen-start)
		}
	}
}

func prev(a netip.Addr) netip.Addr {
	if a.Is4() {
		return v4addr(v4uint(a) - 1)
	}
	b := a.As16()
	for i := 15; i >= 0; i-- {
		if b[i] > 0 {
			b[i]--
			break
		}
		b[i] = 0xFF
	}
	return netip.AddrFrom16(b)
}

// nextNetwork returns the first address after p, or an invalid Addr when p
// reaches the end of the address space.
func nextNetwork(p netip.Prefix) netip.Addr {
	last := lastAddr(p)
	if !last.IsValid() {
		return netip.Addr{}
	}
	n := last.Next()
	if !n.IsValid() {
		return netip.Addr{}
	}
	return n
}

func cmpAddr(a, b netip.Addr) int { return a.Compare(b) }

// alignUp moves a forward to the next boundary where a /bits prefix can start.
func alignUp(a netip.Addr, bits int) netip.Addr {
	if !a.IsValid() {
		return a
	}
	p := netip.PrefixFrom(a, bits).Masked()
	if p.Addr() == a {
		return a
	}
	return nextNetwork(p)
}

// neededBits returns the smallest IPv4 prefix length that fits n usable hosts,
// never going past /30.
//
// A 2-host link technically fits in a /31 (RFC 3021) and a single host in a
// /32, but this is a *planning* tool: a plan is only useful if it can be
// deployed, and /31 support is not universal on older switches and routers.
// Handing back /30 is always implementable, so that is the default; the
// allocation carries a note pointing out when /31 would also work.
func neededBits(n int) int {
	for bits := 30; bits >= 0; bits-- {
		if usableV4(bits) >= n {
			return bits
		}
	}
	return 0
}

// usableV4 is how many hosts a given IPv4 prefix length can address, honouring
// the /31 point-to-point and /32 host special cases.
func usableV4(bits int) int {
	switch {
	case bits >= 32:
		return 1
	case bits == 31:
		return 2
	default:
		return (1 << uint(32-bits)) - 2
	}
}

// freeBlocks expresses the range [from, to] as the fewest CIDR blocks.
func freeBlocks(from, to netip.Addr) []string {
	if !from.IsValid() || !to.IsValid() || from.Compare(to) > 0 || !from.Is4() {
		return nil
	}
	var out []string
	cur := v4uint(from)
	end := v4uint(to)
	for cur <= end {
		// Largest block that starts at cur and doesn't overshoot end.
		bits := 32
		for bits > 0 {
			size := uint64(1) << uint(32-(bits-1))
			// Keep the alignment calculation in uint64. For a candidate /0,
			// size is 2^32; converting that to uint32 produced zero and made
			// the old modulo expression panic.
			if uint64(cur)%size != 0 || uint64(cur)+size-1 > uint64(end) {
				break
			}
			bits--
		}
		out = append(out, netip.PrefixFrom(v4addr(cur), bits).String())
		size := uint64(1) << uint(32-bits)
		if uint64(cur)+size > uint64(^uint32(0)) {
			break
		}
		cur += uint32(size)
		if len(out) >= 64 { // a pathological range shouldn't flood the UI
			break
		}
	}
	return out
}

// collapse sorts and merges prefixes of one family.
func collapse(ps []netip.Prefix) []netip.Prefix {
	if len(ps) == 0 {
		return nil
	}
	sort.Slice(ps, func(i, j int) bool {
		if c := ps[i].Addr().Compare(ps[j].Addr()); c != 0 {
			return c < 0
		}
		return ps[i].Bits() < ps[j].Bits()
	})
	// Drop prefixes contained in an earlier, broader one.
	var kept []netip.Prefix
	for _, p := range ps {
		covered := false
		for _, k := range kept {
			if k.Bits() <= p.Bits() && k.Contains(p.Addr()) {
				covered = true
				break
			}
		}
		if !covered {
			kept = append(kept, p)
		}
	}
	// Merge sibling pairs repeatedly until nothing changes.
	for {
		merged := false
		var next []netip.Prefix
		for i := 0; i < len(kept); i++ {
			if i+1 < len(kept) && siblings(kept[i], kept[i+1]) {
				next = append(next, netip.PrefixFrom(kept[i].Addr(), kept[i].Bits()-1).Masked())
				i++
				merged = true
				continue
			}
			next = append(next, kept[i])
		}
		kept = next
		if !merged {
			return kept
		}
	}
}

// siblings reports whether a and b are the two halves of the same parent.
func siblings(a, b netip.Prefix) bool {
	if a.Bits() != b.Bits() || a.Bits() == 0 || a.Addr().Is4() != b.Addr().Is4() {
		return false
	}
	parent := netip.PrefixFrom(a.Addr(), a.Bits()-1).Masked()
	return parent.Contains(b.Addr()) && parent.Addr() == a.Addr() && nextNetwork(a) == b.Addr()
}

// ---- formatting ----

func subnetRow(i int, p netip.Prefix) Subnet {
	p = p.Masked()
	network := p.Addr()
	last := lastAddr(p)
	row := Subnet{Index: i, Prefix: p.String(), Network: network.String(), LastHost: last.String()}
	if network.Is4() {
		switch {
		case p.Bits() >= 32:
			row.FirstHost, row.LastHost = network.String(), network.String()
			row.UsableCount = "1"
		case p.Bits() == 31:
			row.FirstHost, row.LastHost = network.String(), last.String()
			row.UsableCount = "2"
		default:
			row.Broadcast = last.String()
			row.FirstHost = network.Next().String()
			row.LastHost = prev(last).String()
			row.UsableCount = strconv.Itoa(usableV4(p.Bits()))
		}
		return row
	}
	row.FirstHost = network.String()
	total := new(big.Int).Lsh(big.NewInt(1), uint(128-p.Bits()))
	row.UsableCount = total.String()
	return row
}

func binaryOf(a netip.Addr) string {
	if a.Is4() {
		b := a.As4()
		parts := make([]string, 4)
		for i, x := range b {
			parts[i] = fmt.Sprintf("%08b", x)
		}
		return strings.Join(parts, ".")
	}
	b := a.As16()
	parts := make([]string, 8)
	for i := 0; i < 8; i++ {
		parts[i] = fmt.Sprintf("%08b%08b", b[i*2], b[i*2+1])
	}
	return strings.Join(parts, ":")
}

func hexOf(a netip.Addr) string {
	if a.Is4() {
		return fmt.Sprintf("0x%08X", v4uint(a))
	}
	b := a.As16()
	var sb strings.Builder
	sb.WriteString("0x")
	for _, x := range b {
		fmt.Fprintf(&sb, "%02X", x)
	}
	return sb.String()
}

func expandV6(a netip.Addr) string {
	b := a.As16()
	parts := make([]string, 8)
	for i := 0; i < 8; i++ {
		parts[i] = fmt.Sprintf("%02x%02x", b[i*2], b[i*2+1])
	}
	return strings.Join(parts, ":")
}

func legacyClass(a netip.Addr) string {
	first := a.As4()[0]
	switch {
	case first < 128:
		return "A"
	case first < 192:
		return "B"
	case first < 224:
		return "C"
	case first < 240:
		return "D (multicast)"
	default:
		return "E (reservada)"
	}
}

func classStrings(a netip.Addr) []string {
	cs := classify.Classify(a)
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = string(c)
	}
	return out
}

// ptrName is the full reverse-DNS name of a single address.
func ptrName(a netip.Addr) string {
	if a.Is4() {
		b := a.As4()
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", b[3], b[2], b[1], b[0])
	}
	b := a.As16()
	var sb strings.Builder
	for i := 15; i >= 0; i-- {
		fmt.Fprintf(&sb, "%x.%x.", b[i]&0x0F, b[i]>>4)
	}
	sb.WriteString("ip6.arpa")
	return sb.String()
}

// reverseZone names the delegation zone for a prefix. Sub-/24 IPv4 prefixes use
// the RFC 2317 classless form, since a /26 has no zone of its own.
func reverseZone(p netip.Prefix) string {
	a := p.Addr()
	bits := p.Bits()
	if a.Is4() {
		b := a.As4()
		switch {
		case bits >= 25:
			return fmt.Sprintf("%d/%d.%d.%d.%d.in-addr.arpa", b[3], bits, b[2], b[1], b[0])
		case bits == 24:
			return fmt.Sprintf("%d.%d.%d.in-addr.arpa", b[2], b[1], b[0])
		case bits == 16:
			return fmt.Sprintf("%d.%d.in-addr.arpa", b[1], b[0])
		case bits == 8:
			return fmt.Sprintf("%d.in-addr.arpa", b[0])
		default:
			return "abarca varias zonas in-addr.arpa (el prefijo no cae en un límite de octeto)"
		}
	}
	if bits%4 != 0 {
		return "abarca varias zonas ip6.arpa (el prefijo no cae en un límite de nibble)"
	}
	b := a.As16()
	nibbles := bits / 4
	var sb strings.Builder
	for i := nibbles - 1; i >= 0; i-- {
		x := b[i/2]
		if i%2 == 0 {
			x >>= 4
		} else {
			x &= 0x0F
		}
		fmt.Fprintf(&sb, "%x.", x)
	}
	sb.WriteString("ip6.arpa")
	return sb.String()
}

func family(a netip.Addr) string {
	if a.Is4() {
		return "IPv4"
	}
	return "IPv6"
}
