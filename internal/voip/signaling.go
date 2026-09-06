package voip

// buildSignalingPath derives Call.SignalingPath from Timeline evidence only
// — the INVITE that started the dialog and any INVITEs a proxy/SBC/carrier
// re-sent onward for the SAME Call-ID (a transparent/stateful proxy forwards
// under the original Call-ID; see CONTEXT-trazip.md for what this does and
// doesn't cover). Responses, retransmissions, ACK, CANCEL and BYE never
// contribute a hop: retransmissions are already flagged by handleSIP (same
// top Via branch as an earlier request on this call), while a genuinely
// forwarded INVITE carries a NEW top Via branch (the proxy's own), so the
// two are never confused.
//
// Returns (nil, false) when there isn't enough evidence for even a two-party
// path (no INVITE observed at all — a mid-dialog capture) or when the very
// first hop is already an unresolved fork. See signalingChain for how a
// later fork is handled: the confidently-known prefix is kept, never
// promoted past what the evidence actually shows.
func buildSignalingPath(c *Call) ([]SignalingHop, bool) {
	nodes, complete := signalingChain(c)
	if len(nodes) < 2 {
		return nil, false
	}

	hops := make([]SignalingHop, len(nodes))
	for i, addr := range nodes {
		role := SignalingRoleIntermediary
		switch {
		case i == 0:
			role = SignalingRoleOrigin
		case i == len(nodes)-1 && complete:
			role = SignalingRoleDestination
		}
		h := SignalingHop{Address: addr, Role: role}
		if info, ok := c.hopHeaders[addr]; ok {
			h.UserAgent = info.UserAgent
			h.Server = info.Server
		}
		hops[i] = h
	}
	return hops, complete
}

// signalingChain walks the forward INVITE graph from the dialog-initiating
// INVITE's sender, following each node's single outgoing hop when there is
// only one. A node with more than one distinct INVITE target observed is a
// SIP fork (parallel or serial retry to a different next hop): signalingChain
// prefers whichever branch's own chain actually reaches the address that
// produced this call's outcome (the final response's sender — see
// resolveFork), and stops at the fork — reporting only the prefix confirmed
// so far, with complete=false — when that can't be determined uniquely. This
// is what keeps a fork from ever asserting a false linear "destination": see
// buildSignalingPath's caller for how complete=false downgrades the last
// hop's role from destination to intermediary.
func signalingChain(c *Call) (nodes []string, complete bool) {
	adjacency := map[string][]string{}
	origin := ""
	for _, e := range c.Timeline {
		if e.Summary != "INVITE" || e.Retransmission {
			continue
		}
		if origin == "" {
			origin = e.Src
		}
		adjacency[e.Src] = append(adjacency[e.Src], e.Dst)
	}
	if origin == "" {
		return nil, false
	}

	resolveAddr := c.failureOriginAddr
	if resolveAddr == "" {
		resolveAddr = c.establishedByAddr
	}

	nodes = []string{origin}
	visited := map[string]bool{origin: true}
	cur := origin
	complete = true
	for {
		outs := adjacency[cur]
		if len(outs) == 0 {
			break // cur is a leaf: either the true destination, or the last confirmed point of an incomplete chain
		}
		next := outs[0]
		if len(outs) > 1 {
			chosen, ok := resolveFork(adjacency, outs, resolveAddr)
			if !ok {
				complete = false
				break
			}
			next = chosen
		}
		if visited[next] {
			// A cycle isn't a valid SIP forwarding chain — stop rather than
			// loop forever or fabricate an ordering.
			complete = false
			break
		}
		nodes = append(nodes, next)
		visited[next] = true
		cur = next
	}
	return nodes, complete
}

// resolveFork picks the one branch out of a fork whose own forward chain
// reaches resolveAddr (the address that produced the call's final outcome —
// see §7's FailureOrigin, or the party whose 200 OK established the call).
// Returns ok=false — genuinely ambiguous, never guessed — when resolveAddr
// is empty (no outcome recorded yet) or more than one branch could reach it.
func resolveFork(adjacency map[string][]string, outs []string, resolveAddr string) (string, bool) {
	if resolveAddr == "" {
		return "", false
	}
	match, found := "", 0
	for _, o := range outs {
		if o == resolveAddr || reachesAddr(adjacency, o, resolveAddr, map[string]bool{}) {
			match = o
			found++
		}
	}
	if found == 1 {
		return match, true
	}
	return "", false
}

// reachesAddr reports whether target is reachable from from by following
// recorded forward-INVITE edges, guarding against cycles with seen.
func reachesAddr(adjacency map[string][]string, from, target string, seen map[string]bool) bool {
	if from == target {
		return true
	}
	if seen[from] {
		return false
	}
	seen[from] = true
	for _, next := range adjacency[from] {
		if reachesAddr(adjacency, next, target, seen) {
			return true
		}
	}
	return false
}
