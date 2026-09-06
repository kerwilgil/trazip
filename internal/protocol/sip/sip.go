// Package sip is a stateless SIP (RFC 3261) message parser. It never sends
// traffic; it only decodes what TRAZIP observes in captured/PCAP packets
// (prompt maestro §9 Fase 3 #13). Dialog/transaction tracking and retransmission
// detection are stateful concerns owned by internal/voip, which correlates many
// parsed Messages over time — this package only turns one payload into one
// Message.
package sip

import (
	"strconv"
	"strings"
)

// Message is one parsed SIP request or response.
type Message struct {
	IsRequest   bool
	Method      string // request method, or the CSeq method for responses
	RequestURI  string
	StatusCode  int    // 0 for requests
	Reason      string // reason phrase for responses
	CallID      string
	From        string
	FromTag     string
	To          string
	ToTag       string
	CSeqNum     int
	CSeqMethod  string
	ViaBranch   string // topmost Via branch (transaction id per RFC 3261)
	ViaProto    string // UDP | TCP | TLS
	Contact     string
	ContentType string
	Challenged  bool   // WWW-Authenticate/Proxy-Authenticate present
	AuthRealm   string // realm= from the challenge, metadata only (no secrets)
	Authorized  bool   // Authorization/Proxy-Authorization present (request had credentials)
	Body        []byte
	Headers     map[string]string // canonical lowercase name -> raw value (first occurrence)
}

// compactHeaders maps SIP compact header forms to their canonical full name.
var compactHeaders = map[string]string{
	"v": "via", "f": "from", "t": "to", "i": "call-id", "m": "contact",
	"l": "content-length", "c": "content-type", "s": "subject", "k": "supported",
}

// methods recognized as a valid start-line token for a request.
var methods = map[string]bool{
	"INVITE": true, "ACK": true, "BYE": true, "CANCEL": true, "OPTIONS": true,
	"REGISTER": true, "REFER": true, "NOTIFY": true, "SUBSCRIBE": true,
	"PRACK": true, "INFO": true, "UPDATE": true, "MESSAGE": true, "PUBLISH": true,
}

// LooksLikeSIP does a cheap heuristic check before attempting a full Parse.
func LooksLikeSIP(payload []byte) bool {
	line := firstLineOf(payload)
	if strings.HasPrefix(line, "SIP/2.0") {
		return true
	}
	sp := strings.IndexByte(line, ' ')
	if sp <= 0 {
		return false
	}
	return methods[line[:sp]] && strings.Contains(line, "SIP/2.0")
}

// Parse decodes a SIP message from a UDP/TCP payload. It is defensive: it never
// panics and returns an error for anything that doesn't look like SIP.
func Parse(payload []byte) (*Message, error) {
	text := string(payload)

	// Split headers from body on the raw byte offset of the blank line, so the
	// body keeps its exact original bytes (matters for SDP parsing downstream).
	headerText, body := text, ""
	if idx := strings.Index(text, "\r\n\r\n"); idx >= 0 {
		headerText, body = text[:idx], text[idx+4:]
	} else if idx := strings.Index(text, "\n\n"); idx >= 0 {
		headerText, body = text[:idx], text[idx+2:]
	}

	lines := splitLines(headerText)
	if len(lines) == 0 || lines[0] == "" {
		return nil, errNotSIP
	}

	m := &Message{Headers: make(map[string]string)}
	if err := parseStartLine(lines[0], m); err != nil {
		return nil, err
	}

	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		name, value, ok := splitHeader(line)
		if !ok {
			continue
		}
		if full, isCompact := compactHeaders[name]; isCompact {
			name = full
		}
		if _, exists := m.Headers[name]; !exists {
			m.Headers[name] = value
		}
	}

	if body != "" {
		m.Body = []byte(body)
	}

	applyHeaders(m)
	return m, nil
}

func parseStartLine(line string, m *Message) error {
	if strings.HasPrefix(line, "SIP/2.0 ") {
		rest := strings.TrimPrefix(line, "SIP/2.0 ")
		sp := strings.IndexByte(rest, ' ')
		codeStr := rest
		reason := ""
		if sp > 0 {
			codeStr, reason = rest[:sp], rest[sp+1:]
		}
		code, err := strconv.Atoi(strings.TrimSpace(codeStr))
		if err != nil {
			return errNotSIP
		}
		m.StatusCode = code
		m.Reason = strings.TrimSpace(reason)
		return nil
	}

	sp := strings.IndexByte(line, ' ')
	if sp <= 0 {
		return errNotSIP
	}
	method := line[:sp]
	if !methods[method] {
		return errNotSIP
	}
	rest := strings.TrimSpace(line[sp+1:])
	sp2 := strings.IndexByte(rest, ' ')
	uri := rest
	if sp2 > 0 {
		uri = rest[:sp2]
	}
	m.IsRequest = true
	m.Method = method
	m.RequestURI = uri
	return nil
}

func applyHeaders(m *Message) {
	m.CallID = strings.TrimSpace(m.Headers["call-id"])
	m.From, m.FromTag = parseNameAddr(m.Headers["from"])
	m.To, m.ToTag = parseNameAddr(m.Headers["to"])
	m.Contact = strings.TrimSpace(m.Headers["contact"])
	m.ContentType = strings.TrimSpace(strings.ToLower(m.Headers["content-type"]))

	if cseq, ok := m.Headers["cseq"]; ok {
		fields := strings.Fields(cseq)
		if len(fields) >= 1 {
			if n, err := strconv.Atoi(fields[0]); err == nil {
				m.CSeqNum = n
			}
		}
		if len(fields) >= 2 {
			m.CSeqMethod = fields[1]
		}
	}
	if !m.IsRequest {
		m.Method = m.CSeqMethod
	}

	if via, ok := m.Headers["via"]; ok {
		m.ViaProto = viaProto(via)
		m.ViaBranch = paramValue(via, "branch")
	}

	if _, ok := m.Headers["www-authenticate"]; ok {
		m.Challenged = true
		m.AuthRealm = paramValue(m.Headers["www-authenticate"], "realm")
	}
	if _, ok := m.Headers["proxy-authenticate"]; ok {
		m.Challenged = true
		if m.AuthRealm == "" {
			m.AuthRealm = paramValue(m.Headers["proxy-authenticate"], "realm")
		}
	}
	if _, ok := m.Headers["authorization"]; ok {
		m.Authorized = true
	}
	if _, ok := m.Headers["proxy-authorization"]; ok {
		m.Authorized = true
	}
}

// parseNameAddr extracts the address part and the ;tag= parameter from a
// From/To header value, e.g. `"Alice" <sip:alice@a.com>;tag=abc`.
func parseNameAddr(v string) (addr, tag string) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", ""
	}
	tag = paramValue(v, "tag")
	// Prefer the <...> URI if present; else take everything before the first ';'.
	if lt := strings.IndexByte(v, '<'); lt >= 0 {
		if gt := strings.IndexByte(v[lt:], '>'); gt > 0 {
			return v[lt+1 : lt+gt], tag
		}
	}
	if sc := strings.IndexByte(v, ';'); sc > 0 {
		return strings.TrimSpace(v[:sc]), tag
	}
	return v, tag
}

// paramValue extracts `name=value` from a `;`-separated parameter list found
// anywhere in a header value (handles optional quotes).
func paramValue(header, name string) string {
	parts := strings.Split(header, ";")
	prefix := name + "="
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(strings.ToLower(p), prefix) {
			v := strings.TrimSpace(p[len(prefix):])
			return strings.Trim(v, `"`)
		}
	}
	// Also check comma-separated auth-scheme params (WWW-Authenticate uses those).
	if idx := strings.Index(strings.ToLower(header), prefix); idx >= 0 {
		rest := header[idx+len(prefix):]
		rest = strings.TrimPrefix(rest, `"`)
		if end := strings.IndexAny(rest, `",`); end >= 0 {
			return rest[:end]
		}
	}
	return ""
}

func viaProto(via string) string {
	// "SIP/2.0/UDP host:port;..."
	fields := strings.Fields(via)
	if len(fields) == 0 {
		return ""
	}
	segs := strings.Split(fields[0], "/")
	if len(segs) >= 3 {
		return strings.ToUpper(segs[2])
	}
	return ""
}

func firstLineOf(b []byte) string {
	for i, c := range b {
		if c == '\n' {
			s := string(b[:i])
			return strings.TrimRight(s, "\r")
		}
	}
	return string(b)
}

func splitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.Split(s, "\n")
}

func splitHeader(line string) (name, value string, ok bool) {
	c := strings.IndexByte(line, ':')
	if c <= 0 {
		return "", "", false
	}
	return strings.ToLower(strings.TrimSpace(line[:c])), strings.TrimSpace(line[c+1:]), true
}

type sipError string

func (e sipError) Error() string { return string(e) }

const errNotSIP = sipError("no parece un mensaje SIP")
