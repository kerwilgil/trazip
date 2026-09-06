package portscan

import "sort"

// services maps common TCP ports to a service label used for evidence-based
// identification (never an absolute claim).
var services = map[int]string{
	7: "echo", 19: "chargen", 20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet",
	25: "smtp", 26: "rsftp", 37: "time", 53: "dns", 79: "finger", 80: "http",
	81: "hosts2-ns", 88: "kerberos", 106: "pop3pw", 110: "pop3", 111: "rpcbind",
	113: "ident", 119: "nntp", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
	144: "news", 179: "bgp", 199: "smux", 389: "ldap", 427: "svrloc",
	443: "https", 444: "snpp", 445: "microsoft-ds", 465: "smtps", 513: "login",
	514: "shell", 515: "printer", 543: "klogin", 544: "kshell", 548: "afp",
	554: "rtsp", 587: "submission", 631: "ipp", 646: "ldp", 873: "rsync",
	990: "ftps", 993: "imaps", 995: "pop3s", 1025: "NFS-or-IIS", 1026: "LSA",
	1027: "IIS", 1080: "socks", 1110: "nfsd-status", 1433: "ms-sql-s",
	1521: "oracle", 1720: "h323q931", 1723: "pptp", 1755: "wms", 1900: "upnp",
	2000: "cisco-sccp", 2001: "dc", 2049: "nfs", 2121: "ccproxy-ftp",
	2717: "pn-requester", 3000: "ppp", 3128: "squid-http", 3306: "mysql",
	3389: "ms-wbt-server", 3986: "mapper-ws_ethd", 4899: "radmin", 5000: "upnp",
	5009: "airport-admin", 5051: "ida-agent", 5060: "sip", 5101: "admdog",
	5190: "aol", 5357: "wsdapi", 5432: "postgresql", 5631: "pcanywheredata",
	5666: "nrpe", 5800: "vnc-http", 5900: "vnc", 5985: "wsman", 6000: "x11",
	6001: "x11-1", 6379: "redis", 6646: "unknown", 7070: "realserver",
	8000: "http-alt", 8008: "http", 8009: "ajp13", 8080: "http-proxy",
	8081: "blackice-icecap", 8443: "https-alt", 8888: "sun-answerbook",
	9100: "jetdirect", 9200: "elasticsearch", 9999: "abyss", 10000: "snet-sensor-mgmt",
	11211: "memcache", 27017: "mongodb", 32768: "filenet-tms", 49152: "unknown",
}

// ServiceName returns a best-effort label for a port, or "" if unknown.
func ServiceName(port int) string {
	return services[port]
}

// Top100 returns the ~100 most common TCP ports, sorted ascending.
func Top100() []int {
	out := make([]int, 0, len(services))
	for p := range services {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// Quick returns a small set of high-value infrastructure and application
// ports for a low-impact first pass.
func Quick() []int {
	return []int{21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 179, 389, 443, 445, 554, 587, 993, 995, 1433, 3306, 3389, 5060, 5432, 5900, 8080}
}

// Extended returns TCP ports 1-1000. The name is deliberately not "Top1000":
// this is a contiguous audit range, not a popularity ranking.
func Extended() []int { return ParseRange(1, 1000) }

// ParseRange expands "lo-hi" or a single port. Returns nil on invalid input.
func ParseRange(lo, hi int) []int {
	if lo <= 0 || hi <= 0 || hi < lo || hi > 65535 {
		return nil
	}
	out := make([]int, 0, hi-lo+1)
	for p := lo; p <= hi; p++ {
		out = append(out, p)
	}
	return out
}
