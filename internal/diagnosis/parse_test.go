package diagnosis

import "testing"

func TestParseTargetIP(t *testing.T) {
	rt := parseTarget("8.8.8.8")
	if rt.kind != "ip" || !rt.isDirect || rt.host != "8.8.8.8" {
		t.Fatalf("parseTarget(8.8.8.8) = %+v", rt)
	}
}

func TestParseTargetHost(t *testing.T) {
	rt := parseTarget("example.com")
	if rt.kind != "host" || rt.isDirect || rt.host != "example.com" {
		t.Fatalf("parseTarget(example.com) = %+v", rt)
	}
}

func TestParseTargetURL(t *testing.T) {
	rt := parseTarget("https://example.com/path?x=1")
	if rt.kind != "url" || rt.isDirect || rt.host != "example.com" || rt.rawURL != "https://example.com/path?x=1" {
		t.Fatalf("parseTarget(url) = %+v", rt)
	}
}

func TestParseTargetURLWithIPHost(t *testing.T) {
	rt := parseTarget("http://203.0.113.5:8080/")
	if rt.kind != "url" || !rt.isDirect || rt.host != "203.0.113.5" {
		t.Fatalf("parseTarget(url with IP host) = %+v, want kind=url isDirect=true host=203.0.113.5", rt)
	}
}

func TestParseTargetTrimsWhitespace(t *testing.T) {
	rt := parseTarget("  8.8.8.8  ")
	if !rt.isDirect || rt.host != "8.8.8.8" {
		t.Fatalf("parseTarget with whitespace = %+v", rt)
	}
}
