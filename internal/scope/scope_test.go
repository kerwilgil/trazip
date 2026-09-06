package scope

import "testing"

func TestCheckTargetRequiresAuthorization(t *testing.T) {
	g := NewGuard()
	if err := g.CheckTarget("192.0.2.1"); err == nil {
		t.Fatal("expected unauthorized target to be rejected")
	}
}

func TestCheckTargetAcceptsOnlyDeclaredTarget(t *testing.T) {
	g := NewGuard()
	if err := g.Authorize("test", []string{"192.0.2.1", "example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := g.CheckTarget("192.0.2.1"); err != nil {
		t.Fatalf("declared IP rejected: %v", err)
	}
	if err := g.CheckTarget("EXAMPLE.COM"); err != nil {
		t.Fatalf("declared host rejected: %v", err)
	}
	if err := g.CheckTarget("192.0.2.2"); err == nil {
		t.Fatal("undeclared IP accepted")
	}
}

// TestCheckTargetAcceptsItsOwnCIDR reproduces the LAN scanner's exact
// pattern (session.BeginActive authorizes a CIDR range, then immediately
// self-checks that same range) — a freshly authorized CIDR must pass its
// own check; before the fix, CheckTarget only tried ParseAddr/CheckHost, so
// a CIDR (which ParseAddr rejects) always fell through to CheckHost and was
// wrongly reported as out of scope.
func TestCheckTargetAcceptsItsOwnCIDR(t *testing.T) {
	g := NewGuard()
	if err := g.Authorize("lanscan", []string{"10.101.0.0/22"}); err != nil {
		t.Fatal(err)
	}
	if err := g.CheckTarget("10.101.0.0/22"); err != nil {
		t.Fatalf("freshly authorized CIDR rejected by its own self-check: %v", err)
	}
}

func TestCheckTargetCIDRWithinBroaderPrefix(t *testing.T) {
	g := NewGuard()
	if err := g.Authorize("lanscan", []string{"10.0.0.0/8"}); err != nil {
		t.Fatal(err)
	}
	if err := g.CheckTarget("10.101.0.0/22"); err != nil {
		t.Fatalf("narrower CIDR within an authorized broader prefix rejected: %v", err)
	}
}

func TestCheckTargetRejectsUnrelatedCIDR(t *testing.T) {
	g := NewGuard()
	if err := g.Authorize("lanscan", []string{"10.101.0.0/22"}); err != nil {
		t.Fatal(err)
	}
	if err := g.CheckTarget("192.168.1.0/24"); err == nil {
		t.Fatal("expected an unrelated CIDR to be rejected")
	}
}
