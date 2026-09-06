package monitor

import "testing"

func TestRunDeterministicRouteChangeSelfTestTransientNeverConfirms(t *testing.T) {
	res := RunDeterministicRouteChangeSelfTest()
	if res.TransientConfirmed {
		t.Error("TransientConfirmed = true, want false for a single divergent sample followed by a revert")
	}
}

func TestRunDeterministicRouteChangeSelfTestPersistentConfirmsExactlyOnce(t *testing.T) {
	res := RunDeterministicRouteChangeSelfTest()
	if res.PersistentChangeCount != 1 {
		t.Fatalf("PersistentChangeCount = %d, want exactly 1", res.PersistentChangeCount)
	}
	if res.PersistentChange == nil {
		t.Fatal("PersistentChange is nil despite PersistentChangeCount == 1")
	}
	if res.PersistentChange.FirstChangedTTL != 2 {
		t.Errorf("FirstChangedTTL = %d, want 2", res.PersistentChange.FirstChangedTTL)
	}
	if !res.PersistentChange.Persistent {
		t.Error("Persistent = false, want true for a confirmed RouteChange")
	}
}

func TestRunDeterministicRouteChangeSelfTestIsDeterministic(t *testing.T) {
	a := RunDeterministicRouteChangeSelfTest()
	b := RunDeterministicRouteChangeSelfTest()
	if a.TransientConfirmed != b.TransientConfirmed || a.PersistentChangeCount != b.PersistentChangeCount {
		t.Fatal("two independent runs produced different results — fixture must be deterministic")
	}
	if a.PersistentChange == nil || b.PersistentChange == nil {
		t.Fatal("PersistentChange missing on a deterministic run")
	}
	if a.PersistentChange.FirstChangedTTL != b.PersistentChange.FirstChangedTTL ||
		a.PersistentChange.DetectedAt != b.PersistentChange.DetectedAt {
		t.Error("two independent runs produced different RouteChange fixtures")
	}
}
