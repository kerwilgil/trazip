package bgp

import "testing"

func TestBoundedLRU_NeverExceedsCapacity(t *testing.T) {
	l := newBoundedLRU[string, int](5)
	for i := 0; i < 50; i++ {
		l.Set(itoaHelper(i), i)
		if l.Len() > 5 {
			t.Fatalf("Len() = %d after %d inserts, want <= 5", l.Len(), i+1)
		}
	}
	if l.Len() != 5 {
		t.Fatalf("Len() = %d, want exactly 5 after overflowing", l.Len())
	}
	if l.Evicted() != 45 {
		t.Fatalf("Evicted() = %d, want 45 (50 inserts - 5 capacity)", l.Evicted())
	}
}

func TestBoundedLRU_EvictsLeastRecentlyUsedDeterministically(t *testing.T) {
	l := newBoundedLRU[string, int](3)
	l.Set("a", 1)
	l.Set("b", 2)
	l.Set("c", 3)
	// Touch "a" so it becomes most-recently-used — "b" is now the oldest.
	if _, ok := l.Get("a"); !ok {
		t.Fatal("Get(a) missing")
	}
	l.Set("d", 4) // must evict "b", the least-recently-used
	if _, ok := l.Get("b"); ok {
		t.Error("b survived — want it evicted as the least-recently-used entry")
	}
	for _, k := range []string{"a", "c", "d"} {
		if _, ok := l.Get(k); !ok {
			t.Errorf("%s missing, want it still tracked", k)
		}
	}
	if l.Evicted() != 1 {
		t.Fatalf("Evicted() = %d, want 1", l.Evicted())
	}
}

func TestBoundedLRU_Delete_NeverCountsAsEviction(t *testing.T) {
	l := newBoundedLRU[string, int](5)
	l.Set("a", 1)
	l.Delete("a")
	if l.Len() != 0 {
		t.Fatalf("Len() = %d after Delete, want 0", l.Len())
	}
	if l.Evicted() != 0 {
		t.Errorf("Evicted() = %d after a plain Delete, want 0 (Delete is a real removal, never a capacity eviction)", l.Evicted())
	}
	if _, ok := l.Get("a"); ok {
		t.Error("a still present after Delete")
	}
}

func TestBoundedLRU_SetExistingKey_NeverEvicts(t *testing.T) {
	l := newBoundedLRU[string, int](3)
	l.Set("a", 1)
	l.Set("b", 2)
	l.Set("c", 3)
	l.Set("a", 100) // update, not a new entry — must never trigger eviction
	if l.Evicted() != 0 {
		t.Fatalf("Evicted() = %d after updating an existing key, want 0", l.Evicted())
	}
	if v, ok := l.Get("a"); !ok || v != 100 {
		t.Errorf("Get(a) = (%d, %v), want (100, true)", v, ok)
	}
	for _, k := range []string{"b", "c"} {
		if _, ok := l.Get(k); !ok {
			t.Errorf("%s missing after an unrelated Set-update", k)
		}
	}
}

func TestBoundedLRU_Range_VisitsAllTrackedEntries(t *testing.T) {
	l := newBoundedLRU[int, string](10)
	want := map[int]string{1: "a", 2: "b", 3: "c"}
	for k, v := range want {
		l.Set(k, v)
	}
	got := make(map[int]string)
	l.Range(func(k int, v string) { got[k] = v })
	if len(got) != len(want) {
		t.Fatalf("Range visited %d entries, want %d", len(got), len(want))
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("Range[%d] = %q, want %q", k, got[k], v)
		}
	}
}
