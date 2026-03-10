package collector

import (
	"strings"
	"testing"
)

func TestNewEventIDUniqueness(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id := NewEventID()
		if seen[id] {
			t.Fatalf("duplicate event ID: %s", id)
		}
		seen[id] = true
	}
}

func TestNewEventIDFormat(t *testing.T) {
	id := NewEventID()
	if !strings.HasPrefix(id, "ev_") {
		t.Fatalf("expected event ID to start with 'ev_', got %q", id)
	}
	// "ev_" prefix + hex chars
	if len(id) < 10 {
		t.Fatalf("expected event ID to be at least 10 chars, got %d (%q)", len(id), id)
	}
}

func TestStableAgentIDPrefix(t *testing.T) {
	id := StableAgentID()
	if !strings.HasPrefix(id, "agent_") {
		t.Fatalf("expected agent ID to start with 'agent_', got %q", id)
	}
}

func TestStableAgentIDDeterministic(t *testing.T) {
	id1 := StableAgentID()
	id2 := StableAgentID()
	if id1 != id2 {
		t.Fatalf("StableAgentID should be deterministic: %q != %q", id1, id2)
	}
}
