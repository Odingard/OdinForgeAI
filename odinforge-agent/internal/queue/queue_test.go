package queue

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"odinforge-agent/internal/collector"
)

func tempQueue(t *testing.T) (*BoltQueue, func()) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	q, err := NewBoltQueue(path, 1000)
	if err != nil {
		t.Fatalf("failed to create queue: %v", err)
	}
	return q, func() {
		q.Close()
		os.RemoveAll(dir)
	}
}

func TestEnqueueDequeue(t *testing.T) {
	q, cleanup := tempQueue(t)
	defer cleanup()

	ev := collector.Event{
		ID:           "ev_test123",
		Type:         "telemetry",
		SchemaVer:    1,
		AgentID:      "agent_abc",
		TimestampUTC: time.Now(),
		Payload:      map[string]interface{}{"cpu": 42.0},
	}

	if err := q.Enqueue(ev); err != nil {
		t.Fatalf("enqueue failed: %v", err)
	}

	depth, err := q.Depth()
	if err != nil {
		t.Fatalf("depth failed: %v", err)
	}
	if depth != 1 {
		t.Fatalf("expected depth 1, got %d", depth)
	}

	items, err := q.DequeueBatch(10)
	if err != nil {
		t.Fatalf("dequeue failed: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
}

func TestEmptyDequeue(t *testing.T) {
	q, cleanup := tempQueue(t)
	defer cleanup()

	items, err := q.DequeueBatch(10)
	if err != nil {
		t.Fatalf("dequeue failed: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("expected 0 items from empty queue, got %d", len(items))
	}
}

func TestDepthEmptyQueue(t *testing.T) {
	q, cleanup := tempQueue(t)
	defer cleanup()

	depth, err := q.Depth()
	if err != nil {
		t.Fatalf("depth failed: %v", err)
	}
	if depth != 0 {
		t.Fatalf("expected depth 0, got %d", depth)
	}
}
