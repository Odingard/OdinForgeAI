package implant

import (
	"context"
	"testing"
)

// stubHandler implements CommandHandler for testing
type stubHandler struct {
	name   string
	result Result
	err    error
}

func (s *stubHandler) Name() string { return s.name }
func (s *stubHandler) Handle(_ context.Context, _ map[string]interface{}) (Result, error) {
	return s.result, s.err
}

func TestDispatcherRegisterAndExecute(t *testing.T) {
	d := NewDispatcher()
	h := &stubHandler{name: "test_cmd", result: Result{Status: "ok"}}
	d.Register("test_cmd", h)

	if !d.HasHandler("test_cmd") {
		t.Fatal("expected handler to be registered")
	}

	r := d.Execute(context.Background(), "test_cmd", nil)
	if r.Status != "ok" {
		t.Fatalf("expected status 'ok', got %q", r.Status)
	}
}

func TestDispatcherUnknownCommand(t *testing.T) {
	d := NewDispatcher()
	r := d.Execute(context.Background(), "nonexistent", nil)
	if r.Status != "error" {
		t.Fatalf("expected status 'error' for unknown command, got %q", r.Status)
	}
}

func TestDispatcherRegisteredReturnsAll(t *testing.T) {
	d := NewDispatcher()
	d.Register("alpha", &stubHandler{name: "alpha"})
	d.Register("beta", &stubHandler{name: "beta"})

	names := d.Registered()
	if len(names) != 2 {
		t.Fatalf("expected 2 registered handlers, got %d", len(names))
	}

	found := map[string]bool{}
	for _, n := range names {
		found[n] = true
	}
	if !found["alpha"] || !found["beta"] {
		t.Fatalf("expected alpha and beta, got %v", names)
	}
}

func TestDispatcherExecuteSetsTimingFields(t *testing.T) {
	d := NewDispatcher()
	d.Register("timing", &stubHandler{name: "timing", result: Result{Status: "ok"}})

	r := d.Execute(context.Background(), "timing", nil)
	if r.StartedAt == "" {
		t.Fatal("expected StartedAt to be set")
	}
	if r.Duration < 0 {
		t.Fatal("expected non-negative duration")
	}
}
