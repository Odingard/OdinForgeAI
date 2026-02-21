package implant

import (
	"context"
	"fmt"
	"time"

	"odinforge-agent/internal/logger"
)

var log = logger.WithComponent("implant")

// CommandHandler defines the interface for modular command execution.
// Each command type (probe, scan, checkin, etc.) implements this interface,
// allowing the dispatcher to route commands without a hardcoded switch.
type CommandHandler interface {
	Handle(ctx context.Context, payload map[string]interface{}) (Result, error)
	Name() string
}

// Result is the unified return type for all command handlers.
type Result struct {
	Status    string                 `json:"status"`
	Data      map[string]interface{} `json:"data,omitempty"`
	Error     string                 `json:"error,omitempty"`
	StartedAt string                 `json:"startedAt"`
	Duration  int64                  `json:"durationMs"`
}

// Dispatcher maintains a registry of CommandHandlers and routes
// incoming commands to the appropriate handler.
type Dispatcher struct {
	handlers map[string]CommandHandler
}

// NewDispatcher creates an empty dispatcher. Register handlers before use.
func NewDispatcher() *Dispatcher {
	return &Dispatcher{
		handlers: make(map[string]CommandHandler),
	}
}

// Register adds a handler for a given command type.
func (d *Dispatcher) Register(commandType string, handler CommandHandler) {
	d.handlers[commandType] = handler
	log.Info("registered command handler", "commandType", commandType, "handler", handler.Name())
}

// HasHandler returns true if a handler is registered for the command type.
func (d *Dispatcher) HasHandler(commandType string) bool {
	_, ok := d.handlers[commandType]
	return ok
}

// Registered returns the list of registered command types.
func (d *Dispatcher) Registered() []string {
	types := make([]string, 0, len(d.handlers))
	for k := range d.handlers {
		types = append(types, k)
	}
	return types
}

// Execute dispatches a command to its registered handler.
// Returns an error Result if no handler is registered for the command type.
func (d *Dispatcher) Execute(ctx context.Context, commandType string, payload map[string]interface{}) Result {
	start := time.Now()
	startStr := start.Format(time.RFC3339)

	handler, ok := d.handlers[commandType]
	if !ok {
		return Result{
			Status:    "error",
			Error:     fmt.Sprintf("unknown command type: %s", commandType),
			StartedAt: startStr,
			Duration:  time.Since(start).Milliseconds(),
		}
	}

	log.Info("dispatching command", "commandType", commandType, "handler", handler.Name())

	result, err := handler.Handle(ctx, payload)
	elapsed := time.Since(start).Milliseconds()

	if err != nil {
		log.Error("handler returned error", "commandType", commandType, "error", err.Error())
		return Result{
			Status:    "error",
			Error:     err.Error(),
			StartedAt: startStr,
			Duration:  elapsed,
		}
	}

	result.StartedAt = startStr
	result.Duration = elapsed
	return result
}
