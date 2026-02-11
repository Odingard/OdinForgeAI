package logger

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Level represents log severity
type Level int

const (
	DEBUG Level = iota
	INFO
	WARN
	ERROR
)

func (l Level) String() string {
	switch l {
	case DEBUG:
		return "debug"
	case INFO:
		return "info"
	case WARN:
		return "warn"
	case ERROR:
		return "error"
	default:
		return "unknown"
	}
}

// Entry is a structured log entry
type Entry struct {
	Timestamp string                 `json:"ts"`
	Level     string                 `json:"level"`
	Component string                 `json:"component,omitempty"`
	Message   string                 `json:"msg"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}

// Logger provides structured JSON logging
type Logger struct {
	mu        sync.Mutex
	out       io.Writer
	level     Level
	component string
}

var defaultLogger = &Logger{out: os.Stderr, level: INFO}

// Init sets up the global logger
func Init(level Level) {
	defaultLogger.mu.Lock()
	defer defaultLogger.mu.Unlock()
	defaultLogger.level = level
}

// WithComponent returns a component-scoped logger
func WithComponent(name string) *Logger {
	return &Logger{
		out:       defaultLogger.out,
		level:     defaultLogger.level,
		component: name,
	}
}

func (l *Logger) log(level Level, msg string, fields map[string]interface{}) {
	if level < l.level {
		return
	}

	entry := Entry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Level:     level.String(),
		Component: l.component,
		Message:   msg,
		Fields:    fields,
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	data, err := json.Marshal(entry)
	if err != nil {
		fmt.Fprintf(l.out, `{"ts":"%s","level":"error","msg":"log marshal failed: %v"}`+"\n",
			time.Now().UTC().Format(time.RFC3339), err)
		return
	}
	l.out.Write(data)
	l.out.Write([]byte("\n"))
}

func (l *Logger) Debug(msg string, kv ...interface{}) { l.log(DEBUG, msg, kvToMap(kv)) }
func (l *Logger) Info(msg string, kv ...interface{})  { l.log(INFO, msg, kvToMap(kv)) }
func (l *Logger) Warn(msg string, kv ...interface{})  { l.log(WARN, msg, kvToMap(kv)) }
func (l *Logger) Error(msg string, kv ...interface{}) { l.log(ERROR, msg, kvToMap(kv)) }

// Package-level functions use the default logger
func Debug(msg string, kv ...interface{}) { defaultLogger.log(DEBUG, msg, kvToMap(kv)) }
func Info(msg string, kv ...interface{})  { defaultLogger.log(INFO, msg, kvToMap(kv)) }
func Warn(msg string, kv ...interface{})  { defaultLogger.log(WARN, msg, kvToMap(kv)) }
func Error(msg string, kv ...interface{}) { defaultLogger.log(ERROR, msg, kvToMap(kv)) }

// kvToMap converts key-value pairs to a map
func kvToMap(kv []interface{}) map[string]interface{} {
	if len(kv) == 0 {
		return nil
	}
	m := make(map[string]interface{}, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		key, ok := kv[i].(string)
		if !ok {
			key = fmt.Sprintf("%v", kv[i])
		}
		m[key] = kv[i+1]
	}
	return m
}
