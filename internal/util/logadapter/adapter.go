package logadapter

import (
	"fmt"
	"log"
	"log/slog"
)

// *log.Logger-like interface.
// Preserves structured context by emitting the formatted message as the
// "msg" while attempting to parse key=value pairs appended in Printf calls
// (not rigorous—kept minimal intentionally).
type LoggerAdapter struct {
	l *slog.Logger
}

func New(base *slog.Logger) *log.Logger {
	// Return a *log.Logger whose output writes through the adapter's Printf implementation.
	// Simpler: implement Write and use log.New with that writer.
	adapter := &writer{logger: base}
	std := log.New(adapter, "", 0)
	return std
}

type writer struct {
	logger *slog.Logger
}

func (w *writer) Write(p []byte) (int, error) {
	// Trim newline; keep raw as message.
	msg := string(p)
	if len(msg) > 0 && msg[len(msg)-1] == '\n' {
		msg = msg[:len(msg)-1]
	}
	w.logger.Info(msg)
	return len(p), nil
}

func (a *LoggerAdapter) Printf(format string, args ...any) { a.l.Info(fmt.Sprintf(format, args...)) }
func (a *LoggerAdapter) Println(v ...any)                  { a.l.Info(fmt.Sprint(v...)) }
func (a *LoggerAdapter) Fatalf(format string, args ...any) {
	a.l.Error(fmt.Sprintf(format, args...))
	panic("fatal")
}
