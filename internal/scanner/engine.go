package scanner

import (
	"context"
	"fmt"
	"io"
	"os"
)

type Engine struct {
	modules []Module
	ErrLog  io.Writer
}

func NewEngine() *Engine {
	return &Engine{ErrLog: os.Stderr}
}

func (e *Engine) Register(m Module) {
	e.modules = append(e.modules, m)
}

func (e *Engine) ModuleNames() []string {
	names := make([]string, len(e.modules))
	for i, m := range e.modules {
		names[i] = m.Name()
	}
	return names
}

func (e *Engine) Scan(ctx context.Context, sc ScanContext) (Report, error) {
	return e.scanModules(ctx, sc, nil)
}

func (e *Engine) ScanModules(ctx context.Context, sc ScanContext, only []string) (Report, error) {
	return e.scanModules(ctx, sc, only)
}

func (e *Engine) scanModules(ctx context.Context, sc ScanContext, only []string) (Report, error) {
	allowed := make(map[string]bool)
	for _, name := range only {
		allowed[name] = true
	}

	var report Report
	for _, m := range e.modules {
		if len(only) > 0 && !allowed[m.Name()] {
			continue
		}
		findings, err := m.Scan(ctx, sc)
		if err != nil {
			fmt.Fprintf(e.ErrLog, "git-protect: module %s error: %v\n", m.Name(), err)
			continue
		}
		report.Findings = append(report.Findings, findings...)
	}
	return report, nil
}
