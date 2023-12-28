package pkg

import (
	"context"
	"github.com/tetratelabs/wazero/api"
)

type mem struct{ p, l uint64 }

type memtrack struct {
	mod            api.Module
	allocate, free api.Function
	allocs         []mem
}

func (m *memtrack) setMod(mod api.Module) {
	m.mod = mod
	m.allocate = mod.ExportedFunction("reserve")
	m.free = mod.ExportedFunction("release")
}

func (m *memtrack) allocRet(ctx context.Context, s string, e error) uint64 {
	if e != nil {
		return 0
	}
	p, l := m.allocStr(ctx, s)
	return p<<32 | l
}

func (m *memtrack) allocStr(ctx context.Context, s string) (uint64, uint64) {
	if l := uint64(len(s)); l != 0 {
		if results, err := m.allocate.Call(ctx, l); err == nil && len(results) != 0 {
			p := results[0]
			if p != 0 {
				m.allocs = append(m.allocs, mem{p: p, l: l})
				m.mod.Memory().Write(uint32(p), []byte(s))
			}
			return p, l
		}
	}
	return 0, 0
}

func (m *memtrack) clean(ctx context.Context) {
	if m.free != nil {
		for _, a := range m.allocs {
			_, _ = m.free.Call(ctx, a.p, a.l)
		}
	}
}
