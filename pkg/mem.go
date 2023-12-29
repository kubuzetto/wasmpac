package pkg

import (
	"context"
	"errors"
	"github.com/tetratelabs/wazero/api"
)

type allocation struct{ offset, length uint64 }

type memtrack struct {
	mod            api.Module
	allocate, free api.Function
	allocs         []allocation
}

func (m *memtrack) setModule(mod api.Module) error {
	m.mod = mod
	if m.allocate = mod.ExportedFunction("reserve"); m.allocate == nil {
		return errors.New("missing reserve function in the module")
	}
	if m.free = mod.ExportedFunction("release"); m.free == nil {
		return errors.New("missing release function in the module")
	}
	return nil
}

func (m *memtrack) allocRet(ctx context.Context, output string, err error) uint64 {
	if err != nil {
		// for the error case; we simply return an empty
		// string, which is converted to null on the Rust side.
		// With a logger or a tracer, we might consider
		// printing this error message here.
		return 0
	}
	// proper output string; allocate it
	offset, length := m.allocStr(ctx, output)
	// return it in a single u64; with the higher half as offset and the lower as length
	return offset<<32 | length
}

func (m *memtrack) record(offset, length uint64) {
	m.allocs = append(m.allocs, allocation{offset: offset, length: length})
}

func (m *memtrack) allocStr(ctx context.Context, str string) (uint64, uint64) {
	// if length is 0 don't try to allocate
	if length := uint64(len(str)); length != 0 {
		// if allocation fails; return empty string
		if results, err := m.allocate.Call(ctx, length); err == nil && len(results) != 0 {
			offset := results[0]
			// track the offset for deallocation, and write the data in the memory
			m.record(offset, length)
			m.mod.Memory().Write(uint32(offset), []byte(str))
			return offset, length
		}
	}
	return 0, 0
}

func (m *memtrack) clean(ctx context.Context) {
	if m.free != nil {
		for _, a := range m.allocs {
			// we should print dealloc. errors here, but it's
			// not critical as we're unloading the module anyway.
			_, _ = m.free.Call(ctx, a.offset, a.length)
		}
	}
}
