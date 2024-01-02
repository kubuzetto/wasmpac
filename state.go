package wasmpac

import (
	"context"
	"log/slog"

	"github.com/tetratelabs/wazero/api"
)

type allocation struct{ offset, length uint32 }

type state struct {
	mod    api.Module
	allocs []allocation
	logger *slog.Logger

	eval, allocate, free api.Function
}

// record stores the offset-length pair for future deallocation
func (s *state) record(offset, length uint32) {
	s.allocs = append(s.allocs, allocation{offset: offset, length: length})
}

// allocStrAsU64 allocates and writes a string in the wasm memory.
// it returns the offset and length of the memory encoded in a single u64.
// the string is not null-terminated.
func (s *state) allocStrAsU64(ctx context.Context, str string) uint64 {
	offset, length := s.allocStr(ctx, str)
	return uint64(offset)<<32 | uint64(length)
}

// allocStr allocates and writes a string in the wasm memory.
// it returns the offset and the length of the memory range.
// the string is not null-terminated.
func (s *state) allocStr(ctx context.Context, str string) (uint32, uint32) {
	// if length is 0 don't try to allocate
	length := uint32(len(str))
	if length == 0 {
		return 0, 0
	}
	results, err := s.allocate.Call(ctx, uint64(length))
	// if allocation fails; return empty string
	if err != nil {
		if s.logger != nil {
			s.logger.ErrorContext(ctx, "allocation failed",
				"length", length, "error", err)
		}
		return 0, 0
	}
	if len(results) == 0 {
		if s.logger != nil {
			s.logger.ErrorContext(ctx, "no results returned", "function", "reserve")
		}
		return 0, 0
	}
	offset := uint32(results[0])
	// track the offset for deallocation, and write the data in the memory
	s.record(offset, length)
	// now write the data to the wasm memory
	if !s.mod.Memory().Write(offset, []byte(str)) {
		if s.logger != nil {
			s.logger.ErrorContext(ctx, "cannot write to wasm memory",
				"offset", offset, "length", length)
		}
		return 0, 0
	}
	return offset, length
}

// clean iterates allocation records and frees all memory allocations
func (s *state) cleanAllocs(ctx context.Context) {
	for _, a := range s.allocs {
		if _, err := s.free.Call(ctx, uint64(a.offset), uint64(a.length)); err != nil && s.logger != nil {
			s.logger.WarnContext(ctx, "Cannot free wasm memory",
				"offset", a.offset, "length", a.length, "error", err)
		}
	}
}
