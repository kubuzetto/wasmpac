package pkg

import (
	"context"
	"errors"
	"fmt"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/sys"
	"io"
	"math"
	"net/url"
	"strings"
)

// Funcs is the list of imported functions implemented in the Go side.
type Funcs struct {
	DNSResolver func(string) (string, error)
	MyIPAddr    func() (string, error)

	RandSource         io.Reader
	Nanosleep          sys.Nanosleep
	Nanotime           sys.Nanotime
	NanotimeResolution sys.ClockResolution
	Walltime           sys.Walltime
	WalltimeResolution sys.ClockResolution
}

// Evaluator is the interface for the PAC script evaluation.
type Evaluator interface {
	Eval(ctx context.Context, pacScript, urlStr string) (res string, err error)
}

// eval implements the Evaluator interface.
type eval struct {
	mod   []byte
	funcs Funcs
}

// New creates an Evaluator with the default
// implementations of DNSResolver and MyIPAddr.
func New(mod []byte) Evaluator {
	return NewWithFuncs(mod, DefaultFuncs)
}

// NewWithFuncs creates an Evaluator with the given functions.
func NewWithFuncs(mod []byte, f Funcs) Evaluator {
	return &eval{mod: mod, funcs: f}
}

func (e *eval) Eval(ctx context.Context, pacScript, urlStr string) (res string, err error) {
	defer func() {
		if p := recover(); p != nil {
			res, err = "", fmt.Errorf("panic recovered: %v", p)
		}
	}()
	// now that we can catch panics, eval
	res, err = e.evalSafe(ctx, pacScript, urlStr)
	return
}

func (e *eval) evalSafe(ctx context.Context, pacScript, urlStr string) (string, error) {
	// FindProxyForURL(url, host) needs a url and a host. The host parameter
	// is there simply for convenience; it's the hostname part of the url.
	u, err := url.Parse(urlStr)
	if err != nil {
		return "", err
	}
	host := u.Hostname()
	// We create a new wazero runtime, without AOT
	r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigInterpreter())
	defer func() { _ = r.Close(ctx) }()
	// now we want to initiate the modules and memory management
	mod, memory, err := e.initModules(ctx, r)
	if err != nil {
		return "", err
	}
	// we clean all allocations at the end of eval; it's simpler
	defer memory.clean(ctx)
	// now we can invoke the eval_pac function from the module
	return callEvalPAC(ctx, mod, &memory, pacScript, urlStr, host)
}

func (e *eval) initModules(ctx context.Context, r wazero.Runtime) (mod api.Module, memory memtrack, err error) {
	// first of all; we want the dns_resolve and my_ip_addr functions exposed from the env module.
	if _, err = r.NewHostModuleBuilder("env").NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, offset, length uint32) (ret uint64) {
			// read the input string from the memory
			if bytes, ok := m.Memory().Read(offset, length); ok {
				// invoke the Go function
				result, resErr := e.funcs.DNSResolver(string(bytes))
				// allocate and return the result pointer as an u64
				ret = memory.allocRet(ctx, result, resErr)
			}
			return
		}).Export("dns_resolve").NewFunctionBuilder().
		WithFunc(func(ctx context.Context, _ api.Module) uint64 {
			// no input params here; simply invoke the function
			result, resErr := e.funcs.MyIPAddr()
			// then return the result pointer as an u64
			return memory.allocRet(ctx, result, resErr)
		}).Export("my_ip_addr").Instantiate(ctx); err == nil {
		// boa_engine requires a wasm32_wasi target; so we also need to instantiate WASI here
		if _, err = wasi_snapshot_preview1.Instantiate(ctx, r); err == nil {
			// if that's successful as well; we instantiate the module now.
			// note that we expose a rand source and system time here.
			// both may have security implications.
			if mod, err = r.InstantiateWithConfig(ctx, e.mod, wazero.NewModuleConfig().
				WithRandSource(e.funcs.RandSource).
				WithNanosleep(e.funcs.Nanosleep).
				WithNanotime(e.funcs.Nanotime, e.funcs.NanotimeResolution).
				WithWalltime(e.funcs.Walltime, e.funcs.WalltimeResolution),
			); err == nil {
				// tell our memory struct to use this module instance
				// for alloc/dealloc operations and memory read/write.
				// this can fail if alloc/dealloc cannot be found.
				err = memory.setModule(mod)
			}
		}
	}
	return
}

func callEvalPAC(ctx context.Context, mod api.Module, a *memtrack, pac, urlstr, host string) (string, error) {
	// first, find the function in the module
	evalPAC := mod.ExportedFunction("eval_pac")
	if evalPAC == nil {
		return "", errors.New("missing eval_pac function in the module")
	}
	// for eval_pac we should allocate 3 strings:
	// the script source, url and host strings.
	srcPtr, srcLen := a.allocStr(ctx, pac)
	urlPtr, urlLen := a.allocStr(ctx, urlstr)
	hstPtr, hstLen := a.allocStr(ctx, host)
	// pass all 6 integer inputs to the eval_pac function
	results, err := evalPAC.Call(ctx, srcPtr, srcLen, urlPtr, urlLen, hstPtr, hstLen)
	if err != nil {
		return "", err
	}
	// this shouldn't happen, but anyway
	if len(results) == 0 {
		return "", errors.New("no result returned")
	}
	// the result is an u64; the higher half is an offset of
	// the result string, and the lower half is the length.
	res := results[0]
	offset, length := uint32(res>>32), uint32(res&math.MaxUint32)
	// return early if an empty string is returned
	if offset == 0 || length == 0 {
		return "", nil
	}
	// the Rust side uses mem::forget for this string; so we should free it at the end
	a.record(uint64(offset), uint64(length))
	// read the corresponding memory
	out, ok := a.mod.Memory().Read(offset, length)
	if !ok {
		return "", errors.New("cannot read result")
	}
	// lazily we prefix the output string with !! to denote errors,
	// so if we have this prefix treat the output as an error message.
	if errMsg, isErr := strings.CutPrefix(string(out), "!!"); isErr {
		return "", errors.New(errMsg)
	}
	// otherwise the output string is returned
	return string(out), nil
}
