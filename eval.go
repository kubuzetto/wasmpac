package wasmpac

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strings"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// The pac.wasm module is embedded here. To recompile
// the optimized wasm file, you can use build_mod.sh.

//go:embed pac.wasm
var wasmModuleData []byte

var (
	ErrURLParse       = errors.New("cannot parse url")
	ErrHostModuleInit = errors.New("cannot instantiate the host module")
	ErrWASIModuleInit = errors.New("cannot instantiate the WASI module")
	ErrPACModuleInit  = errors.New("cannot instantiate the PAC module")
	ErrPACEvaluation  = errors.New("cannot evaluate the PAC script")
)

func evalSafe(ctx context.Context, e *Evaluator, pacScript, urlStr string) (string, error) {
	// FindProxyForURL(url, host) needs a url and a host. The host parameter
	// is there simply for convenience; it's the hostname part of the url.
	u, err := url.Parse(urlStr)
	if err != nil {
		return "", wrapErr(ErrURLParse, err)
	}
	host := u.Hostname()
	// We create a new wazero runtime, without AOT
	r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigInterpreter())
	defer func() {
		if clsErr := r.Close(ctx); clsErr != nil && e.Logger != nil {
			e.Logger.WarnContext(ctx, "Cannot close wazero runtime", "error", clsErr)
		}
	}()
	// now we want to initiate the modules and memory management
	st, err := initState(ctx, e, r)
	if err != nil {
		return "", err
	}
	// we clean all allocations at the end of eval; it's simpler
	defer st.cleanAllocs(ctx)
	// now we can invoke the eval_pac function from the module
	result, err := callEvalPAC(ctx, st, pacScript, urlStr, host)
	if err != nil {
		return "", wrapErr(ErrPACEvaluation, err)
	}
	return result, nil
}

func initState(ctx context.Context, e *Evaluator, r wazero.Runtime) (*state, error) {
	st := state{logger: e.Logger}
	// first of all; we want the dns_resolve and my_ip_addr functions exposed from the env host module.
	if _, err := r.NewHostModuleBuilder("env").
		NewFunctionBuilder().WithFunc(wrapDNSResolver(e, &st)).Export("dns_resolve").
		NewFunctionBuilder().WithFunc(wrapMyIPAddress(e, &st)).Export("my_ip_addr").
		Instantiate(ctx); err != nil {
		return nil, wrapErr(ErrHostModuleInit, err)
	}
	// boa_engine requires a wasm32_wasi target; so we also need to instantiate WASI here
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, r); err != nil {
		return nil, wrapErr(ErrWASIModuleInit, err)
	}
	// if that's successful as well; we instantiate the module now.
	mod, err := r.InstantiateWithConfig(ctx, wasmModuleData, newModuleConfig(e))
	if err != nil {
		return nil, wrapErr(ErrPACModuleInit, err)
	}
	// tell our memory struct to use this module instance
	// for alloc/dealloc operations and memory read/write.
	// this can fail if alloc/dealloc cannot be found.
	if err = setModule(&st, mod); err != nil {
		return nil, wrapErr(ErrPACModuleInit, err)
	}
	return &st, nil
}

func setModule(s *state, mod api.Module) (err error) {
	s.mod = mod
	if s.eval, err = findFunction(mod, "eval_pac"); err == nil {
		if s.allocate, err = findFunction(mod, "reserve"); err == nil {
			s.free, err = findFunction(mod, "release")
		}
	}
	return
}

func findFunction(mod api.Module, name string) (f api.Function, err error) {
	if f = mod.ExportedFunction(name); f == nil {
		err = fmt.Errorf("missing %q function in the module", name)
	}
	return
}

func newModuleConfig(e *Evaluator) wazero.ModuleConfig {
	// note that we expose a rand source and system time here.
	// both may have security implications.
	return wazero.NewModuleConfig().
		WithRandSource(e.RandSource).
		WithNanosleep(e.Nanosleep).
		WithNanotime(e.Nanotime, e.NanotimeResolution).
		WithWalltime(e.Walltime, e.WalltimeResolution)
}

func wrapDNSResolver(e *Evaluator, st *state) func(context.Context, api.Module, uint32, uint32) uint64 {
	return func(ctx context.Context, m api.Module, offset, length uint32) uint64 {
		dnsResolver := DNSResolver
		if e.DNSResolver != nil {
			dnsResolver = e.DNSResolver
		}
		input, ok := m.Memory().Read(offset, length)
		if !ok {
			if l := st.logger; l != nil {
				l.ErrorContext(ctx, "Cannot read memory",
					"function", "dns_resolve", "offset", offset, "length", length)
			}
			return 0
		}
		result, err := dnsResolver(string(input))
		if err != nil {
			if l := st.logger; l != nil {
				l.WarnContext(ctx, "Function call failed",
					"function", "dns_resolve", "error", err)
			}
			return 0
		}
		return st.allocStrAsU64(ctx, result)
	}
}

func wrapMyIPAddress(e *Evaluator, st *state) func(context.Context, api.Module) uint64 {
	return func(ctx context.Context, _ api.Module) uint64 {
		myIPAddress := MyIPAddr
		if e.MyIPAddr != nil {
			myIPAddress = e.MyIPAddr
		}
		result, err := myIPAddress()
		if err != nil {
			if l := st.logger; l != nil {
				l.WarnContext(ctx, "Function call failed",
					"function", "my_ip_addr", "error", err)
			}
			return 0
		}
		return st.allocStrAsU64(ctx, result)
	}
}

func callEvalPAC(
	ctx context.Context, st *state, pacScript, urlStr, host string,
) (string, error) {
	// for eval_pac we should allocate 3 strings:
	// the script source, url and host strings.
	srcPtr, srcLen := st.allocStr(ctx, pacScript)
	urlPtr, urlLen := st.allocStr(ctx, urlStr)
	hstPtr, hstLen := st.allocStr(ctx, host)
	// pass all 6 integer inputs to the eval_pac function
	results, err := st.eval.Call(ctx, uint64(srcPtr), uint64(srcLen),
		uint64(urlPtr), uint64(urlLen), uint64(hstPtr), uint64(hstLen))
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
	st.record(offset, length)
	// read the corresponding memory
	result, ok := st.mod.Memory().Read(offset, length)
	if !ok {
		if l := st.logger; l != nil {
			l.ErrorContext(ctx, "Cannot read result from WASM module memory",
				"function", "eval_pac", "offset", offset, "length", length)
		}
		return "", errors.New("cannot read result")
	}
	// lazily we prefix the output string with !! to denote errors,
	// so if we have this prefix treat the output as an error message.
	if errMsg, isErr := strings.CutPrefix(string(result), "!!"); isErr {
		return "", errors.New(errMsg)
	}
	// otherwise the output string is returned, again trim the prefix
	return strings.TrimPrefix(string(result), ".."), nil
}

func wrapErr(typ, det error) error {
	return fmt.Errorf("%w: %v", typ, det)
}
