package pkg

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"math"
	"net/url"
	"strings"
)

type Funcs struct {
	DNSResolver func(string) (string, error)
	MyIPAddr    func() (string, error)
}

type eval struct {
	mod   []byte
	funcs Funcs
}

type Evaluator interface {
	Eval(ctx context.Context, pacScript, urlStr string) (res string, err error)
}

func New(mod []byte) Evaluator {
	return NewWithFuncs(mod, DefaultFuncs)
}

func NewWithFuncs(mod []byte, f Funcs) Evaluator {
	return &eval{mod: mod, funcs: f}
}

func (e *eval) Eval(ctx context.Context, pacScript, urlStr string) (res string, err error) {
	defer func() {
		if p := recover(); p != nil {
			res, err = "", fmt.Errorf("panic recovered: %v", p)
		}
	}()
	res, err = e.evalSafe(ctx, pacScript, urlStr)
	return
}

func (e *eval) evalSafe(ctx context.Context, pacScript, urlStr string) (string, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return "", err
	}
	host := u.Hostname()
	r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigInterpreter())
	defer func() { _ = r.Close(ctx) }()
	mod, a, err := e.initModules(ctx, r)
	if err != nil {
		return "", err
	}
	defer a.clean(ctx)
	return callEvalPAC(ctx, mod, &a, pacScript, urlStr, host)
}

func (e *eval) initModules(ctx context.Context, r wazero.Runtime) (mod api.Module, a memtrack, err error) {
	if _, err = r.NewHostModuleBuilder("env").NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, o, l uint32) (r uint64) {
			if b, ok := m.Memory().Read(o, l); ok {
				v, er := e.funcs.DNSResolver(string(b))
				r = a.allocRet(ctx, v, er)
			}
			return
		}).Export("dns_resolve").NewFunctionBuilder().
		WithFunc(func(ctx context.Context, _ api.Module) uint64 {
			v, er := e.funcs.MyIPAddr()
			return a.allocRet(ctx, v, er)
		}).Export("my_ip_addr").Instantiate(ctx); err == nil {
		if _, err = wasi_snapshot_preview1.Instantiate(ctx, r); err == nil {
			if mod, err = r.InstantiateWithConfig(ctx, e.mod, wazero.NewModuleConfig().
				WithRandSource(rand.Reader).WithSysNanosleep().WithSysNanotime().WithSysWalltime(),
			); err == nil {
				a.setMod(mod)
			}
		}
	}
	return
}

func callEvalPAC(ctx context.Context, mod api.Module, a *memtrack, pac, urlstr, host string) (string, error) {
	srcPtr, srcLen := a.allocStr(ctx, pac)
	urlPtr, urlLen := a.allocStr(ctx, urlstr)
	hstPtr, hstLen := a.allocStr(ctx, host)
	results, err := mod.ExportedFunction("eval_pac").Call(
		ctx, srcPtr, srcLen, urlPtr, urlLen, hstPtr, hstLen)
	if err != nil {
		return "", err
	}
	res := results[0]
	if p, l := uint32(res>>32), uint32(res&math.MaxUint32); p != 0 && l != 0 {
		a.allocs = append(a.allocs, mem{p: uint64(p), l: uint64(l)})
		if out, ok := a.mod.Memory().Read(p, l); ok {
			if o, isErr := strings.CutPrefix(string(out), "!!"); isErr {
				return "", errors.New(o)
			} else {
				return o, nil
			}
		}
	}
	return "", errors.New("no result")
}
