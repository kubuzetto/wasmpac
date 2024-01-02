package wasmpac

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/tetratelabs/wazero/sys"
)

// EvalPAC evaluates a given PAC script for the given url, and returns the output string.
// The evaluation is done in the Boa JavaScript engine, which itself is compiled into a
// WASM module and run by the Wazero WASM engine.
// Note that stdin, stdout and stderr are not connected to the wasm module, therefore
// console commands will not work inside the PAC scripts.
func EvalPAC(ctx context.Context, script, url string) (string, error) {
	return New().EvalPAC(ctx, script, url)
}

type Evaluator struct {
	// Logger can be nil, to disable logging from the Evaluator altogether.
	// Default value is slog.Default().
	Logger *slog.Logger

	// host functions
	DNSResolver DNSResolverFn
	MyIPAddr    MyIPAddrFn

	RandSource         io.Reader
	Nanosleep          sys.Nanosleep
	Nanotime           sys.Nanotime
	NanotimeResolution sys.ClockResolution
	Walltime           sys.Walltime
	WalltimeResolution sys.ClockResolution
}

type (
	DNSResolverFn func(host string) (ip string, err error)
	MyIPAddrFn    func() (ip string, err error)
)

func New() *Evaluator {
	return &Evaluator{
		// default implementations of these are taken from wazero
		RandSource:         rand.Reader,
		Nanosleep:          Nanosleep,
		Nanotime:           Nanotime,
		NanotimeResolution: 1,
		Walltime:           Walltime,
		WalltimeResolution: sys.ClockResolution(time.Microsecond.Nanoseconds()),

		Logger: slog.Default(),
	}
}

func (e *Evaluator) EvalPAC(ctx context.Context, pacScript, urlStr string) (res string, err error) {
	defer func() {
		if p := recover(); p != nil {
			res, err = "", fmt.Errorf("panic recovered: %v", p)
		}
	}()
	// now that we can catch panics, evaluate the pac script
	res, err = evalSafe(ctx, e, pacScript, urlStr)
	return
}
