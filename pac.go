package wasmpac

import (
	"context"
	_ "embed"
	"github.com/kubuzetto/wasmpac/pkg"
)

// The pac.wasm module is embedded here. To recompile
// the optimized wasm file, you can use build_mod.sh.

//go:embed pac.wasm
var WASMModuleData []byte

// EvalPAC evaluates a given PAC script for the given url, and
// returns the output string. The evaluation is done in the Boa
// JavaScript engine, which itself is compiled into a WASM module
// and run by the Wazero WASM engine.
// Note that stdin, stdout and stderr are not connected to the
// wasm module, therefore console commands will not work inside
// the PAC scripts.
func EvalPAC(ctx context.Context, script, url string) (string, error) {
	return pkg.New(WASMModuleData).Eval(ctx, script, url)
}
