package wasmpac

import (
	"context"
	_ "embed"
	"github.com/kubuzetto/wasmpac/pkg"
)

//go:embed pac.wasm
var mod []byte

func EvalPAC(ctx context.Context, script, url string) (string, error) {
	return pkg.New(mod).Eval(ctx, script, url)
}
