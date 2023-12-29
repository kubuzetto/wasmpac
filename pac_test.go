package wasmpac_test

import (
	"context"
	"github.com/kubuzetto/wasmpac"
	"testing"
)

func TestEvalPAC(t *testing.T) {
	const testScript = `// super simple smoke test
function FindProxyForURL(url, host) {
	return "DIRECT";
}`
	res, err := wasmpac.EvalPAC(context.Background(), testScript, "https://example.org/")
	if err != nil {
		t.Errorf("Error: %v", err)
	} else if res != "DIRECT" {
		t.Errorf("Wrong output: %q", res)
	}
}
