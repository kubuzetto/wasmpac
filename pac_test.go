package wasmpac_test

import (
	"context"
	"log/slog"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kubuzetto/wasmpac"
)

func TestEvalPAC(t *testing.T) {
	const testScript = `
function FindProxyForURL(url, host) {
	// not a meaningful output; but hits all host functions
	return "DIRECT|" + url + "|" + host + "|" + new Date().toISOString() + "|" +
		myIpAddress() + "|" + dnsResolve(host);
}`
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, nil)))
	res, err := wasmpac.EvalPAC(context.Background(), testScript, "https://example.org/")
	assert(t, err == nil, "eval failed: %v", err)
	parts := strings.Split(res, "|")
	assert(t, len(parts) == 6, "wrong number of parts: %d", len(parts))
	assert(t, parts[0] == "DIRECT", "wrong output: %q", parts[0])
	assert(t, parts[1] == "https://example.org/", "wrong url: %q", parts[1])
	assert(t, parts[2] == "example.org", "wrong hostname: %q", parts[2])
	tm, err := time.Parse(time.RFC3339Nano, parts[3])
	assert(t, err == nil, "cannot parse time: %v", err)
	assert(t, time.Since(tm) < time.Minute, "wrong time: %v", tm)
	assert(t, net.ParseIP(parts[4]) != nil,
		"ip address does not match regex: %s", parts[4])
	assert(t, net.ParseIP(parts[5]) != nil,
		"ip address does not match regex: %s", parts[5])

}

func assert(t *testing.T, cond bool, fmt string, args ...any) {
	t.Helper()
	if !cond {
		t.Fatalf(fmt, args...)
	}
}
