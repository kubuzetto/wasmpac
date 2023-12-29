package pkg

import (
	"crypto/rand"
	"errors"
	"github.com/tetratelabs/wazero/sys"
	"net"
	"time"
)

// DefaultFuncs bundles all functionality implemented in the Go side.
var DefaultFuncs = Funcs{
	DNSResolver: DNSResolver,
	MyIPAddr:    MyIPAddr,

	// default implementations of these are taken from wazero
	RandSource:         rand.Reader,
	Nanosleep:          Nanosleep,
	Nanotime:           Nanotime,
	NanotimeResolution: 1,
	Walltime:           Walltime,
	WalltimeResolution: sys.ClockResolution(time.Microsecond.Nanoseconds()),
}

var nanoBase = time.Now()

func Nanotime() int64 {
	// there is a more accurate nanotime impl in wazero but that one uses CGO
	return time.Since(nanoBase).Nanoseconds()
}

func Nanosleep(ns int64) {
	time.Sleep(time.Duration(ns))
}

func Walltime() (sec int64, nsec int32) {
	t := time.Now()
	return t.Unix(), int32(t.Nanosecond())
}

// DNSResolver resolves a given hostname to the corresponding IP address.
// Adapted from https://github.com/darren/gpac/blob/master/builtin_natives.go
func DNSResolver(host string) (string, error) {
	if ips, err := net.LookupIP(host); err != nil {
		return "", err
	} else if len(ips) == 0 {
		return "", errors.New("no ips resolved")
	} else {
		return ips[0].String(), nil
	}
}

// MyIPAddr returns the ip address of the machine. The meaning of this is vague
// for machines with multiple NICs and even in the presence of IPv6; so the usage
// of this function is generally discouraged in PAC files. See: https://findproxyforurl.com/pac-functions/
// Adapted from https://github.com/darren/gpac/blob/master/builtin_natives.go
func MyIPAddr() (string, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, ifn := range ifs {
		if ifn.Flags&net.FlagUp == net.FlagUp {
			if ip := chkOneIfn(ifn); ip != "" {
				return ip, nil
			}
		}
	}
	return "", errors.New("self ip not set")
}

func chkOneIfn(ifn net.Interface) string {
	if addrs, err := ifn.Addrs(); err == nil {
		for _, addr := range addrs {
			if ip, ok := addr.(*net.IPNet); ok && ip.IP.IsGlobalUnicast() {
				return ip.IP.String()
			}
		}
	}
	return ""
}
