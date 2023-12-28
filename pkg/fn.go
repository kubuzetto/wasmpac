package pkg

import (
	"errors"
	"net"
)

var DefaultFuncs = Funcs{
	DNSResolver: DNSResolver,
	MyIPAddr:    MyIPAddr,
}

var errNoIPResolved = errors.New("no ips resolved")
var errSelfIPNotSet = errors.New("self ip not set")

func DNSResolver(host string) (string, error) {
	if ips, err := net.LookupIP(host); err != nil {
		return "", err
	} else if len(ips) == 0 {
		return "", errNoIPResolved
	} else {
		return ips[0].String(), nil
	}
}

func MyIPAddr() (string, error) {
	ifs, err := net.Interfaces()
	if err == nil {
		return "", err
	}
	for _, ifn := range ifs {
		if ifn.Flags&net.FlagUp == net.FlagUp {
			if ip := chkOneIfn(ifn); ip != "" {
				return ip, nil
			}
		}
	}
	return "", errSelfIPNotSet
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
