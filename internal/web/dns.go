package web

import (
	"context"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"
)

// AddrInfo is one resolved address plus the thing you actually want to know
// about it when debugging a private endpoint: which address space it sits in.
type AddrInfo struct {
	IP    string `json:"ip"`
	Scope string `json:"scope"`
}

// DNSInfo is the outcome of the resolution phase.
type DNSInfo struct {
	Host      string     `json:"host"`
	Resolver  string     `json:"resolver"`
	CNAME     string     `json:"cname,omitempty"`
	Addrs     []AddrInfo `json:"addrs"`
	ElapsedMS float64    `json:"elapsed_ms"`
}

// Private reports whether every resolved address is in a private range, which
// is what a correctly-resolving private endpoint looks like.
func (d DNSInfo) Private() bool {
	if len(d.Addrs) == 0 {
		return false
	}
	for _, a := range d.Addrs {
		if a.Scope == "public" {
			return false
		}
	}
	return true
}

// Mixed reports whether the answer contains both private and public addresses,
// which usually means a split-horizon zone is only half in place.
func (d DNSInfo) Mixed() bool {
	var priv, pub bool
	for _, a := range d.Addrs {
		if a.Scope == "public" {
			pub = true
		} else {
			priv = true
		}
	}
	return priv && pub
}

// IPs returns the resolved addresses as plain strings.
func (d DNSInfo) IPs() []string {
	out := make([]string, 0, len(d.Addrs))
	for _, a := range d.Addrs {
		out = append(out, a.IP)
	}
	return out
}

// cgnat is RFC 6598 shared address space, which shows up in tunnelled and
// carrier-ish setups and is neither RFC1918 nor routable public.
var cgnat = net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// Scope classifies an address into the space it belongs to.
func Scope(ip net.IP) string {
	switch {
	case ip.IsLoopback():
		return "loopback"
	case ip.IsUnspecified():
		return "unspecified"
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return "link-local"
	case ip.IsPrivate():
		return "private"
	case cgnat.Contains(ip):
		return "cgnat"
	default:
		return "public"
	}
}

// Resolver builds a resolver. An empty server means the system resolver;
// otherwise queries are sent to that server directly, which is how you prove
// whether a specific VPC or private resolver knows a name.
func Resolver(server string) (*net.Resolver, string, error) {
	if strings.TrimSpace(server) == "" {
		return net.DefaultResolver, "system (" + strings.Join(SystemNameservers(), ", ") + ")", nil
	}
	addr := server
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "53")
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return nil, "", fmt.Errorf("bad resolver %q: %w", server, err)
	}
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			// Keep UDP for udp requests but let Go fall back to TCP itself.
			return d.DialContext(ctx, network, addr)
		},
	}
	return r, addr, nil
}

var nameserverRe = regexp.MustCompile(`(?m)^\s*nameserver\s+(\S+)`)

// SystemNameservers reads /etc/resolv.conf so reports can say which resolver
// answered. macOS keeps the effective list in scutil, but resolv.conf is close
// enough to identify a wrong-resolver problem.
func SystemNameservers() []string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return []string{"unknown"}
	}
	var out []string
	for _, m := range nameserverRe.FindAllStringSubmatch(string(data), -1) {
		out = append(out, m[1])
	}
	if len(out) == 0 {
		return []string{"unknown"}
	}
	return out
}

// LookupHost resolves host, recording the CNAME target and the scope of every
// address. An IP literal short-circuits the whole phase.
func LookupHost(ctx context.Context, r *net.Resolver, resolverName, host string) (DNSInfo, error) {
	info := DNSInfo{Host: host, Resolver: resolverName}

	if ip := net.ParseIP(host); ip != nil {
		info.Resolver = "none (IP literal)"
		info.Addrs = []AddrInfo{{IP: ip.String(), Scope: Scope(ip)}}
		return info, nil
	}

	start := time.Now()
	addrs, err := r.LookupNetIP(ctx, "ip", host)
	info.ElapsedMS = float64(time.Since(start).Microseconds()) / 1000
	if err != nil {
		return info, err
	}
	for _, a := range addrs {
		ip := net.IP(a.AsSlice())
		info.Addrs = append(info.Addrs, AddrInfo{IP: a.Unmap().String(), Scope: Scope(ip)})
	}

	// A CNAME is reported only when it actually differs from the queried name;
	// Go returns the name itself for A records.
	if cname, err := r.LookupCNAME(ctx, host); err == nil {
		cname = strings.TrimSuffix(cname, ".")
		if !strings.EqualFold(cname, strings.TrimSuffix(host, ".")) {
			info.CNAME = cname
		}
	}
	return info, nil
}
