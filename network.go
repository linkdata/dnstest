package dnstest

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
)

var _ proxy.ContextDialer = &Network{}

type Network struct {
	dialer        proxy.ContextDialer
	remotes       map[string]*Server  // canonical remote addr -> simulated server
	nameToRemotes map[string][]string // canonical domain -> remote addrs
	aliases       map[string]string   // alias addr -> canonical remote addr
}

func NewNetwork(exchs []Exchange) (nw *Network, err error) {
	aSet := map[string]map[string]struct{}{}        // qname -> set of IPs
	ipToRemotes := map[string]map[string]struct{}{} // ip -> set of remote addrs
	nameToRemoteSet := map[string]map[string]struct{}{}
	remoteResponses := map[string]map[Key]*Response{}
	aliasCandidates := map[string]string{}

	for _, exch := range exchs {
		if exch.Msg == nil || len(exch.Question) == 0 {
			continue
		}

		remoteAddr, err := normalizeServerAddress(exch.Server)
		if err != nil {
			return nil, err
		}
		alias := deriveAlias(exch.Server)
		if alias != "" && alias != remoteAddr {
			aliasCandidates[alias] = remoteAddr
		}
		// Build response mapping per remote address.
		if _, ok := remoteResponses[remoteAddr]; !ok {
			remoteResponses[remoteAddr] = make(map[Key]*Response)
		}
		msgCopy := exch.Msg.Copy()
		for _, q := range exch.Question {
			resp := &Response{Msg: msgCopy}
			if msgCopy.Rcode != dns.RcodeSuccess {
				resp.Rcode = msgCopy.Rcode
			}
			remoteResponses[remoteAddr][NewKey(q.Name, q.Qtype)] = resp
		}

		host, _, _ := net.SplitHostPort(remoteAddr)
		ipHost := host
		if alias != "" {
			if ah, _, err := net.SplitHostPort(alias); err == nil {
				ipHost = ah
			}
		}
		if ip := canonicalIP(ipHost); ip != "" {
			addToSet(ipToRemotes, ip, remoteAddr)
		} else {
			addToSet(nameToRemoteSet, normalizeDomain(host), remoteAddr)
		}

		for _, rrs := range [][]dns.RR{exch.Answer, exch.Ns, exch.Extra} {
			for _, rr := range rrs {
				qname := dns.CanonicalName(rr.Header().Name)
				switch rr := rr.(type) {
				case *dns.A:
					addToSet(aSet, qname, rr.A.String())
				case *dns.AAAA:
					addToSet(aSet, qname, rr.AAAA.String())
				}
			}
		}
	}

	nw = &Network{
		dialer:        &net.Dialer{},
		remotes:       make(map[string]*Server),
		nameToRemotes: make(map[string][]string),
		aliases:       make(map[string]string),
	}

	// Helper to close already created servers when returning early.
	closeAll := func() {
		for _, srv := range nw.remotes {
			srv.Close()
		}
	}

	for remoteAddr, responses := range remoteResponses {
		if len(responses) == 0 {
			continue
		}
		srv, err := NewServer(responses)
		if err != nil {
			closeAll()
			return nil, err
		}
		nw.remotes[remoteAddr] = srv
	}
	for alias, remoteAddr := range aliasCandidates {
		if _, ok := nw.remotes[remoteAddr]; ok {
			nw.aliases[alias] = remoteAddr
		}
	}

	// Build domain -> remote mapping from recorded A/AAAA data.
	for name, ipSet := range aSet {
		canonicalName := normalizeDomain(name)
		for ip := range ipSet {
			for remoteAddr := range ipToRemotes[ip] {
				if _, ok := nw.remotes[remoteAddr]; ok {
					addToSet(nameToRemoteSet, canonicalName, remoteAddr)
				}
			}
		}
	}

	for name, remoteSet := range nameToRemoteSet {
		var remotes []string
		for remoteAddr := range remoteSet {
			if _, ok := nw.remotes[remoteAddr]; ok {
				remotes = append(remotes, remoteAddr)
			}
		}
		if len(remotes) > 0 {
			sort.Strings(remotes)
			nw.nameToRemotes[name] = remotes
		}
	}

	return nw, nil
}

func (n *Network) DialContext(ctx context.Context, network string, address string) (conn net.Conn, err error) {
	if n == nil {
		return nil, fmt.Errorf("dnstest: nil network")
	}
	canonicalAddr, err := normalizeServerAddress(address)
	if err != nil {
		return nil, err
	}
	if srv, ok := n.remotes[canonicalAddr]; ok {
		return n.dialer.DialContext(ctx, network, srv.Addr)
	}
	if base, ok := n.aliases[canonicalAddr]; ok {
		if srv, ok := n.remotes[base]; ok {
			return n.dialer.DialContext(ctx, network, srv.Addr)
		}
	}

	host, port, _ := net.SplitHostPort(canonicalAddr)
	if ip := canonicalIP(host); ip != "" {
		if srv, ok := n.remotes[net.JoinHostPort(ip, port)]; ok {
			return n.dialer.DialContext(ctx, network, srv.Addr)
		}
	}
	name := normalizeDomain(host)
	if remotes := n.nameToRemotes[name]; len(remotes) > 0 {
		for _, remoteAddr := range remotes {
			if _, rport, err := net.SplitHostPort(remoteAddr); err == nil && rport == port {
				if srv, ok := n.remotes[remoteAddr]; ok {
					return n.dialer.DialContext(ctx, network, srv.Addr)
				}
			}
		}
	}
	return nil, fmt.Errorf("dnstest: no simulated server for %q", address)
}

// Close shuts down all simulated servers created for the network.
func (n *Network) Close() {
	if n == nil {
		return
	}
	for _, srv := range n.remotes {
		srv.Close()
	}
}

func addToSet(m map[string]map[string]struct{}, key, value string) {
	if key == "" || value == "" {
		return
	}
	if _, ok := m[key]; !ok {
		m[key] = make(map[string]struct{})
	}
	m[key][value] = struct{}{}
}

func deriveAlias(server string) string {
	server = strings.TrimSpace(server)
	if server == "" || strings.Contains(server, "[") {
		return ""
	}
	idx := strings.LastIndex(server, ":")
	if idx <= 0 {
		return ""
	}
	hostPart := server[:idx]
	portPart := server[idx+1:]
	p, err := normalizePort(portPart)
	if err != nil {
		return ""
	}
	if ip := canonicalIP(hostPart); ip != "" {
		return net.JoinHostPort(ip, p)
	}
	return ""
}

func normalizeServerAddress(addr string) (string, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", fmt.Errorf("dnstest: empty address")
	}

	if host, port, err := net.SplitHostPort(addr); err == nil {
		host = normalizeHost(host)
		p, err := normalizePort(port)
		if err != nil {
			return "", err
		}
		return net.JoinHostPort(host, p), nil
	}

	if ip := canonicalIP(addr); ip != "" {
		return net.JoinHostPort(ip, "53"), nil
	}

	// Handle IPv6 addresses without brackets but with port appended.
	if idx := strings.LastIndex(addr, ":"); idx > 0 {
		hostPart := addr[:idx]
		portPart := addr[idx+1:]
		if ip := canonicalIP(hostPart); ip != "" {
			p, err := normalizePort(portPart)
			if err != nil {
				return "", err
			}
			return net.JoinHostPort(ip, p), nil
		}
	}

	if strings.Contains(addr, ":") {
		return "", fmt.Errorf("dnstest: invalid address %q", addr)
	}

	host := normalizeDomain(addr)
	return net.JoinHostPort(host, "53"), nil
}

func normalizeHost(host string) string {
	if ip := canonicalIP(host); ip != "" {
		return ip
	}
	return normalizeDomain(host)
}

func normalizeDomain(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	return strings.TrimSuffix(dns.CanonicalName(host), ".")
}

func canonicalIP(host string) string {
	h := strings.Trim(host, "[]")
	if i := strings.IndexByte(h, '%'); i >= 0 {
		h = h[:i]
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.String()
	}
	return ""
}

func normalizePort(port string) (string, error) {
	port = strings.TrimSpace(port)
	if port == "" {
		return "53", nil
	}
	if n, err := strconv.ParseUint(port, 10, 16); err == nil {
		return strconv.FormatUint(n, 10), nil
	}
	return "", fmt.Errorf("dnstest: invalid port %q", port)
}
