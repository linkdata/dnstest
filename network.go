package dnstest

import (
	"context"
	"net"

	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
)

var _ proxy.ContextDialer = &Network{}

type Network struct {
}

func NewNetwork(exchs []Exchange) (nw *Network, err error) {
	aSet := map[string]map[string]struct{}{} // A record qname -> set of IPs
	nsSet := map[string]struct{}{}           // NS records
	for _, exch := range exchs {
		for _, rrs := range [][]dns.RR{exch.Answer, exch.Ns, exch.Answer} {
			for _, rr := range rrs {
				qname := dns.CanonicalName(rr.Header().Name)
				switch rr := rr.(type) {
				case *dns.A:
					aSet[qname][rr.A.String()] = struct{}{}
				case *dns.AAAA:
					aSet[qname][rr.AAAA.String()] = struct{}{}
				case *dns.NS:
					nsSet[dns.CanonicalName(rr.Ns)] = struct{}{}
				}
			}
		}
	}

	return
}

func (n *Network) DialContext(ctx context.Context, network string, address string) (conn net.Conn, err error) {
	return
}
