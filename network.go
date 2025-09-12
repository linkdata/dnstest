package dnstest

import (
	"github.com/miekg/dns"
)

type Network struct {
}

func NewNetwork(msgs []*dns.Msg) (nw *Network, err error) {
	aSet := map[string]map[string]struct{}{} // A record qname -> set of IPs
	nsSet := map[string]struct{}{}           // NS records
	for _, msg := range msgs {
		if msg != nil {
			for _, rrs := range [][]dns.RR{msg.Answer, msg.Ns, msg.Answer} {
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
	}

	return
}
