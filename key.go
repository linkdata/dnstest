package dnstest

import "github.com/miekg/dns"

type Key struct {
	Qname string // DNS query canonical name
	Qtype uint16 // DNS query type
	Proto string // "udp", "tcp" or "" for both
}

// NewKey returns a map key for the given question name and type.
func NewKey(qname string, qtype uint16, proto ...string) (k Key) {
	k = Key{
		Qname: dns.CanonicalName(qname),
		Qtype: qtype,
	}
	if len(proto) == 1 {
		k.Proto = proto[0]
	}
	return
}
