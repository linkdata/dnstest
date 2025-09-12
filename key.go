package dnstest

import "github.com/miekg/dns"

type Key struct {
	Qname string // DNS query canonical name
	Qtype uint16 // DNS query type
}

// NewKey returns a map key for the given question name and type.
func NewKey(qname string, qtype uint16) Key {
	return Key{
		Qname: dns.CanonicalName(qname),
		Qtype: qtype,
	}
}
