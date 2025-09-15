package dnstest

import "github.com/miekg/dns"

type Exchange struct {
	*dns.Msg
	Server string
}
