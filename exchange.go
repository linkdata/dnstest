package dnstest

import "github.com/miekg/dns"

type Exchange struct {
	Server string
	Msg    *dns.Msg
	Error  error
}
