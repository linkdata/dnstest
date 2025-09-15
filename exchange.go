package dnstest

import "github.com/miekg/dns"

type Exchange struct {
	*dns.Msg
	Server string // ;; SERVER: address
	Error  string // ;; ERROR: text
}
