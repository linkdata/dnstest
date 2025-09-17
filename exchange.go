package dnstest

import (
	"fmt"

	"github.com/miekg/dns"
)

type Exchange struct {
	*dns.Msg
	Server string // ;; SERVER: address
	Error  string // ;; ERROR: text
}

func (ex Exchange) Difference(other Exchange) (reason string) {
	if len(ex.Question) != len(other.Question) {
		return "[]Question"
	}
	for i := range ex.Question {
		if ex.Question[i].Name != other.Question[i].Name {
			return fmt.Sprintf("Question[%v].Name %q != %q", i, ex.Question[i].Name, other.Question[i].Name)
		}
		if ex.Question[i].Qtype != other.Question[i].Qtype {
			return fmt.Sprintf("Question[%v].Qtype %v != %v", i, ex.Question[i].Qtype, other.Question[i].Qtype)
		}
	}
	if ex.Rcode != other.Rcode {
		return fmt.Sprintf("%s != %s", dns.RcodeToString[ex.Rcode], dns.RcodeToString[other.Rcode])
	}
	if ex.Rcode == dns.RcodeNameError {
		return ""
	}
	if len(ex.Answer) != len(other.Answer) {
		return fmt.Sprintf("[%v]Answer != [%v]Answer", len(ex.Answer), len(other.Answer))
	}
	if len(ex.Ns) != len(other.Ns) {
		return fmt.Sprintf("[%v]Ns != [%v]Ns", len(ex.Ns), len(other.Ns))
	}
	if len(ex.Extra) != len(other.Extra) {
		return "[]Extra"
	}
	if ex.Error == other.Error {
		return ""
	}
	if ex.Error != "" && other.Error != "" {
		return ""
	}
	return fmt.Sprintf("%q != %q", ex.Error, other.Error)
}
