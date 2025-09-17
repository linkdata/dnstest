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
	if ex.Rcode != other.Rcode {
		return fmt.Sprintf("%s != %s", dns.RcodeToString[ex.Rcode], dns.RcodeToString[other.Rcode])
	}
	if ex.Rcode == dns.RcodeNameError || ex.Rcode == dns.RcodeServerFailure {
		return ""
	}
	if ex.Error != "" && other.Error != "" {
		return ""
	}
	if ex.Error != "" || other.Error != "" {
		return fmt.Sprintf("%q != %q", ex.Error, other.Error)
	}
	for i := range ex.Question {
		if ex.Question[i].Name != other.Question[i].Name {
			return fmt.Sprintf("Question[%v].Name %q != %q", i, ex.Question[i].Name, other.Question[i].Name)
		}
		if ex.Question[i].Qtype != other.Question[i].Qtype {
			return fmt.Sprintf("Question[%v].Qtype %v != %v", i, ex.Question[i].Qtype, other.Question[i].Qtype)
		}
	}
	qtype := ex.Question[0].Qtype
	found := len(ex.Answer) == 0 && len(other.Answer) == 0
	for _, exans := range ex.Answer {
		if exans.Header().Rrtype == qtype {
			for _, oans := range other.Answer {
				if oans.Header().Rrtype == qtype {
					found = true
				}
			}
		}
	}
	if !found {
		return fmt.Sprintf("[%v]Answer != [%v]Answer", len(ex.Answer), len(other.Answer))
	}
	if ex.Error == other.Error {
		return ""
	}
	return fmt.Sprintf("%q != %q", ex.Error, other.Error)
}
