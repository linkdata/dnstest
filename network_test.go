package dnstest

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestNetworkDialContext(t *testing.T) {
	t.Parallel()

	rrA := mustRR(t, "example.org. 300 IN A 192.0.2.5")
	rrNS := mustRR(t, "example.org. 300 IN NS ns1.example.org.")
	rrGlue := mustRR(t, "ns1.example.org. 300 IN A 192.0.2.1")

	msgA := &dns.Msg{}
	msgA.Id = 1234
	msgA.Response = true
	msgA.Authoritative = true
	msgA.RecursionAvailable = true
	msgA.Question = []dns.Question{{
		Name:   dns.Fqdn("example.org"),
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}}
	msgA.Answer = []dns.RR{rrA}
	msgA.Ns = []dns.RR{rrNS}
	msgA.Extra = []dns.RR{rrGlue}

	rrAAAA := mustRR(t, "ipv6.example. 300 IN AAAA 2001:db8::feed")
	rrGlueV6 := mustRR(t, "ns2.example.org. 300 IN AAAA 2001:db8::10")
	msgAAAA := &dns.Msg{}
	msgAAAA.Id = 4321
	msgAAAA.Response = true
	msgAAAA.Authoritative = true
	msgAAAA.Question = []dns.Question{{
		Name:   dns.Fqdn("ipv6.example"),
		Qtype:  dns.TypeAAAA,
		Qclass: dns.ClassINET,
	}}
	msgAAAA.Answer = []dns.RR{rrAAAA}
	msgAAAA.Extra = []dns.RR{rrGlueV6}

	rrTXT := mustRR(t, "service.example. 60 IN TXT \"ok\"")
	msgTXT := &dns.Msg{}
	msgTXT.Id = 9999
	msgTXT.Response = true
	msgTXT.Authoritative = true
	msgTXT.Question = []dns.Question{{
		Name:   dns.Fqdn("service.example"),
		Qtype:  dns.TypeTXT,
		Qclass: dns.ClassINET,
	}}
	msgTXT.Answer = []dns.RR{rrTXT}

	network, err := NewNetwork([]Exchange{
		{Msg: msgA, Server: "192.0.2.1"},
		{Msg: msgAAAA, Server: "2001:db8::10:53"},
		{Msg: msgTXT, Server: "NS3.EXAMPLE.ORG:53"},
	})
	if err != nil {
		t.Fatalf("NewNetwork: %v", err)
	}
	defer network.Close()
	if base, ok := network.aliases["[2001:db8::10]:53"]; !ok {
		t.Fatalf("missing ipv6 alias mapping")
	} else if base == "" || network.remotes[base] == nil {
		t.Fatalf("alias %q not bound to a remote", base)
	}

	questionA := dns.Question{Name: dns.Fqdn("example.org"), Qtype: dns.TypeA, Qclass: dns.ClassINET}
	resp := exchangeViaNetwork(t, network, "192.0.2.1:53", questionA)
	assertARecord(t, resp, "192.0.2.5")

	resp = exchangeViaNetwork(t, network, "ns1.example.org:53", questionA)
	assertARecord(t, resp, "192.0.2.5")

	questionAAAA := dns.Question{Name: dns.Fqdn("ipv6.example"), Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}
	resp = exchangeViaNetwork(t, network, "[2001:db8::10]:53", questionAAAA)
	assertAAAARecord(t, resp, "2001:db8::feed")

	resp = exchangeViaNetwork(t, network, "ns2.example.org:53", questionAAAA)
	assertAAAARecord(t, resp, "2001:db8::feed")

	questionTXT := dns.Question{Name: dns.Fqdn("service.example"), Qtype: dns.TypeTXT, Qclass: dns.ClassINET}
	resp = exchangeViaNetwork(t, network, "ns3.example.org:53", questionTXT)
	if len(resp.Answer) != 1 {
		t.Fatalf("TXT answer length: got %d, want 1", len(resp.Answer))
	}
	txt, ok := resp.Answer[0].(*dns.TXT)
	if !ok {
		t.Fatalf("expected TXT, got %T", resp.Answer[0])
	}
	if len(txt.Txt) != 1 || txt.Txt[0] != "ok" {
		t.Fatalf("TXT answer: %#v", txt.Txt)
	}

	if _, err := network.DialContext(context.Background(), "udp", "203.0.113.1:53"); err == nil {
		t.Fatalf("expected error for unknown IP")
	}
	if _, err := network.DialContext(context.Background(), "udp", "unknown.example.org:53"); err == nil {
		t.Fatalf("expected error for unknown name")
	}
}

func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("dns.NewRR(%q): %v", s, err)
	}
	return rr
}

func exchangeViaNetwork(t *testing.T, nw *Network, address string, question dns.Question) *dns.Msg {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	conn, err := nw.DialContext(ctx, "udp", address)
	if err != nil {
		t.Fatalf("DialContext(%q): %v", address, err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	dconn := &dns.Conn{Conn: conn}
	defer dconn.Close()

	msg := &dns.Msg{}
	msg.Id = dns.Id()
	msg.RecursionDesired = true
	msg.Question = []dns.Question{question}
	if err := dconn.WriteMsg(msg); err != nil {
		t.Fatalf("WriteMsg: %v", err)
	}
	resp, err := dconn.ReadMsg()
	if err != nil {
		t.Fatalf("ReadMsg: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("unexpected rcode %d", resp.Rcode)
	}
	return resp
}

func assertARecord(t *testing.T, msg *dns.Msg, want string) {
	t.Helper()
	if len(msg.Answer) != 1 {
		t.Fatalf("A answer length: got %d, want 1", len(msg.Answer))
	}
	a, ok := msg.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A, got %T", msg.Answer[0])
	}
	if got := a.A.String(); got != want {
		t.Fatalf("A answer: got %s, want %s", got, want)
	}
}

func assertAAAARecord(t *testing.T, msg *dns.Msg, want string) {
	t.Helper()
	if len(msg.Answer) != 1 {
		t.Fatalf("AAAA answer length: got %d, want 1", len(msg.Answer))
	}
	aaa, ok := msg.Answer[0].(*dns.AAAA)
	if !ok {
		t.Fatalf("expected AAAA, got %T", msg.Answer[0])
	}
	if got := aaa.AAAA.String(); got != want {
		t.Fatalf("AAAA answer: got %s, want %s", got, want)
	}
}
