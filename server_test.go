package dnstest

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestServer(t *testing.T) {
	rr, err := dns.NewRR("example.org. 60 IN A 127.0.0.1")
	if err != nil {
		t.Fatalf("NewRR: %v", err)
	}
	respMsg := &dns.Msg{Answer: []dns.RR{rr}}
	respMsg.Authoritative = true

	srv, err := NewServer("127.0.0.1:0", map[string]*Response{
		Key("example.org.", dns.TypeA):      {Msg: respMsg},
		Key("nxdomain.example.", dns.TypeA): {Rcode: dns.RcodeNameError},
		Key("bad.example.", dns.TypeA):      {Raw: []byte{0, 1, 2, 3}},
		Key("delay.example.", dns.TypeA):    {Delay: 10 * time.Millisecond},
		Key("timeout.example.", dns.TypeA):  {Drop: true},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	c := dns.Client{Net: "udp"}
	req := new(dns.Msg)
	req.SetQuestion("example.org.", dns.TypeA)
	in, _, err := c.Exchange(req, srv.Addr)
	if err != nil {
		t.Fatalf("udp exchange: %v", err)
	}
	if !in.Authoritative {
		t.Fatal("expected AUTH answer")
	}
	want := fmt.Sprint(respMsg.Answer)
	got := fmt.Sprint(in.Answer)
	if want != got {
		t.Fatalf("\nwant %q\n got %q\n", want, got)
	}

	c.Net = "tcp"
	in, _, err = c.Exchange(req, srv.Addr)
	if err != nil {
		t.Fatalf("tcp exchange: %v", err)
	}
	if !in.Authoritative {
		t.Fatal("expected AUTH answer")
	}
	got = fmt.Sprint(in.Answer)
	if want != got {
		t.Fatalf("\nwant %q\n got %q\n", want, got)
	}

	c.Net = "udp"
	req.SetQuestion("nxdomain.example.", dns.TypeA)
	in, _, err = c.Exchange(req, srv.Addr)
	if err != nil {
		t.Fatalf("nxdomain exchange: %v", err)
	}
	if in.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN, got %d", in.Rcode)
	}
	if in.Authoritative {
		t.Fatal("unexpected AUTH answer")
	}

	req.SetQuestion("bad.example.", dns.TypeA)
	_, _, err = c.Exchange(req, srv.Addr)
	if err == nil {
		t.Fatalf("expected error for bad response")
	}

	req.SetQuestion("delay.example.", dns.TypeA)
	now := time.Now()
	_, _, err = c.Exchange(req, srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(now); elapsed < time.Millisecond*10 {
		t.Error(elapsed)
	}

	c.ReadTimeout = time.Millisecond
	req.SetQuestion("timeout.example.", dns.TypeA)
	_, _, err = c.Exchange(req, srv.Addr)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "timeout") {
		t.Fatalf("expected timeout, got %v", err)
	}
}
