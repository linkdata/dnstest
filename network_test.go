package dnstest

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestNetworkDialContext(t *testing.T) {
	t.Parallel()

	msgA, msgAAAA, msgTXT := networkTestMessages(t)

	srvA, err := NewServer(map[Key]*Response{
		NewKey("example.org.", dns.TypeA): {Msg: msgA},
	})
	if err != nil {
		t.Fatalf("NewServer IPv4: %v", err)
	}

	srvAAAA, err := NewServer(map[Key]*Response{
		NewKey("ipv6.example.", dns.TypeAAAA): {Msg: msgAAAA},
	})
	if err != nil {
		srvA.Close()
		t.Fatalf("NewServer IPv6: %v", err)
	}

	srvTXT, err := NewServer(map[Key]*Response{
		NewKey("service.example.", dns.TypeTXT): {Msg: msgTXT},
	})
	if err != nil {
		srvA.Close()
		srvAAAA.Close()
		t.Fatalf("NewServer TXT: %v", err)
	}

	network := &Network{
		dialer: &net.Dialer{},
		remotes: map[string]*Server{
			"192.0.2.1:53":         srvA,
			"[2001:db8::10:53]:53": srvAAAA,
			"ns3.example.org:53":   srvTXT,
		},
		nameToRemotes: map[string][]string{
			"ns1.example.org": {"192.0.2.1:53"},
			"ns2.example.org": {"[2001:db8::10:53]:53"},
		},
		aliases: map[string]string{
			"[2001:db8::10]:53": "[2001:db8::10:53]:53",
		},
	}
	t.Cleanup(network.Close)
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

func TestNewNetworkFromExchanges(t *testing.T) {
	t.Parallel()

	msgA, msgAAAA, msgTXT := networkTestMessages(t)

	network, err := NewNetwork([]Exchange{
		{Msg: msgA, Server: "192.0.2.1"},
		{Msg: msgAAAA, Server: "2001:db8::10:53"},
		{Msg: msgTXT, Server: "NS3.EXAMPLE.ORG:53"},
	})
	if err != nil {
		t.Fatalf("NewNetwork: %v", err)
	}
	t.Cleanup(network.Close)

	if srv := network.remotes["192.0.2.1:53"]; srv == nil {
		t.Fatalf("missing IPv4 remote")
	}
	if srv := network.remotes["ns3.example.org:53"]; srv == nil {
		t.Fatalf("missing TXT remote")
	}
	base, ok := network.aliases["[2001:db8::10]:53"]
	if !ok {
		t.Fatalf("missing ipv6 alias mapping")
	}
	if base == "" || network.remotes[base] == nil {
		t.Fatalf("alias %q not bound to a remote", base)
	}
	if got := network.nameToRemotes["ns1.example.org"]; len(got) != 1 || got[0] != "192.0.2.1:53" {
		t.Fatalf("unexpected ns1 remotes: %#v", got)
	}
	if got := network.nameToRemotes["ns2.example.org"]; len(got) != 1 || got[0] != "[2001:db8::10:53]:53" {
		t.Fatalf("unexpected ns2 remotes: %#v", got)
	}
}

func TestNetworkRecursiveConsoleAWS(t *testing.T) {
	t.Parallel()

	exchs, err := ParseDigOutput(strings.NewReader(recursiveConsoleAWSChain))
	if err != nil {
		t.Fatalf("ParseDigOutput: %v", err)
	}

	network, err := NewNetwork(exchs)
	if err != nil {
		t.Fatalf("NewNetwork: %v", err)
	}
	t.Cleanup(network.Close)

	type remoteQuery struct {
		addr  string
		name  string
		qtype uint16
	}
	latest := make(map[remoteQuery]Exchange)
	for idx, exch := range exchs {
		if exch.Msg == nil || len(exch.Question) == 0 {
			continue
		}
		if exch.Server == "" {
			t.Fatalf("exchange %d missing server", idx)
		}
		addr, err := normalizeServerAddress(exch.Server)
		if err != nil {
			t.Fatalf("normalizeServerAddress(%q): %v", exch.Server, err)
		}
		q := exch.Question[0]
		key := remoteQuery{addr: addr, name: q.Name, qtype: q.Qtype}
		latest[key] = exch
	}
	keys := make([]remoteQuery, 0, len(latest))
	for k := range latest {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].addr != keys[j].addr {
			return keys[i].addr < keys[j].addr
		}
		if keys[i].name != keys[j].name {
			return keys[i].name < keys[j].name
		}
		return keys[i].qtype < keys[j].qtype
	})
	for _, key := range keys {
		exch := latest[key]
		resp := queryNetworkForExchange(t, network, key.addr, exch)
		if diff := compareDNSMessages(exch.Msg, resp); diff != "" {
			qtypeName := dns.TypeToString[key.qtype]
			if qtypeName == "" {
				qtypeName = fmt.Sprintf("TYPE%d", key.qtype)
			}
			t.Fatalf("server %q question %q (%s): %s", key.addr, key.name, qtypeName, diff)
		}
	}
}

func queryNetworkForExchange(t *testing.T, nw *Network, addr string, exch Exchange) *dns.Msg {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := nw.DialContext(ctx, "udp", addr)
	if err != nil {
		t.Fatalf("DialContext(%q): %v", addr, err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	dconn := &dns.Conn{Conn: conn}
	dconn.UDPSize = 4096
	defer dconn.Close()

	req := &dns.Msg{}
	req.Id = dns.Id()
	req.Question = append(req.Question, exch.Question[0])
	req.RecursionDesired = exch.Msg.RecursionDesired
	req.CheckingDisabled = exch.Msg.CheckingDisabled
	req.AuthenticatedData = exch.Msg.AuthenticatedData
	if opt := exch.Msg.IsEdns0(); opt != nil {
		req.SetEdns0(opt.UDPSize(), opt.Do())
	}
	if err := dconn.WriteMsg(req); err != nil {
		t.Fatalf("WriteMsg(%q): %v", addr, err)
	}
	resp, err := dconn.ReadMsg()
	if err != nil {
		t.Fatalf("ReadMsg(%q): %v", addr, err)
	}
	return resp
}

func compareDNSMessages(want, got *dns.Msg) string {
	if want == nil {
		if got == nil {
			return ""
		}
		return "expected nil message"
	}
	if got == nil {
		return "got nil message"
	}
	if want.Rcode != got.Rcode {
		return fmt.Sprintf("rcode mismatch: got %s want %s", dns.RcodeToString[got.Rcode], dns.RcodeToString[want.Rcode])
	}
	if len(want.Question) > 0 {
		if len(got.Question) == 0 {
			return "missing question in response"
		}
		wq, gq := want.Question[0], got.Question[0]
		if wq.Name != gq.Name {
			return fmt.Sprintf("question name mismatch: got %q want %q", gq.Name, wq.Name)
		}
		if wq.Qtype != gq.Qtype {
			return fmt.Sprintf("question type mismatch: got %d want %d", gq.Qtype, wq.Qtype)
		}
		if wq.Qclass != gq.Qclass {
			return fmt.Sprintf("question class mismatch: got %d want %d", gq.Qclass, wq.Qclass)
		}
	} else if len(got.Question) != 0 {
		return fmt.Sprintf("unexpected question count: got %d want 0", len(got.Question))
	}
	for _, section := range []struct {
		name string
		want []dns.RR
		got  []dns.RR
	}{
		{"answer", want.Answer, got.Answer},
		{"authority", want.Ns, got.Ns},
		{"additional", want.Extra, got.Extra},
	} {
		if diff := diffRRSection(section.name, section.want, section.got); diff != "" {
			return diff
		}
	}
	return ""
}

func diffRRSection(section string, want, got []dns.RR) string {
	wantOpts, wantRRs := splitOpts(want)
	gotOpts, gotRRs := splitOpts(got)
	if len(wantRRs) != len(gotRRs) {
		return fmt.Sprintf("%s len mismatch: got %d want %d", section, len(gotRRs), len(wantRRs))
	}
	for i := range wantRRs {
		if wantRRs[i].String() != gotRRs[i].String() {
			return fmt.Sprintf("%s[%d] mismatch: got %q want %q", section, i, gotRRs[i].String(), wantRRs[i].String())
		}
	}
	if len(wantOpts) != len(gotOpts) {
		return fmt.Sprintf("%s opt count mismatch: got %d want %d", section, len(gotOpts), len(wantOpts))
	}
	for i := range wantOpts {
		if wantOpts[i].String() != gotOpts[i].String() {
			return fmt.Sprintf("%s opt[%d] mismatch: got %q want %q", section, i, gotOpts[i].String(), wantOpts[i].String())
		}
	}
	return ""
}

func splitOpts(rrs []dns.RR) (opts []dns.RR, rest []dns.RR) {
	for _, rr := range rrs {
		if _, ok := rr.(*dns.OPT); ok {
			opts = append(opts, rr)
			continue
		}
		rest = append(rest, rr)
	}
	return opts, rest
}

func networkTestMessages(t *testing.T) (msgA, msgAAAA, msgTXT *dns.Msg) {
	t.Helper()

	rrA := mustRR(t, "example.org. 300 IN A 192.0.2.5")
	rrNS := mustRR(t, "example.org. 300 IN NS ns1.example.org.")
	rrGlue := mustRR(t, "ns1.example.org. 300 IN A 192.0.2.1")

	msgA = &dns.Msg{}
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

	msgAAAA = &dns.Msg{}
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

	msgTXT = &dns.Msg{}
	msgTXT.Id = 9999
	msgTXT.Response = true
	msgTXT.Authoritative = true
	msgTXT.Question = []dns.Question{{
		Name:   dns.Fqdn("service.example"),
		Qtype:  dns.TypeTXT,
		Qclass: dns.ClassINET,
	}}
	msgTXT.Answer = []dns.RR{rrTXT}

	return msgA, msgAAAA, msgTXT
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

func TestNetworkFromRecursiveTestData(t *testing.T) {
	t.Parallel()
	exerciseNetworksFromDir(t, "testdata/recursive")
}

func TestNetworkFromDigTestData(t *testing.T) {
	t.Parallel()
	exerciseNetworksFromDir(t, "testdata/dig")
}

func exerciseNetworksFromDir(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%q): %v", dir, err)
	}
	var files []os.DirEntry
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".txt") {
			continue
		}
		files = append(files, entry)
	}
	if len(files) == 0 {
		t.Fatalf("no transcripts found in %s", dir)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name() < files[j].Name() })
	for _, entry := range files {
		name := entry.Name()
		path := filepath.Join(dir, name)
		t.Run(strings.TrimSuffix(name, ".txt"), func(t *testing.T) {
			f, err := os.Open(path)
			if err != nil {
				t.Fatalf("Open(%q): %v", path, err)
			}
			defer f.Close()

			exchs, err := ParseDigOutput(f)
			if err != nil {
				t.Fatalf("ParseDigOutput(%q): %v", path, err)
			}
			var filtered []Exchange
			for _, exch := range exchs {
				if strings.TrimSpace(exch.Server) == "" || exch.Msg == nil {
					continue
				}
				filtered = append(filtered, exch)
			}
			if len(filtered) == 0 {
				t.Fatalf("no usable exchanges parsed from %s", path)
			}

			network, err := NewNetwork(filtered)
			if err != nil {
				t.Fatalf("NewNetwork(%q): %v", path, err)
			}
			t.Cleanup(network.Close)

			lastIdx := -1
			for i := len(filtered) - 1; i >= 0; i-- {
				ex := filtered[i]
				if ex.Msg == nil || len(ex.Question) == 0 || strings.TrimSpace(ex.Server) == "" {
					continue
				}
				lastIdx = i
				break
			}
			if lastIdx == -1 {
				t.Fatalf("no usable exchanges in %s", path)
			}

			exch := filtered[lastIdx]
			addr, err := normalizeServerAddress(exch.Server)
			if err != nil {
				t.Fatalf("normalizeServerAddress(%q): %v", exch.Server, err)
			}

			resp := queryNetworkForExchange(t, network, addr, exch)
			if diff := compareDNSMessages(exch.Msg, resp); diff != "" {
				q := exch.Question[0]
				qtype := dns.TypeToString[q.Qtype]
				if qtype == "" {
					qtype = fmt.Sprintf("TYPE%d", q.Qtype)
				}
				t.Fatalf("%s final exchange mismatch for %s %s: %s", path, q.Name, qtype, diff)
			}
		})
	}
}

const recursiveConsoleAWSChain = `;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @192.36.148.17 NS com.
;; opcode: QUERY, status: NOERROR, id: 736
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 13, ADDITIONAL: 27

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 1232
; COOKIE: fdcdd36e68ceda4a0100000068d6281cb971190ab8f005d1

;; QUESTION SECTION:
;com.	IN	 NS

;; AUTHORITY SECTION:
com.	172800	IN	NS	h.gtld-servers.net.
com.	172800	IN	NS	b.gtld-servers.net.
com.	172800	IN	NS	e.gtld-servers.net.
com.	172800	IN	NS	f.gtld-servers.net.
com.	172800	IN	NS	a.gtld-servers.net.
com.	172800	IN	NS	d.gtld-servers.net.
com.	172800	IN	NS	j.gtld-servers.net.
com.	172800	IN	NS	c.gtld-servers.net.
com.	172800	IN	NS	k.gtld-servers.net.
com.	172800	IN	NS	g.gtld-servers.net.
com.	172800	IN	NS	i.gtld-servers.net.
com.	172800	IN	NS	l.gtld-servers.net.
com.	172800	IN	NS	m.gtld-servers.net.

;; ADDITIONAL SECTION:
m.gtld-servers.net.	172800	IN	A	192.55.83.30
l.gtld-servers.net.	172800	IN	A	192.41.162.30
k.gtld-servers.net.	172800	IN	A	192.52.178.30
j.gtld-servers.net.	172800	IN	A	192.48.79.30
i.gtld-servers.net.	172800	IN	A	192.43.172.30
h.gtld-servers.net.	172800	IN	A	192.54.112.30
g.gtld-servers.net.	172800	IN	A	192.42.93.30
f.gtld-servers.net.	172800	IN	A	192.35.51.30
e.gtld-servers.net.	172800	IN	A	192.12.94.30
d.gtld-servers.net.	172800	IN	A	192.31.80.30
c.gtld-servers.net.	172800	IN	A	192.26.92.30
b.gtld-servers.net.	172800	IN	A	192.33.14.30
a.gtld-servers.net.	172800	IN	A	192.5.6.30
m.gtld-servers.net.	172800	IN	AAAA	2001:501:b1f9::30
l.gtld-servers.net.	172800	IN	AAAA	2001:500:d937::30
k.gtld-servers.net.	172800	IN	AAAA	2001:503:d2d::30
j.gtld-servers.net.	172800	IN	AAAA	2001:502:7094::30
i.gtld-servers.net.	172800	IN	AAAA	2001:503:39c1::30
h.gtld-servers.net.	172800	IN	AAAA	2001:502:8cc::30
g.gtld-servers.net.	172800	IN	AAAA	2001:503:eea3::30
f.gtld-servers.net.	172800	IN	AAAA	2001:503:d414::30
e.gtld-servers.net.	172800	IN	AAAA	2001:502:1ca1::30
d.gtld-servers.net.	172800	IN	AAAA	2001:500:856e::30
c.gtld-servers.net.	172800	IN	AAAA	2001:503:83eb::30
b.gtld-servers.net.	172800	IN	AAAA	2001:503:231d::2:30
a.gtld-servers.net.	172800	IN	AAAA	2001:503:a83e::2:30

;; GZPACK: H4sIAAAAAAAA/4TUPy9DURgG8PfctiJNK4YO/lwv0kVJkyZEY/EBLCRWJLRXi7aqbewivoEvQBeDhYmNHSFEwmSXiNUgEVI8hyc5nXpvfvfNOed57vWetkSMiMSlN5RbL4t4Yn7+iNcUSZhirNAo5dP1oLYZ1OqhStCQv2TJTQI3WXaTRTfJu8mqm+TcZM1NCm6y4iYlNyn/J+yemNYT4bPsrLLBIFL7yvYIYuxY2VmCyEwr2yGIkUNlDQMxXlV2kCCG55WVB0RyVFkDQcQWlFUHRP+MslqA6JlT9iqAGOxQ1mEQkTalyfkt0TlgIuboTb5/GZoiannIgmaJog7F06BZuqi96i5olrQ1e+IcNEvdmt1+AZo1wJr90gTN2mDpuwRo1gxrJf4eaNYS67x3KqBZY6yVbD+DZu2xdLKvZT3J0CZZ+mDyV4ukwtdfF75Epev98rZSvHqc+vz6F++H/NON7ujJa+TmIwAA//+w7TkWEwYAAA==
;; SERVER: 192.36.148.17
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @192.5.6.30 NS amazon.com.
;; opcode: QUERY, status: NOERROR, id: 38212
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 8, ADDITIONAL: 5

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 4096

;; QUESTION SECTION:
;amazon.com.	IN	 NS

;; AUTHORITY SECTION:
amazon.com.	172800	IN	NS	ns1.amzndns.org.
amazon.com.	172800	IN	NS	ns2.amzndns.org.
amazon.com.	172800	IN	NS	ns1.amzndns.co.uk.
amazon.com.	172800	IN	NS	ns2.amzndns.co.uk.
amazon.com.	172800	IN	NS	ns1.amzndns.net.
amazon.com.	172800	IN	NS	ns2.amzndns.net.
amazon.com.	172800	IN	NS	ns1.amzndns.com.
amazon.com.	172800	IN	NS	ns2.amzndns.com.

;; ADDITIONAL SECTION:
ns1.amzndns.com.	172800	IN	A	156.154.64.10
ns1.amzndns.com.	172800	IN	AAAA	2001:502:f3ff::10
ns2.amzndns.com.	172800	IN	A	156.154.68.10
ns2.amzndns.com.	172800	IN	AAAA	2610:a1:1016::10

;; GZPACK: H4sIAAAAAAAA/5rq0sjAwMjAwMDBwMqWmJtYlZ/HnJyfy8DAxMCIzmdgWszAIMicV2zInphblZeSV8ycX5TOgFOZEWFlwsimMSXnM5Vm41ZoRIxCVPflpZYQ4z68yhCmgaSIMA0khaGPgRGqlmXOLAcuTGkZqLSAAiMr0+f/DDAggGE0skkuXJjScJPUBBgWCoghTGJg0BSAsgEBAAD//+XQ5fn3AQAA
;; SERVER: 192.5.6.30
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @156.154.64.10 NS aws.amazon.com.
;; opcode: QUERY, status: NOERROR, id: 814
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 4, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 4096

;; QUESTION SECTION:
;aws.amazon.com.	IN	 NS

;; ANSWER SECTION:
aws.amazon.com.	7200	IN	CNAME	tp.8e49140c2-frontier.amazon.com.

;; AUTHORITY SECTION:
8e49140c2-frontier.amazon.com.	900	IN	NS	ns-439.awsdns-54.com.
8e49140c2-frontier.amazon.com.	900	IN	NS	ns-959.awsdns-55.net.
8e49140c2-frontier.amazon.com.	900	IN	NS	ns-1172.awsdns-18.org.
8e49140c2-frontier.amazon.com.	900	IN	NS	ns-2017.awsdns-60.co.uk.

;; GZPACK: H4sIAAAAAAAA/5TMwcqCQBQF4DNz/99oFy2KoEW0azHh2Jj6OINZRHgnHENoXe8dElKLILvLe853aH0HBAT+IMg2PrClvTqm3JWA/PD7hwDmCyxlfR6nhcm0CfNI7SvH9bGo3rtf4nYeoBsmAXtlNtnQNn7HXsXmd57FLx4TF3VvPh2wV1onUed1Sq469Paz1kehTjq/DWXu5OUEYDXC8x4BAAD//3syKSpnAQAA
;; SERVER: 156.154.64.10
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @192.36.148.17 A org.
;; opcode: QUERY, status: NOERROR, id: 41593
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 6, ADDITIONAL: 13

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 1232
; COOKIE: fdcdd36e68ceda4a0100000068d6281cb971190ab8f005d1

;; QUESTION SECTION:
;org.	IN	 A

;; AUTHORITY SECTION:
org.	172800	IN	NS	b0.org.afilias-nst.org.
org.	172800	IN	NS	d0.org.afilias-nst.org.
org.	172800	IN	NS	a0.org.afilias-nst.info.
org.	172800	IN	NS	a2.org.afilias-nst.info.
org.	172800	IN	NS	c0.org.afilias-nst.info.
org.	172800	IN	NS	b2.org.afilias-nst.org.

;; ADDITIONAL SECTION:
d0.org.afilias-nst.org.	172800	IN	A	199.19.57.1
c0.org.afilias-nst.info.	172800	IN	A	199.19.53.1
b2.org.afilias-nst.org.	172800	IN	A	199.249.120.1
b0.org.afilias-nst.org.	172800	IN	A	199.19.54.1
a2.org.afilias-nst.info.	172800	IN	A	199.249.112.1
a0.org.afilias-nst.info.	172800	IN	A	199.19.56.1
d0.org.afilias-nst.org.	172800	IN	AAAA	2001:500:f::1
c0.org.afilias-nst.info.	172800	IN	AAAA	2001:500:b::1
b2.org.afilias-nst.org.	172800	IN	AAAA	2001:500:48::1
b0.org.afilias-nst.org.	172800	IN	AAAA	2001:500:c::1
a2.org.afilias-nst.info.	172800	IN	AAAA	2001:500:40::1
a0.org.afilias-nst.info.	172800	IN	AAAA	2001:500:e::1

;; GZPACK: H4sIAAAAAAAA/1pU2cjAwMjAwMDGwMucX5QO4jBCGEwMjAxMixkYJJiSDEAi3IlpmTmZicW6ecUlYBXoylKIUSbJlIihjCUzLy0fU50RceqSiTJPgikJwzywClzOBgUEWCfLcWFLRpy2ICszZcRlCZKqnxWMuAIU2SwzRpwBgGxYASPO8EQ2zYIRpzdloKoEFBhZGRj4GWAAj5dRtXAjacHlfVQdHsg6iHIWD5IOnMGCqsUBWQtxPuFDaGFg0GS5AGbKMHAxSPw9ezkv49wtL1BOybimIbOzUJJrxwfWi4AAAAD//x3pyzo/AwAA
;; SERVER: 192.36.148.17
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @199.19.53.1 A awsdns-18.org.
;; opcode: QUERY, status: NOERROR, id: 41574
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 4, ADDITIONAL: 9

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 1232

;; QUESTION SECTION:
;awsdns-18.org.	IN	 A

;; AUTHORITY SECTION:
awsdns-18.org.	3600	IN	NS	g-ns-146.awsdns-18.org.
awsdns-18.org.	3600	IN	NS	g-ns-724.awsdns-18.org.
awsdns-18.org.	3600	IN	NS	g-ns-1045.awsdns-18.org.
awsdns-18.org.	3600	IN	NS	g-ns-1618.awsdns-18.org.

;; ADDITIONAL SECTION:
g-ns-146.awsdns-18.org.	3600	IN	A	205.251.192.146
g-ns-724.awsdns-18.org.	3600	IN	A	205.251.194.212
g-ns-1045.awsdns-18.org.	3600	IN	A	205.251.196.21
g-ns-1618.awsdns-18.org.	3600	IN	A	205.251.198.82
g-ns-146.awsdns-18.org.	3600	IN	AAAA	2600:9000:5300:9200::1
g-ns-724.awsdns-18.org.	3600	IN	AAAA	2600:9000:5302:d400::1
g-ns-1045.awsdns-18.org.	3600	IN	AAAA	2600:9000:5304:1500::1
g-ns-1618.awsdns-18.org.	3600	IN	AAAA	2600:9000:5306:5200::1

;; GZPACK: H4sIAAAAAAAA/1qU1sjAwMjAwMDCwMmZWF6cklesa2jBnF+UDhJmRBdiAqnlE2CQ4EjXBQmbmKGpIKDB3MiESA2SnBAbDExMSdRhZmiBpgSXY0E+BGtlOfv7wCRcLkRWdegKTmchKzsiitMtyMqOBeF0mQxUlYAawwSGYIZJDFDAiNOVqDqYrsB14HYxqhYWUXQtWFyPqoUtCK6FgUGT5QKEDQgAAP//sGQ3xFQCAAA=
;; SERVER: 199.19.53.1
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @205.251.192.146 A ns-1172.awsdns-18.org.
;; opcode: QUERY, status: NOERROR, id: 57929
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 4, ADDITIONAL: 9

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 4096

;; QUESTION SECTION:
;ns-1172.awsdns-18.org.	IN	 A

;; ANSWER SECTION:
ns-1172.awsdns-18.org.	172800	IN	A	205.251.196.148

;; AUTHORITY SECTION:
awsdns-18.org.	172800	IN	NS	g-ns-1045.awsdns-18.org.
awsdns-18.org.	172800	IN	NS	g-ns-146.awsdns-18.org.
awsdns-18.org.	172800	IN	NS	g-ns-1618.awsdns-18.org.
awsdns-18.org.	172800	IN	NS	g-ns-724.awsdns-18.org.

;; ADDITIONAL SECTION:
g-ns-1045.awsdns-18.org.	172800	IN	A	205.251.196.21
g-ns-1045.awsdns-18.org.	172800	IN	AAAA	2600:9000:5304:1500::1
g-ns-146.awsdns-18.org.	172800	IN	A	205.251.192.146
g-ns-146.awsdns-18.org.	172800	IN	AAAA	2600:9000:5300:9200::1
g-ns-1618.awsdns-18.org.	172800	IN	A	205.251.198.82
g-ns-1618.awsdns-18.org.	172800	IN	AAAA	2600:9000:5306:5200::1
g-ns-724.awsdns-18.org.	172800	IN	A	205.251.194.212
g-ns-724.awsdns-18.org.	172800	IN	AAAA	2600:9000:5302:d400::1

;; GZPACK: H4sIAAAAAAAA/3rk2crAwMjAyMDCwMmeV6xraGhuxJlYXpwCYlsw5xelg6XxSDEwLWZgYDn7+8gUdEkmqKQkZ7ouSNjAxBRNCS4dEhwQHSZmRGqAWWFmaEGaFeZGJugacDkWxbOiuJXJQJUJqDFMYAhmEWWAAkZcnkI2+MAknKpQzWWYBDcXp9+RDT4WhFsZqslsQWguxgwjZIMPXcGpCtVcpitwcxkYNAWgbEAAAAD//ydHGMmBAgAA
;; SERVER: 205.251.192.146
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @205.251.196.148 NS console.aws.amazon.com.
;; opcode: QUERY, status: REFUSED, id: 31024
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;console.aws.amazon.com.	IN	 NS

;; GZPACK: H4sIAAAAAAAA/6o0aGRlYGQAA/bk/Lzi/JxU5sTyYrbE3MSq/Dzm5PxcBgYmBkZAAAAA//+4teN6KAAAAA==
;; SERVER: 205.251.196.148
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @192.36.148.17 A console.aws.amazon.com.
;; opcode: QUERY, status: NOERROR, id: 60248
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 13, ADDITIONAL: 27

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 1232
; COOKIE: fdcdd36e68ceda4a0100000068d6281cb971190ab8f005d1

;; QUESTION SECTION:
;console.aws.amazon.com.	IN	 A

;; AUTHORITY SECTION:
com.	172800	IN	NS	e.gtld-servers.net.
com.	172800	IN	NS	a.gtld-servers.net.
com.	172800	IN	NS	h.gtld-servers.net.
com.	172800	IN	NS	g.gtld-servers.net.
com.	172800	IN	NS	b.gtld-servers.net.
com.	172800	IN	NS	i.gtld-servers.net.
com.	172800	IN	NS	f.gtld-servers.net.
com.	172800	IN	NS	k.gtld-servers.net.
com.	172800	IN	NS	l.gtld-servers.net.
com.	172800	IN	NS	m.gtld-servers.net.
com.	172800	IN	NS	c.gtld-servers.net.
com.	172800	IN	NS	j.gtld-servers.net.
com.	172800	IN	NS	d.gtld-servers.net.

;; ADDITIONAL SECTION:
m.gtld-servers.net.	172800	IN	A	192.55.83.30
l.gtld-servers.net.	172800	IN	A	192.41.162.30
k.gtld-servers.net.	172800	IN	A	192.52.178.30
j.gtld-servers.net.	172800	IN	A	192.48.79.30
i.gtld-servers.net.	172800	IN	A	192.43.172.30
h.gtld-servers.net.	172800	IN	A	192.54.112.30
g.gtld-servers.net.	172800	IN	A	192.42.93.30
f.gtld-servers.net.	172800	IN	A	192.35.51.30
e.gtld-servers.net.	172800	IN	A	192.12.94.30
d.gtld-servers.net.	172800	IN	A	192.31.80.30
c.gtld-servers.net.	172800	IN	A	192.26.92.30
b.gtld-servers.net.	172800	IN	A	192.33.14.30
a.gtld-servers.net.	172800	IN	A	192.5.6.30
m.gtld-servers.net.	172800	IN	AAAA	2001:501:b1f9::30
l.gtld-servers.net.	172800	IN	AAAA	2001:500:d937::30
k.gtld-servers.net.	172800	IN	AAAA	2001:503:d2d::30
j.gtld-servers.net.	172800	IN	AAAA	2001:502:7094::30
i.gtld-servers.net.	172800	IN	AAAA	2001:503:39c1::30
h.gtld-servers.net.	172800	IN	AAAA	2001:502:8cc::30
g.gtld-servers.net.	172800	IN	AAAA	2001:503:eea3::30
f.gtld-servers.net.	172800	IN	AAAA	2001:503:d414::30
e.gtld-servers.net.	172800	IN	AAAA	2001:502:1ca1::30
d.gtld-servers.net.	172800	IN	AAAA	2001:500:856e::30
c.gtld-servers.net.	172800	IN	AAAA	2001:503:83eb::30
b.gtld-servers.net.	172800	IN	AAAA	2001:503:231d::2:30
a.gtld-servers.net.	172800	IN	AAAA	2001:503:a83e::2:30

;; GZPACK: H4sIAAAAAAAA/4TVv0rzUBgG8DdJ2++jtOLQwT/xVelilUJBsbh4AS4KLg4qxDa2apvUpii4iXgH3oB2cXDRSTfdVRRF0FsoiKuDIKkV36MPnE4N+eXk5H2ekNbCLpFBREnq/1fwvcCvuJazHcScqrPje1bBr4bnja8/JhlkNolShpsoNSrFbODWt9x6YHlug34TR0/KelLSkxU9WdOTVT3Z0JOKnlT1pKAn63pS/EvQzcN421dELvPzjJ5AiMwRozEIMXHGaHNC5GYZBSLE2AmjbggxWWNUDSFGlxhlKkR6nFGPhUgsM5qiEINzjNISom+RUUOFGO5i9LIIEY0xTM7uiO4hI2qcvtP3LwdTlJqe80KjRKW2klmhUbpSm7UDoVHSytpTV0Kj1JW1/18LjRqgrP3aFBq1QdGPKaFRM5Sd2IdCo5Yo8973hEaNUXay1xIatUfR6YGONSkHm6To4+kfTZSJ3LUPbIpTz8fNg1e+fZkJPwjlpxH7YrM3fv4Wvf8MAAD//2gFn1wmBgAA
;; SERVER: 192.36.148.17
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @192.5.6.30 A console.aws.amazon.com.
;; opcode: QUERY, status: NOERROR, id: 62588
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 8, ADDITIONAL: 5

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 4096

;; QUESTION SECTION:
;console.aws.amazon.com.	IN	 A

;; AUTHORITY SECTION:
amazon.com.	172800	IN	NS	ns1.amzndns.org.
amazon.com.	172800	IN	NS	ns2.amzndns.org.
amazon.com.	172800	IN	NS	ns1.amzndns.co.uk.
amazon.com.	172800	IN	NS	ns2.amzndns.co.uk.
amazon.com.	172800	IN	NS	ns1.amzndns.net.
amazon.com.	172800	IN	NS	ns2.amzndns.net.
amazon.com.	172800	IN	NS	ns1.amzndns.com.
amazon.com.	172800	IN	NS	ns2.amzndns.com.

;; ADDITIONAL SECTION:
ns1.amzndns.com.	172800	IN	A	156.154.64.10
ns1.amzndns.com.	172800	IN	AAAA	2001:502:f3ff::10
ns2.amzndns.com.	172800	IN	A	156.154.68.10
ns2.amzndns.com.	172800	IN	AAAA	2610:a1:1016::10

;; GZPACK: H4sIAAAAAAAA//pS08jAwMjAwMDBwMqenJ9XnJ+TypxYXsyWmJtYlZ/HnJyfC5JnROEzMTAyMC1mYBBkzis2ZE/MrcpLyStmzi9KZ8CpzIiwMmFk05iS85lKs3ErNCJGIar78lJLiHEfXmUI00BSRJgGksLQBwpQsFqWObMcuDClZaDSAgqMrEyf/zPAgACG0cgmuXBhSsNNUhNgWCgghjCJgUFTAMoGBAAA//9jSh98AwIAAA==
;; SERVER: 192.5.6.30
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @156.154.64.10 A console.aws.amazon.com.
;; opcode: QUERY, status: NOERROR, id: 224
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 4, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 4096

;; QUESTION SECTION:
;console.aws.amazon.com.	IN	 A

;; ANSWER SECTION:
console.aws.amazon.com.	7200	IN	CNAME	console.cname-proxy.amazon.com.

;; AUTHORITY SECTION:
cname-proxy.amazon.com.	60	IN	NS	ns-1313.awsdns-36.org.
cname-proxy.amazon.com.	60	IN	NS	ns-1878.awsdns-42.co.uk.
cname-proxy.amazon.com.	60	IN	NS	ns-429.awsdns-53.com.
cname-proxy.amazon.com.	60	IN	NS	ns-689.awsdns-22.net.

;; GZPACK: H4sIAAAAAAAA/2J40MrAwMjAyMDCwMienJ9XnJ+TypxYXsyWmJtYlZ/HnJyfC5bHKcfKwMjAIKPAoABTwZ2cl5ibqltQlF9RiawSlzgDE8gEBhsGcfa8Yl1DY0NjzsTy4pS8Yl1jM+b8onTCGiXBGi3MLWAaTYyYkvOZSrMJaxVjAyu3hOk0NSbOrWB9ZhZwfUZGzHmpJQwMDJoCDBAACAAA///yC/6eWQEAAA==
;; SERVER: 156.154.64.10
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @192.36.148.17 A console.cname-proxy.amazon.com.
;; opcode: QUERY, status: NOERROR, id: 59718
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 13, ADDITIONAL: 27

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 1232
; COOKIE: fdcdd36e68ceda4a0100000068d6281cb971190ab8f005d1

;; QUESTION SECTION:
;console.cname-proxy.amazon.com.	IN	 A

;; AUTHORITY SECTION:
com.	172800	IN	NS	i.gtld-servers.net.
com.	172800	IN	NS	d.gtld-servers.net.
com.	172800	IN	NS	j.gtld-servers.net.
com.	172800	IN	NS	l.gtld-servers.net.
com.	172800	IN	NS	g.gtld-servers.net.
com.	172800	IN	NS	h.gtld-servers.net.
com.	172800	IN	NS	e.gtld-servers.net.
com.	172800	IN	NS	c.gtld-servers.net.
com.	172800	IN	NS	b.gtld-servers.net.
com.	172800	IN	NS	a.gtld-servers.net.
com.	172800	IN	NS	m.gtld-servers.net.
com.	172800	IN	NS	f.gtld-servers.net.
com.	172800	IN	NS	k.gtld-servers.net.

;; ADDITIONAL SECTION:
m.gtld-servers.net.	172800	IN	A	192.55.83.30
l.gtld-servers.net.	172800	IN	A	192.41.162.30
k.gtld-servers.net.	172800	IN	A	192.52.178.30
j.gtld-servers.net.	172800	IN	A	192.48.79.30
i.gtld-servers.net.	172800	IN	A	192.43.172.30
h.gtld-servers.net.	172800	IN	A	192.54.112.30
g.gtld-servers.net.	172800	IN	A	192.42.93.30
f.gtld-servers.net.	172800	IN	A	192.35.51.30
e.gtld-servers.net.	172800	IN	A	192.12.94.30
d.gtld-servers.net.	172800	IN	A	192.31.80.30
c.gtld-servers.net.	172800	IN	A	192.26.92.30
b.gtld-servers.net.	172800	IN	A	192.33.14.30
a.gtld-servers.net.	172800	IN	A	192.5.6.30
m.gtld-servers.net.	172800	IN	AAAA	2001:501:b1f9::30
l.gtld-servers.net.	172800	IN	AAAA	2001:500:d937::30
k.gtld-servers.net.	172800	IN	AAAA	2001:503:d2d::30
j.gtld-servers.net.	172800	IN	AAAA	2001:502:7094::30
i.gtld-servers.net.	172800	IN	AAAA	2001:503:39c1::30
h.gtld-servers.net.	172800	IN	AAAA	2001:502:8cc::30
g.gtld-servers.net.	172800	IN	AAAA	2001:503:eea3::30
f.gtld-servers.net.	172800	IN	AAAA	2001:503:d414::30
e.gtld-servers.net.	172800	IN	AAAA	2001:502:1ca1::30
d.gtld-servers.net.	172800	IN	AAAA	2001:500:856e::30
c.gtld-servers.net.	172800	IN	AAAA	2001:503:83eb::30
b.gtld-servers.net.	172800	IN	AAAA	2001:503:231d::2:30
a.gtld-servers.net.	172800	IN	AAAA	2001:503:a83e::2:30

;; GZPACK: H4sIAAAAAAAA/4TVTS87URQG8DPTl/8/1YpFF17GQbpR0qQJ0dhYWtiQ2CIZ09GiM1NtI9iJ+Aa+AN1Y2LBixx4hRMI3EInYWkikVXEuT3JnNZP85uTmPE9ynye3iQwiSlDPPyfwq0HJbXN823Mz5UqwsRm1PXsr8ENO4DWc8fVikkFmnShpLMcLtVI+U3Ur626lGvLdGv0meT1Z0ZOSnhT0pKgnrp44erKoJ7aeeHqypCerfwma3Ii3+Uf4PDfLaOFCpA8YzRVi9IRRrkJkpxn1R4jhI0aRCTFWZpS7EEPzjJYkRGqEUepCxBcY1ViIvhlGtRCie45RK4QYaGdUCiEiUYbJWS3R0W9EjON3+n6yMEWp6TEnNEpU6lAiIzRKV2qzvCc0SlqZPX4hNEpdmf3/UmjUAGX2a11o1AZF3yeFRs1QTmLtC41aoux71xcaNUY5yc6L0Kg9ik71tqxJWdgkRR9O/GiidPim+WFRjDo/ru784vXTVONiKD4MWmdrXbHTt8jtZwAAAP//zvLrkC4GAAA=
;; SERVER: 192.36.148.17
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @192.5.6.30 A console.cname-proxy.amazon.com.
;; opcode: QUERY, status: NOERROR, id: 44638
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 8, ADDITIONAL: 5

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 4096

;; QUESTION SECTION:
;console.cname-proxy.amazon.com.	IN	 A

;; AUTHORITY SECTION:
amazon.com.	172800	IN	NS	ns1.amzndns.org.
amazon.com.	172800	IN	NS	ns2.amzndns.org.
amazon.com.	172800	IN	NS	ns1.amzndns.co.uk.
amazon.com.	172800	IN	NS	ns2.amzndns.co.uk.
amazon.com.	172800	IN	NS	ns1.amzndns.net.
amazon.com.	172800	IN	NS	ns2.amzndns.net.
amazon.com.	172800	IN	NS	ns1.amzndns.com.
amazon.com.	172800	IN	NS	ns2.amzndns.com.

;; ADDITIONAL SECTION:
ns1.amzndns.com.	172800	IN	A	156.154.64.10
ns1.amzndns.com.	172800	IN	AAAA	2001:502:f3ff::10
ns2.amzndns.com.	172800	IN	A	156.154.68.10
ns2.amzndns.com.	172800	IN	AAAA	2610:a1:1016::10

;; GZPACK: H4sIAAAAAAAA/1oX18jAwMjAwMDBwMqenJ9XnJ+Typ2cl5ibqltQlF9RyZaYm1iVn8ecnJ8LUseIwmdiYGRgWszAIMicV2zInphblZeSV8ycX5TOgFOZEWFlwsimMSXnM5Vm41ZoRIxCVPflpZYQ4z68yhCmgaSIMA0khaEPFKBgtSxzZjlwYUrLQKUFFBhZmT7/Z4ABAQyjkU1y4cKUhpukJsCwUEAMYRIDg6YAlA0IAAD//3TvjYoLAgAA
;; SERVER: 192.5.6.30
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @156.154.64.10 A console.cname-proxy.amazon.com.
;; opcode: QUERY, status: NOERROR, id: 2411
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 4, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 4096

;; QUESTION SECTION:
;console.cname-proxy.amazon.com.	IN	 A

;; AUTHORITY SECTION:
cname-proxy.amazon.com.	60	IN	NS	ns-429.awsdns-53.com.
cname-proxy.amazon.com.	60	IN	NS	ns-689.awsdns-22.net.
cname-proxy.amazon.com.	60	IN	NS	ns-1313.awsdns-36.org.
cname-proxy.amazon.com.	60	IN	NS	ns-1878.awsdns-42.co.uk.

;; GZPACK: H4sIAAAAAAAA/+LMbmRgYGRgYGBhYGRPzs8rzs9J5U7OS8xN1S0oyq+oZEvMTazKz2NOzs8FqWPEKccENsWGQYwtr1jXxMiSM7G8OCWvWNfUGCxPnD4zC7g+IyPmvNQSwvrE2fOKdQ2NDY1hGo3NmPOL0glrlARrtDC3gGk0MWJKzmcqzWZgYNAUYIAAQAAAAP//4Vru1R8BAAA=
;; SERVER: 156.154.64.10
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @192.36.148.17 A ns-1313.awsdns-36.org.
;; opcode: QUERY, status: NOERROR, id: 57038
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 6, ADDITIONAL: 13

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 1232
; COOKIE: fdcdd36e68ceda4a0100000068d6281cbf4b4fcef2255a3e

;; QUESTION SECTION:
;ns-1313.awsdns-36.org.	IN	 A

;; AUTHORITY SECTION:
org.	172800	IN	NS	a0.org.afilias-nst.info.
org.	172800	IN	NS	b2.org.afilias-nst.org.
org.	172800	IN	NS	c0.org.afilias-nst.info.
org.	172800	IN	NS	a2.org.afilias-nst.info.
org.	172800	IN	NS	b0.org.afilias-nst.org.
org.	172800	IN	NS	d0.org.afilias-nst.org.

;; ADDITIONAL SECTION:
d0.org.afilias-nst.org.	172800	IN	A	199.19.57.1
c0.org.afilias-nst.info.	172800	IN	A	199.19.53.1
b2.org.afilias-nst.org.	172800	IN	A	199.249.120.1
b0.org.afilias-nst.org.	172800	IN	A	199.19.54.1
a2.org.afilias-nst.info.	172800	IN	A	199.249.112.1
a0.org.afilias-nst.info.	172800	IN	A	199.19.56.1
d0.org.afilias-nst.org.	172800	IN	AAAA	2001:500:f::1
c0.org.afilias-nst.info.	172800	IN	AAAA	2001:500:b::1
b2.org.afilias-nst.org.	172800	IN	AAAA	2001:500:48::1
b0.org.afilias-nst.org.	172800	IN	AAAA	2001:500:c::1
a2.org.afilias-nst.info.	172800	IN	AAAA	2001:500:40::1
a0.org.afilias-nst.info.	172800	IN	AAAA	2001:500:e::1

;; GZPACK: H4sIAAAAAAAA/7p3rpGBgZGBgYGNgZc9r1jX0NjQmDOxvDglr1jX2Iw5vygdJM0IYTAxMDIwLWZgkGRKNACJcCemZeZkJhbr5hWXsGTmpeUzoKqTYEoyQlcHVoFuXDJRxkkyJWIYh8NaDPOwWCvBlIJdGS5xUECAdbIcF7ZkxOloZGWmjLiCAEnVzwpGXC5GNsuMEaf/kQ0rYMQZO8imWTDi9KYMVJWAAiMrAwM/Awzg8TKqFm4kLbi8j6rDA1kHUc7iQdKBM1hQtTggayHOJ3wILQwMmiwXwEwZBi4Gib9nL+dlnLvlBco7Gdc0ZHYWSnLt+MB6ERAAAP//8xCurlEDAAA=
;; SERVER: 192.36.148.17
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @199.19.53.1 A ns-1313.awsdns-36.org.
;; opcode: QUERY, status: NOERROR, id: 48586
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 4, ADDITIONAL: 9

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 1232

;; QUESTION SECTION:
;ns-1313.awsdns-36.org.	IN	 A

;; AUTHORITY SECTION:
awsdns-36.org.	3600	IN	NS	g-ns-1063.awsdns-36.org.
awsdns-36.org.	3600	IN	NS	g-ns-1636.awsdns-36.org.
awsdns-36.org.	3600	IN	NS	g-ns-164.awsdns-36.org.
awsdns-36.org.	3600	IN	NS	g-ns-742.awsdns-36.org.

;; ADDITIONAL SECTION:
g-ns-164.awsdns-36.org.	3600	IN	A	205.251.192.164
g-ns-742.awsdns-36.org.	3600	IN	A	205.251.194.230
g-ns-1063.awsdns-36.org.	3600	IN	A	205.251.196.39
g-ns-1636.awsdns-36.org.	3600	IN	A	205.251.198.100
g-ns-164.awsdns-36.org.	3600	IN	AAAA	2600:9000:5300:a400::1
g-ns-742.awsdns-36.org.	3600	IN	AAAA	2600:9000:5302:e600::1
g-ns-1063.awsdns-36.org.	3600	IN	AAAA	2600:9000:5304:2700::1
g-ns-1636.awsdns-36.org.	3600	IN	AAAA	2600:9000:5306:6400::1

;; GZPACK: H4sIAAAAAAAA/9p7qpGBgZGBgYGFgZM9r1jX0NjQmDOxvDglr1jX2Iw5vygdJM2ILsQE0sMnwCDJma4L0mVghq6LkA4zYzMidUhwQHWYkKbB3MQITQUug0A+BOtkOfv7wBJcupFVHXqG0+PIyo6o4/QtsrJjKThdJgNVJaDGMIEhmGEJAxQw4nQlqg6mZ3AduF2MqoVFHV0LFtejamFLgWthYNBkuQBhAwIAAP//qs12PVwCAAA=
;; SERVER: 199.19.53.1
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @205.251.192.164 A ns-1313.awsdns-36.org.
;; opcode: QUERY, status: NOERROR, id: 56856
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 4, ADDITIONAL: 9

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 4096

;; QUESTION SECTION:
;ns-1313.awsdns-36.org.	IN	 A

;; ANSWER SECTION:
ns-1313.awsdns-36.org.	172800	IN	A	205.251.197.33

;; AUTHORITY SECTION:
awsdns-36.org.	172800	IN	NS	g-ns-1063.awsdns-36.org.
awsdns-36.org.	172800	IN	NS	g-ns-1636.awsdns-36.org.
awsdns-36.org.	172800	IN	NS	g-ns-164.awsdns-36.org.
awsdns-36.org.	172800	IN	NS	g-ns-742.awsdns-36.org.

;; ADDITIONAL SECTION:
g-ns-1063.awsdns-36.org.	172800	IN	A	205.251.196.39
g-ns-1063.awsdns-36.org.	172800	IN	AAAA	2600:9000:5304:2700::1
g-ns-1636.awsdns-36.org.	172800	IN	A	205.251.198.100
g-ns-1636.awsdns-36.org.	172800	IN	AAAA	2600:9000:5306:6400::1
g-ns-164.awsdns-36.org.	172800	IN	A	205.251.192.164
g-ns-164.awsdns-36.org.	172800	IN	AAAA	2600:9000:5300:a400::1
g-ns-742.awsdns-36.org.	172800	IN	A	205.251.194.230
g-ns-742.awsdns-36.org.	172800	IN	AAAA	2600:9000:5302:e600::1

;; GZPACK: H4sIAAAAAAAA/7on0crAwMjAyMDCwMmeV6xraGxozJlYXpySV6xrbMacX5QOlsYjxcC0mIGB5ezvo4rokkxQSUnOdF2QfgMzdP2EdJgZmxGpQ4IDqsOENA3mJkboGnA5FtmzR9RxK5OBKhNQY5jAEMyizgAFjDg9hWzysRTcylBNZkuBm4zL88gGH1iCUxWquQxL0MzFDCNkcw89w6kK1VymZ3BzGRg0BaBsQAAAAP//KxpVQIECAAA=
;; SERVER: 205.251.192.164
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @205.251.192.164 A ns-1313.awsdns-36.org.
;; opcode: QUERY, status: NOERROR, id: 60137
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 4, ADDITIONAL: 9

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 4096

;; QUESTION SECTION:
;ns-1313.awsdns-36.org.	IN	 A

;; ANSWER SECTION:
ns-1313.awsdns-36.org.	172800	IN	A	205.251.197.33

;; AUTHORITY SECTION:
awsdns-36.org.	172800	IN	NS	g-ns-1063.awsdns-36.org.
awsdns-36.org.	172800	IN	NS	g-ns-1636.awsdns-36.org.
awsdns-36.org.	172800	IN	NS	g-ns-164.awsdns-36.org.
awsdns-36.org.	172800	IN	NS	g-ns-742.awsdns-36.org.

;; ADDITIONAL SECTION:
g-ns-1063.awsdns-36.org.	172800	IN	A	205.251.196.39
g-ns-1063.awsdns-36.org.	172800	IN	AAAA	2600:9000:5304:2700::1
g-ns-1636.awsdns-36.org.	172800	IN	A	205.251.198.100
g-ns-1636.awsdns-36.org.	172800	IN	AAAA	2600:9000:5306:6400::1
g-ns-164.awsdns-36.org.	172800	IN	A	205.251.192.164
g-ns-164.awsdns-36.org.	172800	IN	AAAA	2600:9000:5300:a400::1
g-ns-742.awsdns-36.org.	172800	IN	A	205.251.194.230
g-ns-742.awsdns-36.org.	172800	IN	AAAA	2600:9000:5302:e600::1

;; GZPACK: H4sIAAAAAAAA/3r1spWBgZGBkYGFgZM9r1jX0NjQmDOxvDglr1jX2Iw5vygdLI1HioFpMQMDy9nfR+3QJZmgkpKc6bog/QZm6PoJ6TAzNiNShwQHVIcJaRrMTYzQNeByLLJnj6jjViYDVSagxjCBIZhFnQEKGHF6CtnkYym4laGazJYCNxmX55ENPrAEpypUcxmWoJmLGUbI5h56hlMVqrlMz+DmMjBoCkDZgAAAAP//9SOux4ECAAA=
;; SERVER: 205.251.192.164
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @205.251.192.164 A ns-1313.awsdns-36.org.
;; opcode: QUERY, status: NOERROR, id: 21773
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 4, ADDITIONAL: 9

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 4096

;; QUESTION SECTION:
;ns-1313.awsdns-36.org.	IN	 A

;; ANSWER SECTION:
ns-1313.awsdns-36.org.	172800	IN	A	205.251.197.33

;; AUTHORITY SECTION:
awsdns-36.org.	172800	IN	NS	g-ns-1063.awsdns-36.org.
awsdns-36.org.	172800	IN	NS	g-ns-1636.awsdns-36.org.
awsdns-36.org.	172800	IN	NS	g-ns-164.awsdns-36.org.
awsdns-36.org.	172800	IN	NS	g-ns-742.awsdns-36.org.

;; ADDITIONAL SECTION:
g-ns-1063.awsdns-36.org.	172800	IN	A	205.251.196.39
g-ns-1063.awsdns-36.org.	172800	IN	AAAA	2600:9000:5304:2700::1
g-ns-1636.awsdns-36.org.	172800	IN	A	205.251.198.100
g-ns-1636.awsdns-36.org.	172800	IN	AAAA	2600:9000:5306:6400::1
g-ns-164.awsdns-36.org.	172800	IN	A	205.251.192.164
g-ns-164.awsdns-36.org.	172800	IN	AAAA	2600:9000:5300:a400::1
g-ns-742.awsdns-36.org.	172800	IN	A	205.251.194.230
g-ns-742.awsdns-36.org.	172800	IN	AAAA	2600:9000:5302:e600::1

;; GZPACK: H4sIAAAAAAAA/wrlbWVgYGRgZGBh4GTPK9Y1NDY05kwsL07JK9Y1NmPOL0oHS+ORYmBazMDAcvb3UUV0SSaopCRnui5Iv4EZun5COsyMzYjUIcEB1WFCmgZzEyN0Dbgci+zZI+q4lclAlQmoMUxgCGZRZ4ACRpyeQjb5WApuZagms6XATcbleWSDDyzBqQrVXIYlaOZihhGyuYee4VSFai7TM7i5DAyaAlA2IAAA//+9q4gygQIAAA==
;; SERVER: 205.251.192.164
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @205.251.192.164 A ns-1313.awsdns-36.org.
;; opcode: QUERY, status: NOERROR, id: 32995
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 4, ADDITIONAL: 9

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 4096

;; QUESTION SECTION:
;ns-1313.awsdns-36.org.	IN	 A

;; ANSWER SECTION:
ns-1313.awsdns-36.org.	172800	IN	A	205.251.197.33

;; AUTHORITY SECTION:
awsdns-36.org.	172800	IN	NS	g-ns-1063.awsdns-36.org.
awsdns-36.org.	172800	IN	NS	g-ns-1636.awsdns-36.org.
awsdns-36.org.	172800	IN	NS	g-ns-164.awsdns-36.org.
awsdns-36.org.	172800	IN	NS	g-ns-742.awsdns-36.org.

;; ADDITIONAL SECTION:
g-ns-1063.awsdns-36.org.	172800	IN	A	205.251.196.39
g-ns-1063.awsdns-36.org.	172800	IN	AAAA	2600:9000:5304:2700::1
g-ns-1636.awsdns-36.org.	172800	IN	A	205.251.198.100
g-ns-1636.awsdns-36.org.	172800	IN	AAAA	2600:9000:5306:6400::1
g-ns-164.awsdns-36.org.	172800	IN	A	205.251.192.164
g-ns-164.awsdns-36.org.	172800	IN	AAAA	2600:9000:5300:a400::1
g-ns-742.awsdns-36.org.	172800	IN	A	205.251.194.233
g-ns-742.awsdns-36.org.	172800	IN	AAAA	2600:9000:5302:e900::1

;; GZPACK: H4sIAAAAAAAA/2p43MrAwMjAyMDCwMmeV6xraGxixJlYXpySV6xrbMmcX5QOlsYjxcC0mIGB5ezvo3bokkxQSUnOdF2QfgMzMzQlhHSYGVsSqUOCA6rDnDQN5iam6BpwORbZs0e0cCuTgSoTUGOYwBDMosUABYw4PYVs8rF03MpQTWZLh5uMy/PIBh9YjlMVqrkMy9HMxQwjZHMPvcSpCtVcppdwcxkYNAWgbEAAAAD//zYT1i6BAgAA
;; SERVER: 205.251.192.164
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @205.251.192.164 A ns-1313.awsdns-36.org.
;; opcode: QUERY, status: NOERROR, id: 39633
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 4, ADDITIONAL: 9

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 4096

;; QUESTION SECTION:
;ns-1313.awsdns-36.org.	IN	 A

;; ANSWER SECTION:
ns-1313.awsdns-36.org.	172800	IN	A	205.251.197.33

;; AUTHORITY SECTION:
awsdns-36.org.	172800	IN	NS	g-ns-1063.awsdns-36.org.
awsdns-36.org.	172800	IN	NS	g-ns-1636.awsdns-36.org.
awsdns-36.org.	172800	IN	NS	g-ns-164.awsdns-36.org.
awsdns-36.org.	172800	IN	NS	g-ns-742.awsdns-36.org.

;; ADDITIONAL SECTION:
g-ns-1063.awsdns-36.org.	172800	IN	A	205.251.196.39
g-ns-1063.awsdns-36.org.	172800	IN	AAAA	2600:9000:5304:2700::1
g-ns-1636.awsdns-36.org.	172800	IN	A	205.251.198.100
g-ns-1636.awsdns-36.org.	172800	IN	AAAA	2600:9000:5306:6400::1
g-ns-164.awsdns-36.org.	172800	IN	A	205.251.192.164
g-ns-164.awsdns-36.org.	172800	IN	AAAA	2600:9000:5300:a400::1
g-ns-742.awsdns-36.org.	172800	IN	A	205.251.194.233
g-ns-742.awsdns-36.org.	172800	IN	AAAA	2600:9000:5302:e900::1

;; GZPACK: H4sIAAAAAAAA/5p1sZWBgZGBkYGFgZM9r1jX0NjEiDOxvDglr1jX2JI5vygdLI1HioFpMQMDy9nfR+TRJZmgkpKc6bog/QZmZmhKCOkwM7YkUocEB1SHOWkazE1M0TXgciyyZ49o4VYmA1UmoMYwgSGYRYsBChhxegrZ5GPpuJWhmsyWDjcZl+eRDT6wHKcqVHMZlqOZixlGyOYeeolTFaq5TC/h5jIwaApA2YAAAAD//0JMXhOBAgAA
;; SERVER: 205.251.192.164
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @205.251.197.33 A console.cname-proxy.amazon.com.
;; opcode: QUERY, status: NOERROR, id: 50784
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 4, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 4096

;; QUESTION SECTION:
;console.cname-proxy.amazon.com.	IN	 A

;; ANSWER SECTION:
console.cname-proxy.amazon.com.	60	IN	CNAME	lbr.us.console.amazonaws.com.

;; AUTHORITY SECTION:
cname-proxy.amazon.com.	1801	IN	NS	ns-1313.awsdns-36.org.
cname-proxy.amazon.com.	1801	IN	NS	ns-1878.awsdns-42.co.uk.
cname-proxy.amazon.com.	1801	IN	NS	ns-429.awsdns-53.com.
cname-proxy.amazon.com.	1801	IN	NS	ns-689.awsdns-22.net.

;; GZPACK: H4sIAAAAAAAA/4zOsa6CMBjF8dP2XghxcdK4uDswQBUx8WGslTgI/QyfBHX31XwuYwluBs/8/yXnuXsAAgJ/EKElx1QWI+tMVcTnmq63wFTmTk5Zqnw32PxDANhirsp9LRvuQdRFpmXfffXy7cMI09BxnOhER6blg+NYZ4rq4zCceZiv8x4uU2lJNqdhOgl8vunlSv/21bss/7g0Va64AFiM0e0VAAD//4/MiOFnAQAA
;; SERVER: 205.251.197.33
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @192.36.148.17 A lbr.us.console.amazonaws.com.
;; opcode: QUERY, status: NOERROR, id: 60079
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 13, ADDITIONAL: 27

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 1232
; COOKIE: fdcdd36e68ceda4a0100000068d6281cbf4b4fcef2255a3e

;; QUESTION SECTION:
;lbr.us.console.amazonaws.com.	IN	 A

;; AUTHORITY SECTION:
com.	172800	IN	NS	f.gtld-servers.net.
com.	172800	IN	NS	a.gtld-servers.net.
com.	172800	IN	NS	h.gtld-servers.net.
com.	172800	IN	NS	c.gtld-servers.net.
com.	172800	IN	NS	i.gtld-servers.net.
com.	172800	IN	NS	b.gtld-servers.net.
com.	172800	IN	NS	g.gtld-servers.net.
com.	172800	IN	NS	l.gtld-servers.net.
com.	172800	IN	NS	m.gtld-servers.net.
com.	172800	IN	NS	j.gtld-servers.net.
com.	172800	IN	NS	d.gtld-servers.net.
com.	172800	IN	NS	k.gtld-servers.net.
com.	172800	IN	NS	e.gtld-servers.net.

;; ADDITIONAL SECTION:
m.gtld-servers.net.	172800	IN	A	192.55.83.30
l.gtld-servers.net.	172800	IN	A	192.41.162.30
k.gtld-servers.net.	172800	IN	A	192.52.178.30
j.gtld-servers.net.	172800	IN	A	192.48.79.30
i.gtld-servers.net.	172800	IN	A	192.43.172.30
h.gtld-servers.net.	172800	IN	A	192.54.112.30
g.gtld-servers.net.	172800	IN	A	192.42.93.30
f.gtld-servers.net.	172800	IN	A	192.35.51.30
e.gtld-servers.net.	172800	IN	A	192.12.94.30
d.gtld-servers.net.	172800	IN	A	192.31.80.30
c.gtld-servers.net.	172800	IN	A	192.26.92.30
b.gtld-servers.net.	172800	IN	A	192.33.14.30
a.gtld-servers.net.	172800	IN	A	192.5.6.30
m.gtld-servers.net.	172800	IN	AAAA	2001:501:b1f9::30
l.gtld-servers.net.	172800	IN	AAAA	2001:500:d937::30
k.gtld-servers.net.	172800	IN	AAAA	2001:503:d2d::30
j.gtld-servers.net.	172800	IN	AAAA	2001:502:7094::30
i.gtld-servers.net.	172800	IN	AAAA	2001:503:39c1::30
h.gtld-servers.net.	172800	IN	AAAA	2001:502:8cc::30
g.gtld-servers.net.	172800	IN	AAAA	2001:503:eea3::30
f.gtld-servers.net.	172800	IN	AAAA	2001:503:d414::30
e.gtld-servers.net.	172800	IN	AAAA	2001:502:1ca1::30
d.gtld-servers.net.	172800	IN	AAAA	2001:500:856e::30
c.gtld-servers.net.	172800	IN	AAAA	2001:503:83eb::30
b.gtld-servers.net.	172800	IN	AAAA	2001:503:231d::2:30
a.gtld-servers.net.	172800	IN	AAAA	2001:503:a83e::2:30

;; GZPACK: H4sIAAAAAAAA/4TVv0rzUBgG8DdJ+/0p7cc3dPBPfFW6WKVQUCwuXoCLgqsKaRtbNU1qUxXcRLwDb0C7OAiik266qyiKoJegIK4OgrRWfI8+cDo18MvJe87zhDwebBAZRJSgbsvL18yV8Hch8MPAc/86FWc98J210CoElaYyPv6YZJDZIEoa8/FS3StmQre26tZCy3fr9J04elLWk4KeLOhJXk9KeuLpSUVPFvWkqCdLeuL+JGi+ZrytOyKnuWlGmxQivcvo0UKMHDHaohDZSUaZCTG0z6gbQoxWGSUmxOAso5YKkRpmdEZCxOcYZSFE7xSjigrRNcOofkL0/2P0sggR/cUwObst/vcZUePwlT5/WZii1HSfExolKrWVyAiN0pXarG4LjZJW1h47Exqlrqz951xo1ABl7eeG0KgNir5NCo2aoUxi7wiNWqKc95YvNGqMMsnmk9CoPYpO9bStSVnYJEXvjX9ponTkqnVhU4w63i5u/PLlw0Tzs1C+G7BPljtjxy/R6/cAAAD//yltflYsBgAA
;; SERVER: 192.36.148.17
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @192.5.6.30 A lbr.us.console.amazonaws.com.
;; opcode: QUERY, status: NOERROR, id: 28597
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 4, ADDITIONAL: 2

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 4096

;; QUESTION SECTION:
;lbr.us.console.amazonaws.com.	IN	 A

;; AUTHORITY SECTION:
amazonaws.com.	172800	IN	NS	ns-27.awsdns-03.com.
amazonaws.com.	172800	IN	NS	ns-967.awsdns-56.net.
amazonaws.com.	172800	IN	NS	ns-1670.awsdns-16.co.uk.
amazonaws.com.	172800	IN	NS	ns-1321.awsdns-37.org.

;; ADDITIONAL SECTION:
ns-27.awsdns-03.com.	172800	IN	A	205.251.192.27

;; GZPACK: H4sIAAAAAAAA/8rf2sjAwMjAwMDCwMSck1TEVFrMnpyfV5yfk8qZmJtYlZ+XWF7MnJyfC1LFgC7ExMDIwLSYgUGUNa9Y18icM7G8OCWvWNfAGCyNS7UYW16xrqUZXLmpGXNeaglO5ZLsecW6hmbmBjD1hmZMyflMpdk4dYiDdRgbGcJ0GJsz5xelM2B1JchfYF0sZ38fkGZg0BRggABAAAAA///i342fGwEAAA==
;; SERVER: 192.5.6.30
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @205.251.192.27 A lbr.us.console.amazonaws.com.
;; opcode: QUERY, status: NOERROR, id: 53980
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 4, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 4096

;; QUESTION SECTION:
;lbr.us.console.amazonaws.com.	IN	 A

;; AUTHORITY SECTION:
console.amazonaws.com.	7200	IN	NS	ns-1342.awsdns-39.org.
console.amazonaws.com.	7200	IN	NS	ns-1832.awsdns-37.co.uk.
console.amazonaws.com.	7200	IN	NS	ns-372.awsdns-46.com.
console.amazonaws.com.	7200	IN	NS	ns-671.awsdns-19.net.

;; GZPACK: H4sIAAAAAAAA/7p0p5GBgZGBgYGFgZE5J6mIqbSYPTk/rzg/J5UzMTexKj8vsbyYOTk/F6SKEZcUE8gIGQUGcfa8Yl1DYxMjzsTy4pS8Yl1jS+b8onQGQvokwfosjBH6zJmS85lKswnqFGMDq4ZrNDEDyxOlzczcEKbN0JI5L7WEgYFBU4ABAgABAAD//6iijoQZAQAA
;; SERVER: 205.251.192.27
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @192.36.148.17 A ns-1342.awsdns-39.org.
;; opcode: QUERY, status: NOERROR, id: 46137
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 6, ADDITIONAL: 13

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 1232
; COOKIE: fdcdd36e68ceda4a0100000068d6281dbf4b4fcef2255a3e

;; QUESTION SECTION:
;ns-1342.awsdns-39.org.	IN	 A

;; AUTHORITY SECTION:
org.	172800	IN	NS	a0.org.afilias-nst.info.
org.	172800	IN	NS	a2.org.afilias-nst.info.
org.	172800	IN	NS	c0.org.afilias-nst.info.
org.	172800	IN	NS	b2.org.afilias-nst.org.
org.	172800	IN	NS	b0.org.afilias-nst.org.
org.	172800	IN	NS	d0.org.afilias-nst.org.

;; ADDITIONAL SECTION:
d0.org.afilias-nst.org.	172800	IN	A	199.19.57.1
c0.org.afilias-nst.info.	172800	IN	A	199.19.53.1
b2.org.afilias-nst.org.	172800	IN	A	199.249.120.1
b0.org.afilias-nst.org.	172800	IN	A	199.19.54.1
a2.org.afilias-nst.info.	172800	IN	A	199.249.112.1
a0.org.afilias-nst.info.	172800	IN	A	199.19.56.1
d0.org.afilias-nst.org.	172800	IN	AAAA	2001:500:f::1
c0.org.afilias-nst.info.	172800	IN	AAAA	2001:500:b::1
b2.org.afilias-nst.org.	172800	IN	AAAA	2001:500:48::1
b0.org.afilias-nst.org.	172800	IN	AAAA	2001:500:c::1
a2.org.afilias-nst.info.	172800	IN	AAAA	2001:500:40::1
a0.org.afilias-nst.info.	172800	IN	AAAA	2001:500:e::1

;; GZPACK: H4sIAAAAAAAA/9pi2cjAwMjAwMDGwMueV6xraGxixJlYXpySV6xrbMmcX5QOkmaEMJgYGBmYFjMwSDIlGoBEuBPTMnMyE4t184pLWDLz0vIZMNQZEacumSjzJJiSMMwDq8BQhmEcVmUp2JXhEgcFBFgny3FhS0acbkZWZsqIy8lIqn5WMOJyMbJZZow4gxPZsAJGnLGDbJoFI05vykBVCSgwsjIw8DPAAB4vo2rhRtKCy/uoOjyQdRDlLB4kHTiDBVWLA7IW4nzCh9DCwKDJcgHMlGHgYpD4e/ZyXsa5W16gvJNxTUN2v7f/uU+qUXaAAAAA//9du03QUQMAAA==
;; SERVER: 192.36.148.17
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @199.19.53.1 A ns-1342.awsdns-39.org.
;; opcode: QUERY, status: NOERROR, id: 12275
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 4, ADDITIONAL: 9

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 1232

;; QUESTION SECTION:
;ns-1342.awsdns-39.org.	IN	 A

;; AUTHORITY SECTION:
awsdns-39.org.	3600	IN	NS	g-ns-1066.awsdns-39.org.
awsdns-39.org.	3600	IN	NS	g-ns-1639.awsdns-39.org.
awsdns-39.org.	3600	IN	NS	g-ns-745.awsdns-39.org.
awsdns-39.org.	3600	IN	NS	g-ns-167.awsdns-39.org.

;; ADDITIONAL SECTION:
g-ns-167.awsdns-39.org.	3600	IN	A	205.251.192.167
g-ns-745.awsdns-39.org.	3600	IN	A	205.251.194.233
g-ns-1066.awsdns-39.org.	3600	IN	A	205.251.196.42
g-ns-1639.awsdns-39.org.	3600	IN	A	205.251.198.103
g-ns-167.awsdns-39.org.	3600	IN	AAAA	2600:9000:5300:a700::1
g-ns-745.awsdns-39.org.	3600	IN	AAAA	2600:9000:5302:e900::1
g-ns-1066.awsdns-39.org.	3600	IN	AAAA	2600:9000:5304:2a00::1
g-ns-1639.awsdns-39.org.	3600	IN	AAAA	2600:9000:5306:6700::1

;; GZPACK: H4sIAAAAAAAA/9L/3MjAwMjAwMDCwMmeV6xraGxixJlYXpySV6xrbMmcX5QOkmZEF2IC6eETYJDkTNcF6TIwM0NTQkiHmbElkTokOMA6zE1MSdNgaGaOpgKXOMiHYJ0sZ38fWI7LOmRVh17i9DiysiNaOH2LrOxYOk6XyUBVCagxTGAIZljOAAWMOF2JqoPpJVwHbhejamHRQteCxfWoWtjS4VoYGDRZLkDYgAAAAP//3Zbrj1wCAAA=
;; SERVER: 199.19.53.1
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @205.251.192.167 A ns-1342.awsdns-39.org.
;; opcode: QUERY, status: NOERROR, id: 28769
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 4, ADDITIONAL: 9

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 4096

;; QUESTION SECTION:
;ns-1342.awsdns-39.org.	IN	 A

;; ANSWER SECTION:
ns-1342.awsdns-39.org.	172800	IN	A	205.251.197.62

;; AUTHORITY SECTION:
awsdns-39.org.	172800	IN	NS	g-ns-1066.awsdns-39.org.
awsdns-39.org.	172800	IN	NS	g-ns-1639.awsdns-39.org.
awsdns-39.org.	172800	IN	NS	g-ns-167.awsdns-39.org.
awsdns-39.org.	172800	IN	NS	g-ns-745.awsdns-39.org.

;; ADDITIONAL SECTION:
g-ns-1066.awsdns-39.org.	172800	IN	A	205.251.196.42
g-ns-1066.awsdns-39.org.	172800	IN	AAAA	2600:9000:5304:2a00::1
g-ns-1639.awsdns-39.org.	172800	IN	A	205.251.198.103
g-ns-1639.awsdns-39.org.	172800	IN	AAAA	2600:9000:5306:6700::1
g-ns-167.awsdns-39.org.	172800	IN	A	205.251.192.167
g-ns-167.awsdns-39.org.	172800	IN	AAAA	2600:9000:5300:a700::1
g-ns-745.awsdns-39.org.	172800	IN	A	205.251.194.233
g-ns-745.awsdns-39.org.	172800	IN	AAAA	2600:9000:5302:e900::1

;; GZPACK: H4sIAAAAAAAA/ypIbGVgYGRgZGBh4GTPK9Y1NDYx4kwsL07JK9Y1tmTOL0oHS+ORYmBazMDAcvb3UTt0SSaopCRnui5Iv4GZGZoSQjrMjC2J1CHBAdVhTpoGcxNTdA24HIvs2SNauJXJQJUJqDFMYAhm0WKAAkacnkI2+Vg6bmWoJrOlw03G5Xlkgw8sx6kK1VyG5WjmYoYRsrmHXuJUhWou00u4uQwMmgJQNiAAAP//wyvl/oECAAA=
;; SERVER: 205.251.192.167
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @205.251.192.167 A ns-1342.awsdns-39.org.
;; opcode: QUERY, status: NOERROR, id: 32995
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 4, ADDITIONAL: 9

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 4096

;; QUESTION SECTION:
;ns-1342.awsdns-39.org.	IN	 A

;; ANSWER SECTION:
ns-1342.awsdns-39.org.	172800	IN	A	205.251.197.62

;; AUTHORITY SECTION:
awsdns-39.org.	172800	IN	NS	g-ns-1066.awsdns-39.org.
awsdns-39.org.	172800	IN	NS	g-ns-1639.awsdns-39.org.
awsdns-39.org.	172800	IN	NS	g-ns-167.awsdns-39.org.
awsdns-39.org.	172800	IN	NS	g-ns-745.awsdns-39.org.

;; ADDITIONAL SECTION:
g-ns-1066.awsdns-39.org.	172800	IN	A	205.251.196.42
g-ns-1066.awsdns-39.org.	172800	IN	AAAA	2600:9000:5304:2a00::1
g-ns-1639.awsdns-39.org.	172800	IN	A	205.251.198.103
g-ns-1639.awsdns-39.org.	172800	IN	AAAA	2600:9000:5306:6700::1
g-ns-167.awsdns-39.org.	172800	IN	A	205.251.192.167
g-ns-167.awsdns-39.org.	172800	IN	AAAA	2600:9000:5300:a700::1
g-ns-745.awsdns-39.org.	172800	IN	A	205.251.194.233
g-ns-745.awsdns-39.org.	172800	IN	AAAA	2600:9000:5302:e900::1

;; GZPACK: H4sIAAAAAAAA/2p43MrAwMjAyMDCwMmeV6xraGxixJlYXpySV6xrbMmcX5QOlsYjxcC0mIGB5ezvo3bokkxQSUnOdF2QfgMzMzQlhHSYGVsSqUOCA6rDnDQN5iam6BpwORbZs0e0cCuTgSoTUGOYwBDMosUABYw4PYVs8rF03MpQTWZLh5uMy/PIBh9YjlMVqrkMy9HMxQwjZHMPvcSpCtVcppdwcxkYNAWgbEAAAAD//zFNhjiBAgAA
;; SERVER: 205.251.192.167
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @205.251.192.167 A ns-1342.awsdns-39.org.
;; opcode: QUERY, status: NOERROR, id: 39633
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 4, ADDITIONAL: 9

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 4096

;; QUESTION SECTION:
;ns-1342.awsdns-39.org.	IN	 A

;; ANSWER SECTION:
ns-1342.awsdns-39.org.	172800	IN	A	205.251.197.62

;; AUTHORITY SECTION:
awsdns-39.org.	172800	IN	NS	g-ns-1066.awsdns-39.org.
awsdns-39.org.	172800	IN	NS	g-ns-1639.awsdns-39.org.
awsdns-39.org.	172800	IN	NS	g-ns-167.awsdns-39.org.
awsdns-39.org.	172800	IN	NS	g-ns-745.awsdns-39.org.

;; ADDITIONAL SECTION:
g-ns-1066.awsdns-39.org.	172800	IN	A	205.251.196.42
g-ns-1066.awsdns-39.org.	172800	IN	AAAA	2600:9000:5304:2a00::1
g-ns-1639.awsdns-39.org.	172800	IN	A	205.251.198.103
g-ns-1639.awsdns-39.org.	172800	IN	AAAA	2600:9000:5306:6700::1
g-ns-167.awsdns-39.org.	172800	IN	A	205.251.192.167
g-ns-167.awsdns-39.org.	172800	IN	AAAA	2600:9000:5300:a700::1
g-ns-745.awsdns-39.org.	172800	IN	A	205.251.194.233
g-ns-745.awsdns-39.org.	172800	IN	AAAA	2600:9000:5302:e900::1

;; GZPACK: H4sIAAAAAAAA/5pf3MrAwMjAyMDCwMmeV6xraGxsyplYXpySV6xrbMGcX5QOlsYjxcC0mIGB5ezvo+bokkxQSUnOdF2QfgMzdP2EdJgZWxCpQ4IDqsOMNA3mJiboGnA5FtmzRzRxK5OBKhNQY5jAEMyiyQAFjDg9hWzysTTcylBNZkuDm4zL88gGH1iGUxWquQzL0MzFDCNkcw+9wKkK1VymF3BzGRg0BaBsQAAAAP//7+EAEYECAAA=
;; SERVER: 205.251.192.167
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @205.251.192.167 A ns-1342.awsdns-39.org.
;; opcode: QUERY, status: NOERROR, id: 58549
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 4, ADDITIONAL: 9

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 4096

;; QUESTION SECTION:
;ns-1342.awsdns-39.org.	IN	 A

;; ANSWER SECTION:
ns-1342.awsdns-39.org.	172800	IN	A	205.251.197.62

;; AUTHORITY SECTION:
awsdns-39.org.	172800	IN	NS	g-ns-1066.awsdns-39.org.
awsdns-39.org.	172800	IN	NS	g-ns-1639.awsdns-39.org.
awsdns-39.org.	172800	IN	NS	g-ns-167.awsdns-39.org.
awsdns-39.org.	172800	IN	NS	g-ns-745.awsdns-39.org.

;; ADDITIONAL SECTION:
g-ns-1066.awsdns-39.org.	172800	IN	A	205.251.196.42
g-ns-1066.awsdns-39.org.	172800	IN	AAAA	2600:9000:5304:2a00::1
g-ns-1639.awsdns-39.org.	172800	IN	A	205.251.198.103
g-ns-1639.awsdns-39.org.	172800	IN	AAAA	2600:9000:5306:6700::1
g-ns-167.awsdns-39.org.	172800	IN	A	205.251.192.167
g-ns-167.awsdns-39.org.	172800	IN	AAAA	2600:9000:5300:a700::1
g-ns-745.awsdns-39.org.	172800	IN	A	205.251.194.233
g-ns-745.awsdns-39.org.	172800	IN	AAAA	2600:9000:5302:e900::1

;; GZPACK: H4sIAAAAAAAA/3qytZWBgZGBkYGFgZM9r1jX0NjYlDOxvDglr1jX2II5vygdLI1HioFpMQMDy9nfR83RJZmgkpKc6bog/QZm6PoJ6TAztiBShwQHVIcZaRrMTUzQNeByLLJnj2jiViYDVSagxjCBIZhFkwEKGHF6CtnkY2m4laGazJYGNxmX55ENPrAMpypUcxmWoZmLGUbI5h56gVMVqrlML+DmMjBoCkDZgAAAAP//ONqbaIECAAA=
;; SERVER: 205.251.192.167
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @205.251.197.55 A lbr.us.console.amazonaws.com.
;; opcode: QUERY, status: NOERROR, id: 11492
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 4, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 4096

;; QUESTION SECTION:
;lbr.us.console.amazonaws.com.	IN	 A

;; ANSWER SECTION:
lbr.us.console.amazonaws.com.	60	IN	CNAME	eu-north-1.console.aws.amazon.com.

;; AUTHORITY SECTION:
us.console.amazonaws.com.	172800	IN	NS	ns-1335.awsdns-38.org.
us.console.amazonaws.com.	172800	IN	NS	ns-1892.awsdns-44.co.uk.
us.console.amazonaws.com.	172800	IN	NS	ns-499.awsdns-62.com.
us.console.amazonaws.com.	172800	IN	NS	ns-611.awsdns-12.net.

;; GZPACK: H4sIAAAAAAAA/4zOQY6CMBTG8a/tDIRZzWomrl2Z2EUBCSRepiLRROhLeBAS957Eq3kQY0m3ylv/fy/f9nEDBAS+IFR76OXIcU2OqW0S29krOTuxqqnz1YfiGwLAHuufZtSO+uGsTWiVnTiaex+/eSMhIO/Af+xYmyzbJXbio2OdlYr60xK68rSs0kDzXNYkx8sS/Be9QFUFW6RLF3tZGBOkSZVrBgCbX8z3DAAA///NkCKHcAEAAA==
;; SERVER: 205.251.197.55
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @192.36.148.17 A eu-north-1.console.aws.amazon.com.
;; opcode: QUERY, status: NOERROR, id: 23014
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 13, ADDITIONAL: 27

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 1232
; COOKIE: fdcdd36e68ceda4a0100000068d6281dbf4b4fcef2255a3e

;; QUESTION SECTION:
;eu-north-1.console.aws.amazon.com.	IN	 A

;; AUTHORITY SECTION:
com.	172800	IN	NS	c.gtld-servers.net.
com.	172800	IN	NS	h.gtld-servers.net.
com.	172800	IN	NS	b.gtld-servers.net.
com.	172800	IN	NS	d.gtld-servers.net.
com.	172800	IN	NS	e.gtld-servers.net.
com.	172800	IN	NS	a.gtld-servers.net.
com.	172800	IN	NS	l.gtld-servers.net.
com.	172800	IN	NS	f.gtld-servers.net.
com.	172800	IN	NS	i.gtld-servers.net.
com.	172800	IN	NS	g.gtld-servers.net.
com.	172800	IN	NS	k.gtld-servers.net.
com.	172800	IN	NS	j.gtld-servers.net.
com.	172800	IN	NS	m.gtld-servers.net.

;; ADDITIONAL SECTION:
m.gtld-servers.net.	172800	IN	A	192.55.83.30
l.gtld-servers.net.	172800	IN	A	192.41.162.30
k.gtld-servers.net.	172800	IN	A	192.52.178.30
j.gtld-servers.net.	172800	IN	A	192.48.79.30
i.gtld-servers.net.	172800	IN	A	192.43.172.30
h.gtld-servers.net.	172800	IN	A	192.54.112.30
g.gtld-servers.net.	172800	IN	A	192.42.93.30
f.gtld-servers.net.	172800	IN	A	192.35.51.30
e.gtld-servers.net.	172800	IN	A	192.12.94.30
d.gtld-servers.net.	172800	IN	A	192.31.80.30
c.gtld-servers.net.	172800	IN	A	192.26.92.30
b.gtld-servers.net.	172800	IN	A	192.33.14.30
a.gtld-servers.net.	172800	IN	A	192.5.6.30
m.gtld-servers.net.	172800	IN	AAAA	2001:501:b1f9::30
l.gtld-servers.net.	172800	IN	AAAA	2001:500:d937::30
k.gtld-servers.net.	172800	IN	AAAA	2001:503:d2d::30
j.gtld-servers.net.	172800	IN	AAAA	2001:502:7094::30
i.gtld-servers.net.	172800	IN	AAAA	2001:503:39c1::30
h.gtld-servers.net.	172800	IN	AAAA	2001:502:8cc::30
g.gtld-servers.net.	172800	IN	AAAA	2001:503:eea3::30
f.gtld-servers.net.	172800	IN	AAAA	2001:503:d414::30
e.gtld-servers.net.	172800	IN	AAAA	2001:502:1ca1::30
d.gtld-servers.net.	172800	IN	AAAA	2001:500:856e::30
c.gtld-servers.net.	172800	IN	AAAA	2001:503:83eb::30
b.gtld-servers.net.	172800	IN	AAAA	2001:503:231d::2:30
a.gtld-servers.net.	172800	IN	AAAA	2001:503:a83e::2:30

;; GZPACK: H4sIAAAAAAAA/4TVsUrDUBQG4JOkrVJacegg2l6VIlglUFEsLn0AHSo4KSrENjZqm5SmKriJ+Aa+gHZxcNEXUHctgiLoA7gIDm4OgqRWPFd/uJ2a8OVyOP8fsviyT6QRUZwGova26Xr1hmNOdBU91/cqtmHt+hGrau15rlH0qgHVvv/opJHeJEpoxVi5USmZvl3fseu+4doN+kscNVlTk5Ka2GpiqUlFTdbVZENNymqypSabalL9T9C9IN72E6Gr3IJAe2AicyLQdExMXQg0HBPZgkB7YmL8TKD6MDFdE2iRTIytCBQYE+lJgbrDRGxVoAIyMTgv0LvARP+yQD1nYrhHoIIyEY4ImFyyI3qHtLB2/kE/vyxMkWt6yjGNEuXaiJtMo3S51mtHTKOkpbNnrplGqUtnd98wjRognf3WZBq1QdIPCaZRM6RJksdMo5ZI+z50mUaNkSY5eGUatUfS6VTH6pSFTZL0af5XE2VCd+2LJEWp7/P23nVaz7PBt8F5HE1dzhVa7yNL+a8AAAD//2jbEksxBgAA
;; SERVER: 192.36.148.17
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @192.5.6.30 A eu-north-1.console.aws.amazon.com.
;; opcode: QUERY, status: NOERROR, id: 2032
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 8, ADDITIONAL: 5

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 4096

;; QUESTION SECTION:
;eu-north-1.console.aws.amazon.com.	IN	 A

;; AUTHORITY SECTION:
amazon.com.	172800	IN	NS	ns1.amzndns.org.
amazon.com.	172800	IN	NS	ns2.amzndns.org.
amazon.com.	172800	IN	NS	ns1.amzndns.co.uk.
amazon.com.	172800	IN	NS	ns2.amzndns.co.uk.
amazon.com.	172800	IN	NS	ns1.amzndns.net.
amazon.com.	172800	IN	NS	ns2.amzndns.net.
amazon.com.	172800	IN	NS	ns1.amzndns.com.
amazon.com.	172800	IN	NS	ns2.amzndns.com.

;; ADDITIONAL SECTION:
ns1.amzndns.com.	172800	IN	A	156.154.64.10
ns1.amzndns.com.	172800	IN	AAAA	2001:502:f3ff::10
ns2.amzndns.com.	172800	IN	A	156.154.68.10
ns2.amzndns.com.	172800	IN	AAAA	2610:a1:1016::10

;; GZPACK: H4sIAAAAAAAA/2L/0MjAwMjAwMDBwMqVWqqbl19UkqFryJ6cn1ecn5PKnFhezJaYm1iVn8ecnJ8LUsqIwmdiYGRgWszAIMicV2zInphblZeSV8ycX5TOgFOZEWFlwsimMSXnM5Vm41ZoRIxCVPflpZYQ4z68yhCmgaSIMA0khaEPFKBgtSxzZjlwYUrLQKUFFBhZmT7/Z4ABAQyjkU1y4cKUhpukJsCwUEAMYRIDg6YAlA0IAAD//37iHQ0OAgAA
;; SERVER: 192.5.6.30
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @156.154.64.10 A eu-north-1.console.aws.amazon.com.
;; opcode: QUERY, status: NOERROR, id: 21624
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 4, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 4096

;; QUESTION SECTION:
;eu-north-1.console.aws.amazon.com.	IN	 A

;; ANSWER SECTION:
eu-north-1.console.aws.amazon.com.	7200	IN	CNAME	eu-north-1.console.cname-proxy.amazon.com.

;; AUTHORITY SECTION:
cname-proxy.amazon.com.	60	IN	NS	ns-429.awsdns-53.com.
cname-proxy.amazon.com.	60	IN	NS	ns-689.awsdns-22.net.
cname-proxy.amazon.com.	60	IN	NS	ns-1313.awsdns-36.org.
cname-proxy.amazon.com.	60	IN	NS	ns-1878.awsdns-42.co.uk.

;; GZPACK: H4sIAAAAAAAA/wqpaGVgYGRgZGBhYORKLdXNyy8qydA1ZE/OzyvOz0llTiwvZkvMTazKz2NOzs8FKyVGGSsDIwODjAKDNhbF3Ml5ibmpugVF+RWVyJpwiTMwgQxjsGEQY8sr1jUxsuRMLC9OySvWNTUmQZ+ZBVyfkRFzXmoJYX3i7HnFuobGhsYwjcZmzPlF6YQ1SoI1WphbwDSaGDEl5zOVZjMwMGgKMEAAIAAA//9tdg0kegEAAA==
;; SERVER: 156.154.64.10
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @192.36.148.17 A eu-north-1.console.cname-proxy.amazon.com.
;; opcode: QUERY, status: NOERROR, id: 23818
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 13, ADDITIONAL: 27

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 1232
; COOKIE: fdcdd36e68ceda4a0100000068d6281dbf4b4fcef2255a3e

;; QUESTION SECTION:
;eu-north-1.console.cname-proxy.amazon.com.	IN	 A

;; AUTHORITY SECTION:
com.	172800	IN	NS	c.gtld-servers.net.
com.	172800	IN	NS	m.gtld-servers.net.
com.	172800	IN	NS	d.gtld-servers.net.
com.	172800	IN	NS	e.gtld-servers.net.
com.	172800	IN	NS	b.gtld-servers.net.
com.	172800	IN	NS	a.gtld-servers.net.
com.	172800	IN	NS	f.gtld-servers.net.
com.	172800	IN	NS	g.gtld-servers.net.
com.	172800	IN	NS	j.gtld-servers.net.
com.	172800	IN	NS	h.gtld-servers.net.
com.	172800	IN	NS	i.gtld-servers.net.
com.	172800	IN	NS	k.gtld-servers.net.
com.	172800	IN	NS	l.gtld-servers.net.

;; ADDITIONAL SECTION:
m.gtld-servers.net.	172800	IN	A	192.55.83.30
l.gtld-servers.net.	172800	IN	A	192.41.162.30
k.gtld-servers.net.	172800	IN	A	192.52.178.30
j.gtld-servers.net.	172800	IN	A	192.48.79.30
i.gtld-servers.net.	172800	IN	A	192.43.172.30
h.gtld-servers.net.	172800	IN	A	192.54.112.30
g.gtld-servers.net.	172800	IN	A	192.42.93.30
f.gtld-servers.net.	172800	IN	A	192.35.51.30
e.gtld-servers.net.	172800	IN	A	192.12.94.30
d.gtld-servers.net.	172800	IN	A	192.31.80.30
c.gtld-servers.net.	172800	IN	A	192.26.92.30
b.gtld-servers.net.	172800	IN	A	192.33.14.30
a.gtld-servers.net.	172800	IN	A	192.5.6.30
m.gtld-servers.net.	172800	IN	AAAA	2001:501:b1f9::30
l.gtld-servers.net.	172800	IN	AAAA	2001:500:d937::30
k.gtld-servers.net.	172800	IN	AAAA	2001:503:d2d::30
j.gtld-servers.net.	172800	IN	AAAA	2001:502:7094::30
i.gtld-servers.net.	172800	IN	AAAA	2001:503:39c1::30
h.gtld-servers.net.	172800	IN	AAAA	2001:502:8cc::30
g.gtld-servers.net.	172800	IN	AAAA	2001:503:eea3::30
f.gtld-servers.net.	172800	IN	AAAA	2001:503:d414::30
e.gtld-servers.net.	172800	IN	AAAA	2001:502:1ca1::30
d.gtld-servers.net.	172800	IN	AAAA	2001:500:856e::30
c.gtld-servers.net.	172800	IN	AAAA	2001:503:83eb::30
b.gtld-servers.net.	172800	IN	AAAA	2001:503:231d::2:30
a.gtld-servers.net.	172800	IN	AAAA	2001:503:a83e::2:30

;; GZPACK: H4sIAAAAAAAA/4TVzy47URQH8DPTP79fqhWLLoT2II1EySQVorHpA7CoxE5UMqZXB507zbQEOxFv4AXoxsKGF8CeRkIkvILEws5CIq2KcznJ7aqTfO6dO+f7nUwptg9gAEACBmNiy5J+0HCtyX+OL+t+VfQ40vaEVQv8nd2o7dl7vgw5vtdeYnz9McEAswmQNJx4pVEtW3URbIugHpKiAb+JpydlPRF6sqontp6s6UlFTzb0xNWTdT3Z1JPqX8KF0o63syJ8lV9EbhUR2RPkbk3E9AVyUyAiV0TuCYmYOENuTETM1JCLg4jxEnKZEpGZQq5eRMRXkOsoEUMLyL0LRAwsI9dQIkZ6kSsoEZEossmluqJv2IgY5+/w/cuxKVINT3miuUSpDiUsorl0qTZrR0RzSSt7z14TzaWu7P3/hmiuAcrer02iuTYo+iFJNNcM5SSpY6K5lijzPpREc41RTnLwQjTXHkVn0l1rQo5tkqJPCz8aIBu+61ykIAb9H7f30m09z7W/Ee7jWPpyvth6G10qfAYAAP//p5/qpjkGAAA==
;; SERVER: 192.36.148.17
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @192.5.6.30 A eu-north-1.console.cname-proxy.amazon.com.
;; opcode: QUERY, status: NOERROR, id: 26640
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 8, ADDITIONAL: 5

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 4096

;; QUESTION SECTION:
;eu-north-1.console.cname-proxy.amazon.com.	IN	 A

;; AUTHORITY SECTION:
amazon.com.	172800	IN	NS	ns1.amzndns.org.
amazon.com.	172800	IN	NS	ns2.amzndns.org.
amazon.com.	172800	IN	NS	ns1.amzndns.co.uk.
amazon.com.	172800	IN	NS	ns2.amzndns.co.uk.
amazon.com.	172800	IN	NS	ns1.amzndns.net.
amazon.com.	172800	IN	NS	ns2.amzndns.net.
amazon.com.	172800	IN	NS	ns1.amzndns.com.
amazon.com.	172800	IN	NS	ns2.amzndns.com.

;; ADDITIONAL SECTION:
ns1.amzndns.com.	172800	IN	A	156.154.64.10
ns1.amzndns.com.	172800	IN	AAAA	2001:502:f3ff::10
ns2.amzndns.com.	172800	IN	A	156.154.68.10
ns2.amzndns.com.	172800	IN	AAAA	2610:a1:1016::10

;; GZPACK: H4sIAAAAAAAA/8oQaGRgYGRgYOBgYOVKLdXNyy8qydA1ZE/OzyvOz0nlTs5LzE3VLSjKr6hkS8xNrMrPY07OzwVpYUThMzEwMjAtZmAQZM4rNmRPzK3KS8krZs4vSmfAqcyIsDJhZNOYkvOZSrNxKzQiRiGq+/JSS4hxH15lCNNAUkSYBpLC0AcKULBaljmzHLgwpWWg0gIKjKxMn/8zwIAAhtHIJrlwYUrDTVITYFgoIIYwiYFBUwDKBgQAAP//NxrDdhYCAAA=
;; SERVER: 192.5.6.30
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @156.154.64.10 A eu-north-1.console.cname-proxy.amazon.com.
;; opcode: QUERY, status: NOERROR, id: 25502
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 4, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 4096

;; QUESTION SECTION:
;eu-north-1.console.cname-proxy.amazon.com.	IN	 A

;; AUTHORITY SECTION:
cname-proxy.amazon.com.	60	IN	NS	ns-429.awsdns-53.com.
cname-proxy.amazon.com.	60	IN	NS	ns-689.awsdns-22.net.
cname-proxy.amazon.com.	60	IN	NS	ns-1313.awsdns-36.org.
cname-proxy.amazon.com.	60	IN	NS	ns-1878.awsdns-42.co.uk.

;; GZPACK: H4sIAAAAAAAA/0qe18jAwMjAwMDCwMiVWqqbl19UkqFryJ6cn1ecn5PKnZyXmJuqW1CUX1HJlpibWJWfx5ycnwvSwohTjglsoA2DGFtesa6JkSVnYnlxSl6xrqkxWJ44fWYWcH1GRsx5qSWE9Ymz5xXrGhobGsM0Gpsx5xelE9YoCdZoYW4B02hixJScz1SazcDAoCnAAAGAAAAA//8Wn6TiKgEAAA==
;; SERVER: 156.154.64.10
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @205.251.197.33 A eu-north-1.console.cname-proxy.amazon.com.
;; opcode: QUERY, status: NOERROR, id: 15939
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 4, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 4096

;; QUESTION SECTION:
;eu-north-1.console.cname-proxy.amazon.com.	IN	 A

;; ANSWER SECTION:
eu-north-1.console.cname-proxy.amazon.com.	60	IN	CNAME	gr.aga.console-geo.eu-north-1.amazonaws.com.

;; AUTHORITY SECTION:
cname-proxy.amazon.com.	1801	IN	NS	ns-1313.awsdns-36.org.
cname-proxy.amazon.com.	1801	IN	NS	ns-1878.awsdns-42.co.uk.
cname-proxy.amazon.com.	1801	IN	NS	ns-429.awsdns-53.com.
cname-proxy.amazon.com.	1801	IN	NS	ns-689.awsdns-22.net.

;; GZPACK: H4sIAAAAAAAA/5TOsa6CMBTG8dP2XgiX5U4aH8GhA1QRE+PikzS1qYnSY1oI6u57G4sYF4Oe+fv9c9abKwABAj9A/nTDLbp6x7NYofV40KmystL86PB0jmQlL2iZwiqQb+a/QABgBZwax6SR6QNwo/Glk3RGtj6wtzl6z8UJjGPreSYykcjWb63nomDozDCcBFguyh7OcqqQNvthOorCfNnLufjs1+CK8unynFldA8D0H7q7BQAA//8sKFNajAEAAA==
;; SERVER: 205.251.197.33
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @192.36.148.17 A gr.aga.console-geo.eu-north-1.amazonaws.com.
;; opcode: QUERY, status: NOERROR, id: 34270
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 13, ADDITIONAL: 27

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 1232
; COOKIE: fdcdd36e68ceda4a0100000068d6281dbf4b4fcef2255a3e

;; QUESTION SECTION:
;gr.aga.console-geo.eu-north-1.amazonaws.com.	IN	 A

;; AUTHORITY SECTION:
com.	172800	IN	NS	b.gtld-servers.net.
com.	172800	IN	NS	i.gtld-servers.net.
com.	172800	IN	NS	g.gtld-servers.net.
com.	172800	IN	NS	a.gtld-servers.net.
com.	172800	IN	NS	l.gtld-servers.net.
com.	172800	IN	NS	m.gtld-servers.net.
com.	172800	IN	NS	k.gtld-servers.net.
com.	172800	IN	NS	d.gtld-servers.net.
com.	172800	IN	NS	h.gtld-servers.net.
com.	172800	IN	NS	f.gtld-servers.net.
com.	172800	IN	NS	e.gtld-servers.net.
com.	172800	IN	NS	j.gtld-servers.net.
com.	172800	IN	NS	c.gtld-servers.net.

;; ADDITIONAL SECTION:
m.gtld-servers.net.	172800	IN	A	192.55.83.30
l.gtld-servers.net.	172800	IN	A	192.41.162.30
k.gtld-servers.net.	172800	IN	A	192.52.178.30
j.gtld-servers.net.	172800	IN	A	192.48.79.30
i.gtld-servers.net.	172800	IN	A	192.43.172.30
h.gtld-servers.net.	172800	IN	A	192.54.112.30
g.gtld-servers.net.	172800	IN	A	192.42.93.30
f.gtld-servers.net.	172800	IN	A	192.35.51.30
e.gtld-servers.net.	172800	IN	A	192.12.94.30
d.gtld-servers.net.	172800	IN	A	192.31.80.30
c.gtld-servers.net.	172800	IN	A	192.26.92.30
b.gtld-servers.net.	172800	IN	A	192.33.14.30
a.gtld-servers.net.	172800	IN	A	192.5.6.30
m.gtld-servers.net.	172800	IN	AAAA	2001:501:b1f9::30
l.gtld-servers.net.	172800	IN	AAAA	2001:500:d937::30
k.gtld-servers.net.	172800	IN	AAAA	2001:503:d2d::30
j.gtld-servers.net.	172800	IN	AAAA	2001:502:7094::30
i.gtld-servers.net.	172800	IN	AAAA	2001:503:39c1::30
h.gtld-servers.net.	172800	IN	AAAA	2001:502:8cc::30
g.gtld-servers.net.	172800	IN	AAAA	2001:503:eea3::30
f.gtld-servers.net.	172800	IN	AAAA	2001:503:d414::30
e.gtld-servers.net.	172800	IN	AAAA	2001:502:1ca1::30
d.gtld-servers.net.	172800	IN	AAAA	2001:500:856e::30
c.gtld-servers.net.	172800	IN	AAAA	2001:503:83eb::30
b.gtld-servers.net.	172800	IN	AAAA	2001:503:231d::2:30
a.gtld-servers.net.	172800	IN	AAAA	2001:503:a83e::2:30

;; GZPACK: H4sIAAAAAAAA/4TVwUoCURQG4DMzGmUaLVxE6amQIIsBo0ja+AC1MGgXFUx6m6l0RmasoF2Eb9ALlJsWbeoFqn1JUAS16AWCFu1aBDFmdG4duK4Uvrlc/v+XabwcAGgAkIAh3fYNy7Z6S54beBVh2sKLiR3T9fy6Y071WFVr33OtvcAoedXwIe37iw4a6E2ApLYet+uVshkIf1f4geGKOvwlm2piq4mlJhU1qarJtpqU1cRRkw01EWqypSal/4QLIqy3/UTkKr+EXJpEZE+QS4qImQvkLkdErojcOIiYPEMuSSJma8ith4iJVeSiJiIzjVzSRMTXkCudiOFF5HImYnAFuX8LEaN9yM2ciGgXss2lOqJ/RItq5x/w88mxLVINT3miuUapNhIm0Vy7VOu1I6K5pqWz566J5lqXzu6+IZpbgHT2W5Nobg2SfkgSzS1DuknqmGhuJVLeDZdobjHSTQ5fiebWI+lMumN1yLFLkvRp4VcDZCN37R8piMHA5+2967Se58O3hPM4nr5cKLbex5YLXwEAAP//JrhiGjsGAAA=
;; SERVER: 192.36.148.17
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @192.5.6.30 A gr.aga.console-geo.eu-north-1.amazonaws.com.
;; opcode: QUERY, status: NOERROR, id: 31755
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 4, ADDITIONAL: 2

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 4096

;; QUESTION SECTION:
;gr.aga.console-geo.eu-north-1.amazonaws.com.	IN	 A

;; AUTHORITY SECTION:
amazonaws.com.	172800	IN	NS	ns-27.awsdns-03.com.
amazonaws.com.	172800	IN	NS	ns-967.awsdns-56.net.
amazonaws.com.	172800	IN	NS	ns-1670.awsdns-16.co.uk.
amazonaws.com.	172800	IN	NS	ns-1321.awsdns-37.org.

;; ADDITIONAL SECTION:
ns-27.awsdns-03.com.	172800	IN	A	205.251.192.27

;; GZPACK: H4sIAAAAAAAA/6rhbmRgYGRgYGBhYGJKL2JOTE/kTs7PK87PSdVNT83nSi3VzcsvKsnQNeRMzE2sys9LLC9mTs7PBWliRBdiYmBkYFrMwCDKmlesa2TOmVhenJJXrGtgDJbGpVqMLa9Y19IMrtzUjDkvtQSnckn2vGJdQzNzA5h6QzOm5Hym0mycOsTBOoyNDGE6jM2Z84vSGbC6EuQvsC6Ws78PSDMwaAowQAAgAAD//94qYP8qAQAA
;; SERVER: 192.5.6.30
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @205.251.192.27 A gr.aga.console-geo.eu-north-1.amazonaws.com.
;; opcode: QUERY, status: NOERROR, id: 53444
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 8, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 4096

;; QUESTION SECTION:
;gr.aga.console-geo.eu-north-1.amazonaws.com.	IN	 A

;; AUTHORITY SECTION:
eu-north-1.amazonaws.com.	7200	IN	NS	ns1.amzndns.co.uk.
eu-north-1.amazonaws.com.	7200	IN	NS	ns1.amzndns.com.
eu-north-1.amazonaws.com.	7200	IN	NS	ns1.amzndns.net.
eu-north-1.amazonaws.com.	7200	IN	NS	ns1.amzndns.org.
eu-north-1.amazonaws.com.	7200	IN	NS	ns2.amzndns.co.uk.
eu-north-1.amazonaws.com.	7200	IN	NS	ns2.amzndns.com.
eu-north-1.amazonaws.com.	7200	IN	NS	ns2.amzndns.net.
eu-north-1.amazonaws.com.	7200	IN	NS	ns2.amzndns.org.

;; GZPACK: H4sIAAAAAAAA/7pwpJGBgZGBgYGDgZEpvYg5MT2ROzk/rzg/J1U3PTWfK7VUNy+/qCRD15AzMTexKj8vsbyYOTk/F6SJEY8sE8hQGQUGYea8YkP2xNyqvJS8YqbkfKbSbAYitAkiawNLkawpL7WEdE35RenEaAL5yog8XxmR4ysjcnxlhOIrBgZNAQYIAAQAAP//I1TwNfQBAAA=
;; SERVER: 205.251.192.27
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @156.154.64.10 A gr.aga.console-geo.eu-north-1.amazonaws.com.
;; opcode: QUERY, status: NOERROR, id: 51314
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 4, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 4096

;; QUESTION SECTION:
;gr.aga.console-geo.eu-north-1.amazonaws.com.	IN	 A

;; AUTHORITY SECTION:
console-geo.eu-north-1.amazonaws.com.	7200	IN	NS	ns-148.awsdns-18.com.
console-geo.eu-north-1.amazonaws.com.	7200	IN	NS	ns-581.awsdns-08.net.
console-geo.eu-north-1.amazonaws.com.	7200	IN	NS	ns-1055.awsdns-03.org.
console-geo.eu-north-1.amazonaws.com.	7200	IN	NS	ns-1737.awsdns-25.co.uk.

;; GZPACK: H4sIAAAAAAAA/zpR1MjAwMjAwMDCwMiUXsScmJ7InZyfV5yfk6qbnprPlVqqm5dfVJKha8iZmJtYlZ+XWF7MnJyfC9LESKRKJpAFMgoMYmx5xbqGJhacieXFKSCmBVieHFNMLQxhphhYMOellpBqijg7yAEGpqZwY4yZ84vSSTVGEmyMubE5zBgjU6bkfKbSbAYGBk0BBggABAAA///oyGF5ZAEAAA==
;; SERVER: 156.154.64.10
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @192.36.148.17 A ns-1055.awsdns-03.org.
;; opcode: QUERY, status: NOERROR, id: 13294
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 6, ADDITIONAL: 13

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 1232
; COOKIE: fdcdd36e68ceda4a0100000068d6281dbf4b4fcef2255a3e

;; QUESTION SECTION:
;ns-1055.awsdns-03.org.	IN	 A

;; AUTHORITY SECTION:
org.	172800	IN	NS	a0.org.afilias-nst.info.
org.	172800	IN	NS	b0.org.afilias-nst.org.
org.	172800	IN	NS	c0.org.afilias-nst.info.
org.	172800	IN	NS	b2.org.afilias-nst.org.
org.	172800	IN	NS	a2.org.afilias-nst.info.
org.	172800	IN	NS	d0.org.afilias-nst.org.

;; ADDITIONAL SECTION:
d0.org.afilias-nst.org.	172800	IN	A	199.19.57.1
c0.org.afilias-nst.info.	172800	IN	A	199.19.53.1
b2.org.afilias-nst.org.	172800	IN	A	199.249.120.1
b0.org.afilias-nst.org.	172800	IN	A	199.19.54.1
a2.org.afilias-nst.info.	172800	IN	A	199.249.112.1
a0.org.afilias-nst.info.	172800	IN	A	199.19.56.1
d0.org.afilias-nst.org.	172800	IN	AAAA	2001:500:f::1
c0.org.afilias-nst.info.	172800	IN	AAAA	2001:500:b::1
b2.org.afilias-nst.org.	172800	IN	AAAA	2001:500:48::1
b0.org.afilias-nst.org.	172800	IN	AAAA	2001:500:c::1
a2.org.afilias-nst.info.	172800	IN	AAAA	2001:500:40::1
a0.org.afilias-nst.info.	172800	IN	AAAA	2001:500:e::1

;; GZPACK: H4sIAAAAAAAA/zJ+18jAwMjAwMDGwMueV6xraGBqyplYXpySV6xrYMycX5QOkmaEMJgYGBmYFjMwSDIlGoBEuBPTMnMyE4t184pLWDLz0vIZUNVJMCVhqAOrQDcumVjjjIgyLhFDGXbjUrC7Dpc4KCDAOlmOC1sy4nQ0sjJTRlxuRlL1s4IRV0Ahm2XGiNNjyIYVMOKMHWTTLBhxelMGqkpAgZGVgYGfAQbweBlVCzeSFlzeR9XhgayDKGfxIOnAGSyoWhyQtRDnEz6EFgYGTZYLYKYMAxeDxN+zl/Myzt3yAuWdjGsasvu9/c99Uo2yAwQAAP//8SLCv1EDAAA=
;; SERVER: 192.36.148.17
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @199.19.53.1 A ns-1055.awsdns-03.org.
;; opcode: QUERY, status: NOERROR, id: 666
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 4, ADDITIONAL: 9

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 1232

;; QUESTION SECTION:
;ns-1055.awsdns-03.org.	IN	 A

;; AUTHORITY SECTION:
awsdns-03.org.	3600	IN	NS	g-ns-131.awsdns-03.org.
awsdns-03.org.	3600	IN	NS	g-ns-1603.awsdns-03.org.
awsdns-03.org.	3600	IN	NS	g-ns-709.awsdns-03.org.
awsdns-03.org.	3600	IN	NS	g-ns-1030.awsdns-03.org.

;; ADDITIONAL SECTION:
g-ns-131.awsdns-03.org.	3600	IN	A	205.251.192.131
g-ns-709.awsdns-03.org.	3600	IN	A	205.251.194.197
g-ns-1030.awsdns-03.org.	3600	IN	A	205.251.196.6
g-ns-1603.awsdns-03.org.	3600	IN	A	205.251.198.67
g-ns-131.awsdns-03.org.	3600	IN	AAAA	2600:9000:5300:8300::1
g-ns-709.awsdns-03.org.	3600	IN	AAAA	2600:9000:5302:c500::1
g-ns-1030.awsdns-03.org.	3600	IN	AAAA	2600:9000:5304:600::1
g-ns-1603.awsdns-03.org.	3600	IN	AAAA	2600:9000:5306:4300::1

;; GZPACK: H4sIAAAAAAAA/2Ka1cjAwMjAwMDCwMmeV6xraGBqyplYXpySV6xrYMycX5QOkmZEF2IC6eETYJDgSNcF6TI2RFOBS4MkJ0SDmYExkTqgVpgbWJJohYGxAZoSXI4F+RCsleXs7wPNuOxDVnXoKE5LkJUdYcPpXWRlx5xxukwGqkpAjWECQzBDMwMUMOJ0JaoOpqNwHbhdjKqFhQ1dCxbXo2phc4ZrYWDQZLkAYQMCAAD//9YeTXRcAgAA
;; SERVER: 199.19.53.1
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @205.251.192.131 A ns-1055.awsdns-03.org.
;; opcode: QUERY, status: NOERROR, id: 56747
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 4, ADDITIONAL: 9

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 4096

;; QUESTION SECTION:
;ns-1055.awsdns-03.org.	IN	 A

;; ANSWER SECTION:
ns-1055.awsdns-03.org.	172800	IN	A	205.251.196.31

;; AUTHORITY SECTION:
awsdns-03.org.	172800	IN	NS	g-ns-1030.awsdns-03.org.
awsdns-03.org.	172800	IN	NS	g-ns-131.awsdns-03.org.
awsdns-03.org.	172800	IN	NS	g-ns-1603.awsdns-03.org.
awsdns-03.org.	172800	IN	NS	g-ns-709.awsdns-03.org.

;; ADDITIONAL SECTION:
g-ns-1030.awsdns-03.org.	172800	IN	A	205.251.196.6
g-ns-1030.awsdns-03.org.	172800	IN	AAAA	2600:9000:5304:600::1
g-ns-131.awsdns-03.org.	172800	IN	A	205.251.192.131
g-ns-131.awsdns-03.org.	172800	IN	AAAA	2600:9000:5300:8300::1
g-ns-1603.awsdns-03.org.	172800	IN	A	205.251.198.67
g-ns-1603.awsdns-03.org.	172800	IN	AAAA	2600:9000:5306:4300::1
g-ns-709.awsdns-03.org.	172800	IN	A	205.251.194.197
g-ns-709.awsdns-03.org.	172800	IN	AAAA	2600:9000:5302:c500::1

;; GZPACK: H4sIAAAAAAAA/7q7upWBgZGBkYGFgZM9r1jX0MDUlDOxvDglr1jXwJg5vygdLI1HioFpMQMDy9nfR+TRJZmgkpKc6bpg/cYGaEpw6ZDggOgwNiRSA8wKMwNj0qwwN7BE14DLsSieZcOtTAaqTECNYQJDMAsbAxQw4vIUssEHmnGqQjWXoRluLk6/Ixt8zBm3MlST2ZzRXIwZRsgGHzqKUxWquUxH4eYyMGgKQNmAAAAA///20C0YgQIAAA==
;; SERVER: 205.251.192.131
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @205.251.192.131 A ns-1055.awsdns-03.org.
;; opcode: QUERY, status: NOERROR, id: 23525
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 4, ADDITIONAL: 9

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 4096

;; QUESTION SECTION:
;ns-1055.awsdns-03.org.	IN	 A

;; ANSWER SECTION:
ns-1055.awsdns-03.org.	172800	IN	A	205.251.196.31

;; AUTHORITY SECTION:
awsdns-03.org.	172800	IN	NS	g-ns-1030.awsdns-03.org.
awsdns-03.org.	172800	IN	NS	g-ns-131.awsdns-03.org.
awsdns-03.org.	172800	IN	NS	g-ns-1603.awsdns-03.org.
awsdns-03.org.	172800	IN	NS	g-ns-709.awsdns-03.org.

;; ADDITIONAL SECTION:
g-ns-1030.awsdns-03.org.	172800	IN	A	205.251.196.6
g-ns-1030.awsdns-03.org.	172800	IN	AAAA	2600:9000:5304:600::1
g-ns-131.awsdns-03.org.	172800	IN	A	205.251.192.131
g-ns-131.awsdns-03.org.	172800	IN	AAAA	2600:9000:5300:8300::1
g-ns-1603.awsdns-03.org.	172800	IN	A	205.251.198.67
g-ns-1603.awsdns-03.org.	172800	IN	AAAA	2600:9000:5306:4300::1
g-ns-709.awsdns-03.org.	172800	IN	A	205.251.194.197
g-ns-709.awsdns-03.org.	172800	IN	AAAA	2600:9000:5302:c500::1

;; GZPACK: H4sIAAAAAAAA/4p+2srAwMjAyMDCwMmeV6xraGBqyplYXpySV6xrYMycX5QOlsYjxcC0mIGB5ezvI/LokkxQSUnOdF2wfmMDNCW4dEhwQHQYGxKpAWaFmYExaVaYG1iia8DlWBTPsuFWJgNVJqDGMIEhmIWNAQoYcXkK2eADzThVoZrL0Aw3F6ffkQ0+5oxbGarJbM5oLsYMI2SDDx3FqQrVXKajcHMZGDQFoGxAAAAA//+IPTLEgQIAAA==
;; SERVER: 205.251.192.131
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @205.251.192.131 A ns-1055.awsdns-03.org.
;; opcode: QUERY, status: NOERROR, id: 30750
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 4, ADDITIONAL: 9

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 4096

;; QUESTION SECTION:
;ns-1055.awsdns-03.org.	IN	 A

;; ANSWER SECTION:
ns-1055.awsdns-03.org.	172800	IN	A	205.251.196.31

;; AUTHORITY SECTION:
awsdns-03.org.	172800	IN	NS	g-ns-1030.awsdns-03.org.
awsdns-03.org.	172800	IN	NS	g-ns-131.awsdns-03.org.
awsdns-03.org.	172800	IN	NS	g-ns-1603.awsdns-03.org.
awsdns-03.org.	172800	IN	NS	g-ns-709.awsdns-03.org.

;; ADDITIONAL SECTION:
g-ns-1030.awsdns-03.org.	172800	IN	A	205.251.196.6
g-ns-1030.awsdns-03.org.	172800	IN	AAAA	2600:9000:5304:600::1
g-ns-131.awsdns-03.org.	172800	IN	A	205.251.192.131
g-ns-131.awsdns-03.org.	172800	IN	AAAA	2600:9000:5300:8300::1
g-ns-1603.awsdns-03.org.	172800	IN	A	205.251.198.67
g-ns-1603.awsdns-03.org.	172800	IN	AAAA	2600:9000:5306:4300::1
g-ns-709.awsdns-03.org.	172800	IN	A	205.251.194.197
g-ns-709.awsdns-03.org.	172800	IN	AAAA	2600:9000:5302:c500::1

;; GZPACK: H4sIAAAAAAAA/6qQa2VgYGRgZGBh4GTPK9Y1NDA15UwsL07JK9Y1MGbOL0oHS+ORYmBazMDAcvb3EXl0SSaopCRnui5Yv7EBmhJcOiQ4IDqMDYnUALPCzMCYNCvMDSzRNeByLIpn2XArk4EqE1BjmMAQzMLGAAWMuDyFbPCBZpyqUM1laIabi9PvyAYfc8atDNVkNmc0F2OGEbLBh47iVIVqLtNRuLkMDJoCUDYgAAD//zFNhjiBAgAA
;; SERVER: 205.251.192.131
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @205.251.196.31 A gr.aga.console-geo.eu-north-1.amazonaws.com.
;; opcode: QUERY, status: NOERROR, id: 30269
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 4, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 4096

;; QUESTION SECTION:
;gr.aga.console-geo.eu-north-1.amazonaws.com.	IN	 A

;; ANSWER SECTION:
gr.aga.console-geo.eu-north-1.amazonaws.com.	60	IN	CNAME	aba8735d2c3d241de.awsglobalaccelerator.com.

;; AUTHORITY SECTION:
console-geo.eu-north-1.amazonaws.com.	172800	IN	NS	ns-1055.awsdns-03.org.
console-geo.eu-north-1.amazonaws.com.	172800	IN	NS	ns-148.awsdns-18.com.
console-geo.eu-north-1.amazonaws.com.	172800	IN	NS	ns-1737.awsdns-25.co.uk.
console-geo.eu-north-1.amazonaws.com.	172800	IN	NS	ns-581.awsdns-08.net.

;; GZPACK: H4sIAAAAAAAA/5zPzUoDMRTF8ZOMH1Q3CqL4CIKBZtIwWejD3CYhgmkuJFMH3Pskvqg4Utft3P358b8fr1+AgMAZhEy1o0TXnkvjHFWKfBX3qnAd35Re0Y4+udDUOs+7eXTa4BwCwAueb2lLbjA29N6EfqNDvKOppcxbyuR9zLHSyHVeHWlLCMhv4OGyNKXX1q5oaqE0tTYd13Qqc3/xy2zcQdFuSczjHDOY4cD0VnqW+/dFOdbp/6dcV+II4OkGf/cTAAD//3ABNizHAQAA
;; SERVER: 205.251.196.31
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @192.36.148.17 A aba8735d2c3d241de.awsglobalaccelerator.com.
;; opcode: QUERY, status: NOERROR, id: 55536
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 13, ADDITIONAL: 27

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 1232
; COOKIE: fdcdd36e68ceda4a0100000068d6281dbf4b4fcef2255a3e

;; QUESTION SECTION:
;aba8735d2c3d241de.awsglobalaccelerator.com.	IN	 A

;; AUTHORITY SECTION:
com.	172800	IN	NS	m.gtld-servers.net.
com.	172800	IN	NS	e.gtld-servers.net.
com.	172800	IN	NS	a.gtld-servers.net.
com.	172800	IN	NS	b.gtld-servers.net.
com.	172800	IN	NS	h.gtld-servers.net.
com.	172800	IN	NS	c.gtld-servers.net.
com.	172800	IN	NS	i.gtld-servers.net.
com.	172800	IN	NS	k.gtld-servers.net.
com.	172800	IN	NS	j.gtld-servers.net.
com.	172800	IN	NS	f.gtld-servers.net.
com.	172800	IN	NS	d.gtld-servers.net.
com.	172800	IN	NS	g.gtld-servers.net.
com.	172800	IN	NS	l.gtld-servers.net.

;; ADDITIONAL SECTION:
m.gtld-servers.net.	172800	IN	A	192.55.83.30
l.gtld-servers.net.	172800	IN	A	192.41.162.30
k.gtld-servers.net.	172800	IN	A	192.52.178.30
j.gtld-servers.net.	172800	IN	A	192.48.79.30
i.gtld-servers.net.	172800	IN	A	192.43.172.30
h.gtld-servers.net.	172800	IN	A	192.54.112.30
g.gtld-servers.net.	172800	IN	A	192.42.93.30
f.gtld-servers.net.	172800	IN	A	192.35.51.30
e.gtld-servers.net.	172800	IN	A	192.12.94.30
d.gtld-servers.net.	172800	IN	A	192.31.80.30
c.gtld-servers.net.	172800	IN	A	192.26.92.30
b.gtld-servers.net.	172800	IN	A	192.33.14.30
a.gtld-servers.net.	172800	IN	A	192.5.6.30
m.gtld-servers.net.	172800	IN	AAAA	2001:501:b1f9::30
l.gtld-servers.net.	172800	IN	AAAA	2001:500:d937::30
k.gtld-servers.net.	172800	IN	AAAA	2001:503:d2d::30
j.gtld-servers.net.	172800	IN	AAAA	2001:502:7094::30
i.gtld-servers.net.	172800	IN	AAAA	2001:503:39c1::30
h.gtld-servers.net.	172800	IN	AAAA	2001:502:8cc::30
g.gtld-servers.net.	172800	IN	AAAA	2001:503:eea3::30
f.gtld-servers.net.	172800	IN	AAAA	2001:503:d414::30
e.gtld-servers.net.	172800	IN	AAAA	2001:502:1ca1::30
d.gtld-servers.net.	172800	IN	AAAA	2001:500:856e::30
c.gtld-servers.net.	172800	IN	AAAA	2001:503:83eb::30
b.gtld-servers.net.	172800	IN	AAAA	2001:503:231d::2:30
a.gtld-servers.net.	172800	IN	AAAA	2001:503:a83e::2:30

;; GZPACK: H4sIAAAAAAAA/4TVz0oyURgG8HdG/fgIjQIXUXoqJMhCMLWsjRdQC4N2UcE4c9Jq/MMotY7oDrqBctOiTd1AtS8JiqhuIYho1yIIzeg99cBx5cDvvBze5xnm4XWXyCCiEA31WwVrNpuedlJ22kllphwZtnbqRbdasFzLtqUrPatR9Xx2tdw+Y3z9Mckgs0kUNsrBYsN1EnXpbUuv7qvIBv0mUk8sPSnoSUlPbD3Z0JMtPdnUk3U9cfSkqCfuX4Jya8fbOeG/yC4JdIqJ+JFAa2AicybQFphI5gXaNhOTJwKlysRMTaAVMDGxKtCqmYilBSopE8E1gbJgYnhRoHIxMbgiUImZGO0V6E1gIvBPwOQiXdE3YgSM03f6/iVhilzTY5ZplCjXvlCCaZQu12btgGmUtDJ77pJplLoy+/8V06gByuyXJtOoDYq+CzONmqHcJHLINGqJsu/9CtOoMcpN9p6ZRu1RdCzatSYlYZMUfZz70URx/03nIUI9NPBxfVsptZ7m2x+J0v149Hwh33obW859BgAA//+ba07xOgYAAA==
;; SERVER: 192.36.148.17
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @192.5.6.30 A aba8735d2c3d241de.awsglobalaccelerator.com.
;; opcode: QUERY, status: NOERROR, id: 54814
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 4, ADDITIONAL: 2

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 4096

;; QUESTION SECTION:
;aba8735d2c3d241de.awsglobalaccelerator.com.	IN	 A

;; AUTHORITY SECTION:
awsglobalaccelerator.com.	172800	IN	NS	ns-609.awsdns-12.net.
awsglobalaccelerator.com.	172800	IN	NS	ns-409.awsdns-51.com.
awsglobalaccelerator.com.	172800	IN	NS	ns-1949.awsdns-51.co.uk.
awsglobalaccelerator.com.	172800	IN	NS	ns-1484.awsdns-57.org.

;; ADDITIONAL SECTION:
ns-409.awsdns-51.com.	172800	IN	A	205.251.193.153

;; GZPACK: H4sIAAAAAAAA/7om18jAwMjAwMDCwCSYmJRoYW5smmKUbJxiZGKYkiqSWF6cnpOflJiTmJycmpNalFiSX8ScnJ8L0sOIR5aJgZGBaTEDgxhbXrGumYElZ2J5cUpesa6hEXNeagkDsTpNEDpNDcHyROiUZAdZZGmCpJUpOZ+pNJsYzeJgzSYWJnDN5sz5RekM2F0DCgWwNpazvw/OZGDQFGCAAEAAAAD//zw5IepXAQAA
;; SERVER: 192.5.6.30
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @205.251.193.153 A aba8735d2c3d241de.awsglobalaccelerator.com.
;; opcode: QUERY, status: NOERROR, id: 10475
;; flags: qr aa rd; QUERY: 1, ANSWER: 2, AUTHORITY: 4, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 4096

;; QUESTION SECTION:
;aba8735d2c3d241de.awsglobalaccelerator.com.	IN	 A

;; ANSWER SECTION:
aba8735d2c3d241de.awsglobalaccelerator.com.	300	IN	A	166.117.98.246
aba8735d2c3d241de.awsglobalaccelerator.com.	300	IN	A	166.117.166.206

;; AUTHORITY SECTION:
awsglobalaccelerator.com.	172800	IN	NS	ns-1484.awsdns-57.org.
awsglobalaccelerator.com.	172800	IN	NS	ns-1949.awsdns-51.co.uk.
awsglobalaccelerator.com.	172800	IN	NS	ns-409.awsdns-51.com.
awsglobalaccelerator.com.	172800	IN	NS	ns-609.awsdns-12.net.

;; GZPACK: H4sIAAAAAAAA/9J43crAwMjAxMDCwCiYmJRoYW5smmKUbJxiZGKYkiqSWF6cnpOflJiTmJycmpNalFiSX8ScnJ8L0kOyegYGRh0GlmWlSd/I1bnsHB51TCB/LGZgEGfPK9Y1NLEw4UwsL07JK9Y1NWfOL0pnIEKrJFirpYklXKshU3I+U2k2MZrF2PKKdU0MkPSC5YnVaYbQaWjEnJdawsDAoCnAAAGAAAAA////1KkspwEAAA==
;; SERVER: 205.251.193.153
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @205.251.193.153 A aba8735d2c3d241de.awsglobalaccelerator.com.
;; opcode: QUERY, status: NOERROR, id: 12194
;; flags: qr aa rd; QUERY: 1, ANSWER: 2, AUTHORITY: 4, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 4096

;; QUESTION SECTION:
;aba8735d2c3d241de.awsglobalaccelerator.com.	IN	 A

;; ANSWER SECTION:
aba8735d2c3d241de.awsglobalaccelerator.com.	300	IN	A	166.117.166.206
aba8735d2c3d241de.awsglobalaccelerator.com.	300	IN	A	166.117.98.246

;; AUTHORITY SECTION:
awsglobalaccelerator.com.	172800	IN	NS	ns-1484.awsdns-57.org.
awsglobalaccelerator.com.	172800	IN	NS	ns-1949.awsdns-51.co.uk.
awsglobalaccelerator.com.	172800	IN	NS	ns-409.awsdns-51.com.
awsglobalaccelerator.com.	172800	IN	NS	ns-609.awsdns-12.net.

;; GZPACK: H4sIAAAAAAAA/9Jf1MrAwMjAxMDCwCiYmJRoYW5smmKUbJxiZGKYkiqSWF6cnpOflJiTmJycmpNalFiSX8ScnJ8L0kOyegYGRh0GlmWly86RqzPpGx51TCB/LGZgEGfPK9Y1NLEw4UwsL07JK9Y1NWfOL0pnIEKrJFirpYklXKshU3I+U2k2MZrF2PKKdU0MkPSC5YnVaYbQaWjEnJdawsDAoCnAAAGAAAAA//8X4RxxpwEAAA==
;; SERVER: 205.251.193.153
;;; ----------------------------------------------------------------------
; <<>> recursive <<>> @205.251.193.153 A aba8735d2c3d241de.awsglobalaccelerator.com.
;; opcode: QUERY, status: NOERROR, id: 18170
;; flags: qr aa rd; QUERY: 1, ANSWER: 2, AUTHORITY: 4, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 4096

;; QUESTION SECTION:
;aba8735d2c3d241de.awsglobalaccelerator.com.	IN	 A

;; ANSWER SECTION:
aba8735d2c3d241de.awsglobalaccelerator.com.	300	IN	A	166.117.166.206
aba8735d2c3d241de.awsglobalaccelerator.com.	300	IN	A	166.117.98.246

;; AUTHORITY SECTION:
awsglobalaccelerator.com.	172800	IN	NS	ns-1484.awsdns-57.org.
awsglobalaccelerator.com.	172800	IN	NS	ns-1949.awsdns-51.co.uk.
awsglobalaccelerator.com.	172800	IN	NS	ns-409.awsdns-51.com.
awsglobalaccelerator.com.	172800	IN	NS	ns-609.awsdns-12.net.

;; GZPACK: H4sIAAAAAAAA/3L71crAwMjAxMDCwCiYmJRoYW5smmKUbJxiZGKYkiqSWF6cnpOflJiTmJycmpNalFiSX8ScnJ8L0kOyegYGRh0GlmWly86RqzPpGx51TCB/LGZgEGfPK9Y1NLEw4UwsL07JK9Y1NWfOL0pnIEKrJFirpYklXKshU3I+U2k2MZrF2PKKdU0MkPSC5YnVaYbQaWjEnJdawsDAoCnAAAGAAAAA//8PacAPpwEAAA==
;; SERVER: 205.251.193.153
`
