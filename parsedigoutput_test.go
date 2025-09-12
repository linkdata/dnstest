package dnstest

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestParseDigOutput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		digOut           string
		wantID           uint16
		wantRcode        int
		wantOpcode       int
		wantServer       string
		wantQname        string
		wantQtype        uint16
		wantQclass       uint16
		wantAnswerLens   int
		wantNsLens       int
		wantExtraAtLeast int // because EDNS adds an OPT
		wantDO           bool
		wantUDP          uint16
	}{
		{
			name: "NOERROR with EDNS + DO, multiline TXT, all sections",
			digOut: strings.TrimSpace(`
; <<>> DiG 9.18.1 <<>> +dnssec example.com @8.8.8.8
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1234
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 2, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags: do; udp: 1232
;; QUESTION SECTION:
;example.com.            IN      A

;; ANSWER SECTION:
example.com.     299     IN      A       93.184.216.34
example.com.     299     IN      TXT     ("hello world"
                                         "continued")

;; AUTHORITY SECTION:
example.com.     172800  IN      NS      b.iana-servers.net.

;; ADDITIONAL SECTION:
b.iana-servers.net. 3600 IN      A       199.43.135.53

;; Query time: 15 msec
;; SERVER: 8.8.8.8#53(8.8.8.8)
;; WHEN: Fri Sep 12 12:00:00 CEST 2025
;; MSG SIZE  rcvd: 123
`),
			wantID:           1234,
			wantRcode:        dns.RcodeSuccess,
			wantOpcode:       dns.OpcodeQuery,
			wantServer:       "8.8.8.8#53",
			wantQname:        "example.com.",
			wantQtype:        dns.TypeA,
			wantQclass:       dns.ClassINET,
			wantAnswerLens:   2,
			wantNsLens:       1,
			wantExtraAtLeast: 2, // OPT + one A RR for b.iana-servers.net
			wantDO:           true,
			wantUDP:          1232,
		},
		{
			name: "NXDOMAIN, question omits class, EDNS without DO",
			digOut: strings.TrimSpace(`
; <<>> DiG 9.18.1 <<>> does-not-exist.example @1.1.1.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 42
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; QUESTION SECTION:
;does-not-exist.example.        A

;; AUTHORITY SECTION:
example.        3600    IN  SOA a.iana-servers.net. noc.dns.icann.org. 2025010100 1800 900 604800 86400

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 4096

;; SERVER: 1.1.1.1#53(1.1.1.1)
;; WHEN: Fri Sep 12 12:00:00 CEST 2025
;; MSG SIZE  rcvd: 99
`),
			wantID:           42,
			wantRcode:        dns.RcodeNameError,
			wantOpcode:       dns.OpcodeQuery,
			wantServer:       "1.1.1.1#53",
			wantQname:        "does-not-exist.example.",
			wantQtype:        dns.TypeA,
			wantQclass:       dns.ClassINET, // defaulted by parser
			wantAnswerLens:   0,
			wantNsLens:       1,
			wantExtraAtLeast: 1, // OPT only
			wantDO:           false,
			wantUDP:          4096,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			msg, server, err := ParseDigOutput(strings.NewReader(tt.digOut))
			if err != nil {
				t.Fatalf("ParseDigOutput returned error: %v", err)
			}
			if msg == nil {
				t.Fatalf("ParseDigOutput returned nil msg")
			}
			if server != tt.wantServer {
				t.Fatalf("server: got %q, want %q", server, tt.wantServer)
			}

			// Header checks
			if msg.Id != tt.wantID {
				t.Errorf("Id: got %d, want %d", msg.Id, tt.wantID)
			}
			if msg.Opcode != tt.wantOpcode {
				t.Errorf("Opcode: got %d, want %d", msg.Opcode, tt.wantOpcode)
			}
			if msg.Rcode != tt.wantRcode {
				t.Errorf("Rcode: got %d, want %d", msg.Rcode, tt.wantRcode)
			}
			if !msg.Response {
				t.Errorf("flags: expected Response (qr) bit set")
			}
			if !msg.RecursionDesired {
				t.Errorf("flags: expected RD bit set")
			}
			if !msg.RecursionAvailable {
				t.Errorf("flags: expected RA bit set")
			}

			// Question
			if len(msg.Question) != 1 {
				t.Fatalf("Question len: got %d, want 1", len(msg.Question))
			}
			q := msg.Question[0]
			if q.Name != tt.wantQname {
				t.Errorf("Question name: got %q, want %q", q.Name, tt.wantQname)
			}
			if q.Qtype != tt.wantQtype {
				t.Errorf("Question type: got %d, want %d", q.Qtype, tt.wantQtype)
			}
			if q.Qclass != tt.wantQclass {
				t.Errorf("Question class: got %d, want %d", q.Qclass, tt.wantQclass)
			}

			// Sections
			if len(msg.Answer) != tt.wantAnswerLens {
				t.Errorf("Answer len: got %d, want %d", len(msg.Answer), tt.wantAnswerLens)
			}
			if len(msg.Ns) != tt.wantNsLens {
				t.Errorf("Authority len: got %d, want %d", len(msg.Ns), tt.wantNsLens)
			}
			if len(msg.Extra) < tt.wantExtraAtLeast {
				t.Errorf("Additional len: got %d, want >= %d", len(msg.Extra), tt.wantExtraAtLeast)
			}

			// EDNS
			if opt := msg.IsEdns0(); opt == nil {
				t.Fatalf("expected EDNS OPT, got nil")
			} else {
				if got := opt.UDPSize(); got != tt.wantUDP {
					t.Errorf("EDNS UDPSize: got %d, want %d", got, tt.wantUDP)
				}
				if tt.wantDO && !opt.Do() {
					t.Errorf("EDNS DO bit: got false, want true")
				}
				if !tt.wantDO && opt.Do() {
					t.Errorf("EDNS DO bit: got true, want false")
				}
			}

			// Deep-dive checks for first test case
			if strings.Contains(tt.name, "NOERROR") {
				// A record content
				var foundA, foundTXT, foundAddA bool
				for _, rr := range msg.Answer {
					switch r := rr.(type) {
					case *dns.A:
						foundA = r.Hdr.Name == "example.com." && r.A != nil && r.A.String() == "93.184.216.34" && r.Hdr.Ttl == 299
					case *dns.TXT:
						if r.Hdr.Name == "example.com." && r.Hdr.Ttl == 299 && len(r.Txt) == 2 {
							if r.Txt[0] == "hello world" && r.Txt[1] == "continued" {
								foundTXT = true
							}
						}
					}
				}
				if !foundA {
					t.Errorf("expected A RR for example.com. 93.184.216.34 with TTL 299")
				}
				if !foundTXT {
					t.Errorf("expected multiline TXT RR for example.com. with 2 strings")
				}

				// NS in authority
				if ns, ok := msg.Ns[0].(*dns.NS); !ok || ns.Hdr.Name != "example.com." || ns.Ns != "b.iana-servers.net." {
					t.Errorf("expected NS RR: example.com. NS b.iana-servers.net.")
				}

				// Additional contains A for b.iana-servers.net (besides OPT)
				for _, rr := range msg.Extra {
					if a, ok := rr.(*dns.A); ok && a.Hdr.Name == "b.iana-servers.net." && a.A.String() == "199.43.135.53" {
						foundAddA = true
					}
				}
				if !foundAddA {
					t.Errorf("expected Additional A RR for b.iana-servers.net.")
				}
			}
		})
	}
}
