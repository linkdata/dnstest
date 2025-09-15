package dnstest

import (
	"bufio"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

var (
	headerRe = regexp.MustCompile(`opcode:\s*([A-Z]+),\s*status:\s*([A-Z0-9_-]+),\s*id:\s*(\d+)`)
	flagsRe  = regexp.MustCompile(`flags:\s*([a-z ]+);`)
	countsRe = regexp.MustCompile(`QUERY:\s*(\d+),\s*ANSWER:\s*(\d+),\s*AUTHORITY:\s*(\d+),\s*ADDITIONAL:\s*(\d+)`)
	serverRe = regexp.MustCompile(`^;;\s*SERVER:\s*([^\s#(;]+)(?:#(\d+))?`)
	// Examples we try to support:
	//   "EDNS: version 0; flags: do; udp: 1232"
	//   "EDNS: version: 0, flags:; udp: 4096"
	ednsRe = regexp.MustCompile(`EDNS:\s*version:?[\s]*([0-9]+)[,;]?\s*flags:\s*([a-z ]*);?\s*udp:\s*([0-9]+)`)
)

func isEmptyMsg(m *dns.Msg) bool {
	if m != nil {
		if len(m.Question) > 0 || len(m.Answer) > 0 || len(m.Extra) > 0 || len(m.Ns) > 0 || m.Rcode != dns.RcodeSuccess {
			return false
		}
	}
	return true
}

// ParseDigOutput turns the stdout text of `dig` into a dns.Msg, the server that
// was queried (as "host" or "host#port" if available), and an error.
// It best-effort fills MsgHdr (id, opcode, rcode, flags), Question, Answer,
// Authority, Additional, and EDNS (via OPT PSEUDOSECTION).
//
// If it reads a line starting with "; <<>> " and it has found data, it returns.
// This allows reading consecutive messages from a single stream.
func ParseDigOutput(r io.Reader) (exchs []Exchange, err error) {
	var (
		msg            = new(dns.Msg)
		retv           []Exchange
		srvaddr        string
		section        = "" // "", "question", "answer", "authority", "additional", "opt"
		rrBuf          []string
		parenDepth     int
		seenHeaderLine bool
	)

	sc := bufio.NewScanner(r)

	for err == nil && sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			// DIG version line (separates entries)
			if strings.HasPrefix(line, "; <<>> ") {
				if !isEmptyMsg(msg) {
					retv = append(retv, Exchange{Server: srvaddr, Msg: msg})
				}
				msg = new(dns.Msg)
				srvaddr = ""
				seenHeaderLine = false
				parenDepth = 0
				rrBuf = nil
				continue
			}

			// SERVER line
			if strings.HasPrefix(line, ";; SERVER:") {
				if m := serverRe.FindStringSubmatch(line); m != nil {
					srvaddr = m[1]
					if m[2] != "" {
						srvaddr = srvaddr + "#" + m[2]
					}
				}
				continue
			}

			// HEADER line (id/opcode/status)
			if !seenHeaderLine {
				if strings.HasPrefix(line, ";; ->>HEADER<<-") || strings.HasPrefix(line, ";; opcode:") {
					seenHeaderLine = true
					if m := headerRe.FindStringSubmatch(line); m != nil {
						msg.Id = parseUint16(m[3])
						msg.Opcode = opcodeFromString(m[1])
						msg.Rcode = rcodeFromString(m[2])
					}
					continue
				}
			}

			// FLAGS / COUNTS (may be same line as HEADER or the next one)
			if strings.HasPrefix(line, ";; flags:") || (seenHeaderLine && strings.HasPrefix(line, "flags:")) {
				if m := flagsRe.FindStringSubmatch(line); m != nil {
					setFlags(msg, m[1])
				}
				// counts are not strictly required to be set in MsgHdr; dns.Msg
				// derives them from the slices on pack. We parse them only to avoid surprises.
				if m := countsRe.FindStringSubmatch(line); m != nil {
					// No-op; present for validation. We rely on slice lengths.
					_ = m
				}
				continue
			}

			if strings.HasPrefix(line, ";; ") {
				if strings.HasSuffix(line, "SECTION:") {
					section = ""
					switch line {
					case ";; QUESTION SECTION:":
						section = "question"
					case ";; ANSWER SECTION:":
						section = "answer"
					case ";; AUTHORITY SECTION:":
						section = "authority"
					case ";; ADDITIONAL SECTION:":
						section = "additional"
					case ";; OPT PSEUDOSECTION:":
						section = "opt"
					}
				}
				continue
			}

			// Parse the active section
			switch section {
			case "question":
				// Format usually: ";example.com.            IN      A"
				if after, ok := strings.CutPrefix(line, ";"); ok {
					s := strings.TrimSpace(after)
					parts := fieldsClean(s)
					// Some dig builds can omit class and show just name + type in QUESTION.
					// We try [name class type] then [name type].
					switch len(parts) {
					case 2:
						name := parts[0]
						qtype := parts[1]
						msg.Question = append(msg.Question, dns.Question{
							Name:   dns.Fqdn(name),
							Qtype:  typeFromString(qtype),
							Qclass: dns.ClassINET,
						})
					default:
						if len(parts) >= 3 {
							name, classStr, typeStr := parts[0], parts[1], parts[2]
							msg.Question = append(msg.Question, dns.Question{
								Name:   dns.Fqdn(name),
								Qtype:  typeFromString(typeStr),
								Qclass: classFromString(classStr),
							})
						}
					}
				}

			case "opt":
				// The EDNS summary may be on the next line after the ";; OPT PSEUDOSECTION:" header.
				// Accept lines starting with ';' or raw.
				l := strings.TrimPrefix(line, ";")
				l = strings.TrimSpace(l)
				if m := ednsRe.FindStringSubmatch(l); m != nil {
					udpSize := parseUint16(m[3])
					do := strings.Contains(strings.ToLower(m[2]), "do")
					opt := msg.IsEdns0()
					if opt == nil {
						opt = &dns.OPT{}
						opt.Hdr.Name = "."
						opt.Hdr.Rrtype = dns.TypeOPT
						opt.SetUDPSize(udpSize)
						opt.SetDo(do)
						msg.Extra = append(msg.Extra, opt)
					} else {
						// Update existing
						opt.SetUDPSize(udpSize)
						opt.SetDo(do)
					}
					// Version (m[1]) is typically 0; miekg/dns keeps it in opt.Hdr.Ttl bits.
					// dns.EDNS0_VERSION is encoded in TTL upper 8 bits; we leave default (0).
				}
				// If the line is not the EDNS summary (e.g., "; NSID: ..."), we ignore.

			case "answer", "authority", "additional":
				// Collect RRs; handle multi-line with parentheses the same way dig prints folded records.
				parenDepth += strings.Count(line, "(") - strings.Count(line, ")")
				rrBuf = append(rrBuf, line)
				if parenDepth > 0 {
					continue
				}
				rrLine := normalizeRR(strings.Join(rrBuf, " "))
				rrBuf = rrBuf[:0]

				var rr dns.RR
				if rr, err = dns.NewRR(strings.Join(fieldsClean(rrLine), " ")); err == nil && rr != nil {
					switch section {
					case "answer":
						msg.Answer = append(msg.Answer, rr)
					case "authority":
						msg.Ns = append(msg.Ns, rr)
					case "additional":
						// Avoid duplicating OPT; dig often renders OPT in the pseudo-section,
						// but sometimes also shows other additionals (A/AAAA for NS target etc).
						if _, ok := rr.(*dns.OPT); ok {
							// ensure it’s the EDNS we already set; skip duplicate
							continue
						}
						msg.Extra = append(msg.Extra, rr)
					}
				}
			}
		}
	}

	if err == nil {
		if err = sc.Err(); err == nil {
			if !isEmptyMsg(msg) {
				retv = append(retv, Exchange{Server: srvaddr, Msg: msg})
			}
			exchs = retv
		}
	}
	return
}

// --- helpers ---

func parseUint16(s string) uint16 {
	n, _ := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
	return uint16(n)
}

func fieldsClean(s string) []string {
	fs := strings.Fields(s)
	// Clean trailing semicolons that sometimes sneak in
	for i := range fs {
		fs[i] = strings.TrimSuffix(fs[i], ";")
	}
	return fs
}

func normalizeRR(s string) string {
	// Collapse runs of whitespace, remove stray leading semicolons, trim.
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, ";")
	// Replace tabs with spaces; keep quoted strings as-is (dns.NewRR can handle).
	s = strings.Join(strings.Fields(s), " ")
	return s
}

func setFlags(msg *dns.Msg, flags string) {
	for f := range strings.FieldsSeq(strings.ToLower(flags)) {
		switch f {
		case "qr":
			msg.Response = true
		case "aa":
			msg.Authoritative = true
		case "tc":
			msg.Truncated = true
		case "rd":
			msg.RecursionDesired = true
		case "ra":
			msg.RecursionAvailable = true
		case "ad":
			msg.AuthenticatedData = true
		case "cd":
			msg.CheckingDisabled = true
		}
	}
}

func opcodeFromString(s string) int {
	return dns.StringToOpcode[strings.ToUpper(strings.TrimSpace(s))]
}

func rcodeFromString(s string) (rcode int) {
	s = strings.ToUpper(strings.TrimSpace(s))
	switch s {
	case "SUCCESS":
		s = "NOERROR"
	case "BADVERS":
		s = "BADSIG"
	}
	return dns.StringToRcode[s]
}

func typeFromString(s string) uint16 {
	return dns.StringToType[strings.ToUpper(s)]
}

func classFromString(s string) (c uint16) {
	c = dns.ClassINET
	if v, ok := dns.StringToClass[strings.ToUpper(s)]; ok {
		c = v
	}
	return
}
