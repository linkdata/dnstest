// Package dnstest provides a configurable DNS server simulator for tests.
package dnstest

import (
	"net"
	"time"

	"github.com/miekg/dns"
)

// Response defines how the server should answer a specific DNS question.
type Response struct {
	// Msg is sent as the response if non-nil. The Question and Id are set from
	// the incoming request before sending.
	Msg *dns.Msg
	// Rcode is used if Msg is nil to set the reply code in the generated
	// message. Defaults to RcodeSuccess.
	Rcode int
	// Raw is written directly on the wire instead of Msg/Rcode allowing
	// responses with malformed DNS packets.
	Raw []byte
	// Drop causes the server to ignore the request simulating a timeout.
	Drop bool
	// Delay adds an optional delay before processing the response.
	Delay time.Duration
}

// Server simulates a DNS server for use in tests.
type Server struct {
	// Addr is the address the server is listening on.
	Addr string

	responses map[string]*Response
	udp       *dns.Server
	tcp       *dns.Server
}

// NewServer starts a new DNS server on addr serving the provided responses.
// The same address and port are used for both UDP and TCP. If the port in addr
// is "0" an available port will be chosen automatically.
func NewServer(addr string, responses map[string]*Response) (s *Server, err error) {
	var udpAddr *net.UDPAddr
	if udpAddr, err = net.ResolveUDPAddr("udp", addr); err == nil {
		var udpConn *net.UDPConn
		if udpConn, err = net.ListenUDP("udp", udpAddr); err == nil {
			var tcpListener net.Listener
			if tcpListener, err = net.Listen("tcp", udpConn.LocalAddr().String()); err == nil {
				s = &Server{
					Addr:      udpConn.LocalAddr().String(),
					responses: responses,
				}
				handler := dns.HandlerFunc(s.handle)
				s.udp = &dns.Server{PacketConn: udpConn, Handler: handler}
				s.tcp = &dns.Server{Listener: tcpListener, Handler: handler}
				go s.udp.ActivateAndServe()
				go s.tcp.ActivateAndServe()
			} else {
				_ = udpConn.Close()
			}
		}
	}
	return
}

// Close shuts down the server.
func (s *Server) Close() {
	if s.udp != nil {
		_ = s.udp.Shutdown()
	}
	if s.tcp != nil {
		_ = s.tcp.Shutdown()
	}
}

func (s *Server) handle(w dns.ResponseWriter, req *dns.Msg) {
	for _, q := range req.Question {
		if resp, ok := s.responses[Key(q.Name, q.Qtype)]; ok {
			if resp.Delay > 0 {
				time.Sleep(resp.Delay)
			}
			if !resp.Drop {
				if resp.Raw != nil {
					_, _ = w.Write(resp.Raw)
					return
				}
				m := new(dns.Msg)
				if resp.Msg != nil {
					resp.Msg.CopyTo(m)
				}
				m.SetReply(req)
				if resp.Rcode != dns.RcodeSuccess {
					m.Rcode = resp.Rcode
				}
				_ = w.WriteMsg(m)
			}
		}
	}
}

// Key returns a map key for the given question name and type.
func Key(name string, qtype uint16) string {
	return dns.CanonicalName(name) + "/" + dns.TypeToString[qtype]
}
