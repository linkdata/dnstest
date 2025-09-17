// Package dnstest provides a configurable DNS server simulator for tests.
package dnstest

import (
	"net"
	"strconv"
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
	Addr string // (read-only) address and port we listen on
	Port uint16 // (read-only) port we listen on as uint16

	responses map[Key]*Response
	udp       *dns.Server
	tcp       *dns.Server
}

func getPort(hostport string) (port uint16, err error) {
	var portstr string
	if _, portstr, err = net.SplitHostPort(hostport); err == nil {
		var n uint64
		if n, err = strconv.ParseUint(portstr, 10, 16); err == nil {
			port = uint16(n)
		}
	}
	return
}

// NewServer starts a new DNS server on 127.0.0.1 and a random port serving the provided responses.
// The same address and port are used for both UDP and TCP.
func NewServer(responses map[Key]*Response) (s *Server, err error) {
	var udpAddr *net.UDPAddr
	if udpAddr, err = net.ResolveUDPAddr("udp", "127.0.0.1:0"); err == nil {
		var udpConn *net.UDPConn
		if udpConn, err = net.ListenUDP("udp", udpAddr); err == nil {
			listenAddr := udpConn.LocalAddr().String()
			var port uint16
			if port, err = getPort(listenAddr); err == nil {
				var tcpListener net.Listener
				if tcpListener, err = net.Listen("tcp", listenAddr); err == nil {
					s = &Server{
						Addr:      listenAddr,
						Port:      port,
						responses: responses,
					}
					s.udp = &dns.Server{PacketConn: udpConn, Handler: dns.HandlerFunc(s.handleUDP)}
					s.tcp = &dns.Server{Listener: tcpListener, Handler: dns.HandlerFunc(s.handleTCP)}
					go s.udp.ActivateAndServe()
					go s.tcp.ActivateAndServe()
				} else {
					_ = udpConn.Close()
				}
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

func (s *Server) handleUDP(w dns.ResponseWriter, req *dns.Msg) {
	s.handle(w, req, "udp")
}

func (s *Server) handleTCP(w dns.ResponseWriter, req *dns.Msg) {
	s.handle(w, req, "tcp")
}

func (s *Server) handle(w dns.ResponseWriter, req *dns.Msg, proto string) {
	for _, q := range req.Question {
		for _, pro := range []string{proto, ""} {
			if resp, ok := s.responses[NewKey(q.Name, q.Qtype, pro)]; ok {
				if !resp.Drop {
					if resp.Delay > 0 {
						time.Sleep(resp.Delay)
					}
					if resp.Raw != nil {
						_, _ = w.Write(resp.Raw)
					} else {
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
				break
			}
		}
	}
}
