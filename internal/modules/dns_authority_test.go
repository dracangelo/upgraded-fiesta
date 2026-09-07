package modules

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestLookupDNSAnswersReadsSOAAndCAA(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc("example.test.", func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		for _, question := range request.Question {
			switch question.Qtype {
			case dns.TypeSOA:
				response.Answer = append(response.Answer, &dns.SOA{Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60}, Ns: "ns1.example.test.", Mbox: "hostmaster.example.test.", Serial: 1})
			case dns.TypeCAA:
				response.Answer = append(response.Answer, &dns.CAA{Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: 60}, Flag: 0, Tag: "issue", Value: "letsencrypt.org"})
			}
		}
		_ = w.WriteMsg(response)
	})
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := &dns.Server{PacketConn: listener, Handler: mux}
	go func() { _ = server.ActivateAndServe() }()
	defer func() { _ = server.Shutdown() }()
	for _, questionType := range []uint16{dns.TypeSOA, dns.TypeCAA} {
		answers, err := lookupDNSAnswers(context.Background(), listener.LocalAddr().String(), "example.test", questionType)
		if err != nil || len(answers) != 1 {
			t.Fatalf("DNS answer %d: %#v, %v", questionType, answers, err)
		}
	}
}
