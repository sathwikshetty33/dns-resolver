package dns

import (
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"math/rand"
	"net"
	"strings"
	"testing"
)

type MockPacketConn struct{}

func TestOutgoingDnsQuery(t *testing.T) {
	question := dnsmessage.Question{
		Name:  dnsmessage.MustNewName("com."),
		Type:  dnsmessage.TypeNS, // TypeNS means the authoritative Name Servers for com.
		Class: dnsmessage.ClassINET,
	}

	rootServers := strings.Split(ROOT_SERVERS, ",")
	if len(rootServers) == 0 {
		t.Fatalf("No root servers found")
	}
	servers := []net.IP{net.ParseIP(rootServers[0])}
	dnsAnswer, header, err := outgoingDnsQuery(servers, question)
	fmt.Println("dnsAnswer", dnsAnswer)
	fmt.Println("header", header)
	if err != nil {
		t.Fatalf("outgoingDnsQuery error: %s", err)
	}
	if header == nil {
		t.Fatalf("No header found")
	}
	if dnsAnswer == nil {
		t.Fatalf("no answer found")
	}
	if header.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("response was not succesful (maybe the DNS server has changed?)") //  indicates the status of the DNS query
	}
	err = dnsAnswer.SkipAllAnswers()
	if err != nil {
		t.Fatalf("SkipAllAnswers error: %s", err)
	}
	parsedAuthorities, err := dnsAnswer.AllAuthorities()
	fmt.Println("parsedAuthorities", parsedAuthorities)
	if err != nil {
		t.Fatalf("Error getting answers")
	}
	if len(parsedAuthorities) == 0 {
		t.Fatalf("No answers received")
	}
}

func TestHandlePacket(t *testing.T) {
	names := []string{"www.google.com.", "www.amazon.com."}
	for _, name := range names {
		id := uint16(rand.Intn(65536))
		message := dnsmessage.Message{
			Header: dnsmessage.Header{
				RCode:            dnsmessage.RCode(0),
				ID:               id,
				OpCode:           dnsmessage.OpCode(0),
				Response:         false,
				AuthenticData:    false,
				RecursionDesired: false,
			},
			Questions: []dnsmessage.Question{
				{
					Name:  dnsmessage.MustNewName(name),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
				},
			},
		}
		_, err := message.Pack()
		if err != nil {
			t.Fatalf("Pack error: %s", err)
		}

		//err = handlePacket(&MockPacketConn{}, &net.IPAddr{IP: net.ParseIP("127.0.0.1")}, buf)
		//if err != nil {
		//	t.Fatalf("serve error: %s", err)
		//}
	}

}
