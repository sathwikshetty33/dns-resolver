package dns

import (
	"bufio"
	"fmt"
	"math/rand"
	"net"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

const ROOT_SERVERS = "198.41.0.4,199.9.14.201,192.33.4.12,199.7.91.13,192.203.230.10,192.5.5.241,192.112.36.4,198.97.190.53"

func HandlePacket(pc net.PacketConn, addr net.Addr, buf []byte) {
	if err := handlePacket(pc, addr, buf); err != nil {
		fmt.Printf("handlePacket error: %s\n", err)
	}
}

func handlePacket(pc net.PacketConn, addr net.Addr, buf []byte) error {
	p := dnsmessage.Parser{}
	header, err := p.Start(buf)
	if err != nil {
		return err
	}
	question, err := p.Question()
	if err != nil {
		return err
	}
	res, err := dnsQuery(getRootServers(), question)
	if err != nil {
		return err
	}
	res.Header.ID = header.ID
	responseBuffer, err := res.Pack()
	if err != nil {
		return err
	}
	_, err = pc.WriteTo(responseBuffer, addr)
	if err != nil {
		return err
	}
	return nil
}
func dnsQuery(servers []net.IP, question dnsmessage.Question) (*dnsmessage.Message, error) {
	for i := 0; i < 3; i++ {
		dnsAnswer, header, err := outgoingDnsQuery(servers, question)
		if err != nil {
			return nil, err
		}
		parsedAnswers, err := dnsAnswer.AllAnswers()
		if err != nil {
			return nil, err
		}
		if header.Authoritative {
			return &dnsmessage.Message{
				Header:  dnsmessage.Header{Response: true},
				Answers: parsedAnswers,
			}, nil
		}
		authorities, err := dnsAnswer.AllAuthorities()
		if err != nil {
			return nil, err
		}
		if len(authorities) == 0 {
			return &dnsmessage.Message{
				Header: dnsmessage.Header{
					RCode: dnsmessage.RCodeNameError,
				},
			}, nil
		}
		nameServers := []string{}
		for _, authority := range authorities {
			fmt.Println("authority:", authority)
			nameServers = append(nameServers, authority.Body.GoString())
		}
	}
	return &dnsmessage.Message{
		Header: dnsmessage.Header{
			RCode: dnsmessage.RCodeServerFailure,
		},
	}, nil
}

func getRootServers() []net.IP {
	rootServers := strings.Split(ROOT_SERVERS, ",")
	if len(rootServers) == 0 {
		panic("No root servers found")
	}
	rootServersSlice := make([]net.IP, len(rootServers))
	for _, rootServer := range rootServers {
		rootServersSlice = append(rootServersSlice, net.ParseIP(rootServer))
	}
	return rootServersSlice
}
func outgoingDnsQuery(servers []net.IP, question dnsmessage.Question) (*dnsmessage.Parser, *dnsmessage.Header, error) {
	id := uint16(rand.Intn(65536))
	// Query
	message := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:       id,                   // random num to match questions with responses
			Response: false,                //tells the server it is query not response
			OpCode:   dnsmessage.OpCode(0), //standard DNS query
		},
		Questions: []dnsmessage.Question{question},
	}
	buf, err := message.Pack() // Packing the message to bytes so that it can be transmitted over UDP
	if err != nil {
		return nil, nil, err
	}
	var conn net.Conn
	for _, server := range servers {
		conn, err = net.Dial("udp", server.String()+":53") //Establishing a UDP connection with one of the root servers
		if err == nil {
			break // Break if connection with any one of them is established
		}
	}
	if conn == nil {
		return nil, nil, fmt.Errorf("could not connect to DNS server")
	}
	_, err = conn.Write(buf) // Sends the query to the connect root server
	ans := make([]byte, 512)
	n, err := bufio.NewReader(conn).Read(ans) //Reads up to 512 bytes from the response (the traditional DNS UDP limit). and store in ans
	if err != nil {
		return nil, nil, err
	}
	err = conn.Close() //Closes the UDP connection after reading the response.
	if err != nil {
		return nil, nil, err
	}
	var p dnsmessage.Parser
	headers, err := p.Start(ans[:n]) // initializes the parser and reads the DNS header and other internal state.
	if err != nil {
		return nil, nil, fmt.Errorf("parser start errords:%s", err)
	}
	questions, err := p.AllQuestions()
	if err != nil {
		return nil, nil, fmt.Errorf("parser questions errors:%s", err)
	}
	if len(message.Questions) != len(questions) {
		return nil, nil, fmt.Errorf("parser questions length errords:%d", len(questions))
	}
	err = p.SkipAllQuestions() // Moves the parsers past questions to next section
	if err != nil {
		return nil, nil, fmt.Errorf("parser questions skip errords:%s", err)
	}
	return &p, &headers, nil // headers gives you the metadata: response ID, response code, flags (like RecursionAvailable, Authoritative, etc.).
}

/* DNS Message Structure Reminder
A DNS message is composed of these sections in this exact order:

Header

Questions (what you're asking)

Answers (the direct answer)

Authority (where to go next)

Additional (helpful info) */
