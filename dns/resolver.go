package dns

import (
	"bufio"
	"fmt"
	"math/rand"
	"net"

	"golang.org/x/net/dns/dnsmessage"
)

const ROOT_SERVERS = "198.41.0.4,199.9.14.201,192.33.4.12,199.7.91.13,192.203.230.10,192.5.5.241,192.112.36.4,198.97.190.53"

func handlePacket(pc net.PacketConn, addr net.Addr, buf []byte) error {
	return fmt.Errorf("not implemented yet")
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
	err = conn.Close()
	if err != nil {
		return nil, nil, err
	}
	var p dnsmessage.Parser
	headers, err := p.Start(ans[:n])
	if err != nil {
		return nil, nil, fmt.Errorf("parser start errords:%s", err)
	}
	return &p, &headers, nil
}
