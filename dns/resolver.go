package dns

import (
	"bufio"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const ROOT_SERVERS = "198.41.0.4,199.9.14.201,192.33.4.12,199.7.91.13,192.203.230.10,192.5.5.241,192.112.36.4,198.97.190.53"

func HandlePacket(pc net.PacketConn, addr net.Addr, buf []byte) {
	if err := handlePacket(pc, addr, buf); err != nil {
		fmt.Printf("handlePacket error: %s\n", err)
		// Send error response back to client
		sendErrorResponse(pc, addr, dnsmessage.RCodeServerFailure)
	}
}

func sendErrorResponse(pc net.PacketConn, addr net.Addr, rcode dnsmessage.RCode) {
	errorMsg := dnsmessage.Message{
		Header: dnsmessage.Header{
			Response: true,
			RCode:    rcode,
		},
	}
	if buf, err := errorMsg.Pack(); err == nil {
		pc.WriteTo(buf, addr)
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
	fmt.Printf("Question: %s\n", question.Name.String())

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
	return err
}

func dnsQuery(servers []net.IP, question dnsmessage.Question) (*dnsmessage.Message, error) {
	for i := 0; i < 10; i++ { // Increased iteration limit
		fmt.Printf("Iteration %d: Querying %s\n", i+1, question.Name.String())

		dnsAnswer, header, err := outgoingDnsQuery(servers, question)
		if err != nil {
			fmt.Printf("outgoingDnsQuery error: %s\n", err)
			return nil, err
		}

		// Check for CNAME records first
		parsedAnswers, err := dnsAnswer.AllAnswers()
		if err != nil {
			return nil, err
		}

		for _, ans := range parsedAnswers {
			if ans.Header.Type == dnsmessage.TypeCNAME {
				cname := ans.Body.(*dnsmessage.CNAMEResource).CNAME.String()
				fmt.Printf("Following CNAME: %s -> %s\n", question.Name.String(), cname)
				return dnsQuery(getRootServers(), dnsmessage.Question{
					Name:  dnsmessage.MustNewName(cname),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
				})
			}
		}

		// If we have answers and it's authoritative, we're done
		if header.Authoritative && len(parsedAnswers) > 0 {
			fmt.Printf("Authoritative answer found with %d records\n", len(parsedAnswers))
			return &dnsmessage.Message{
				Header:    dnsmessage.Header{Response: true, Authoritative: true},
				Questions: []dnsmessage.Question{question},
				Answers:   parsedAnswers,
			}, nil
		}

		// Get authority records (NS records)
		authorities, err := dnsAnswer.AllAuthorities()
		if err != nil {
			return nil, err
		}

		if len(authorities) == 0 {
			return &dnsmessage.Message{
				Header: dnsmessage.Header{
					RCode:    dnsmessage.RCodeNameError,
					Response: true,
				},
				Questions: []dnsmessage.Question{question},
			}, nil
		}

		// Extract nameservers from authority section
		var nameServers []string
		for _, authority := range authorities {
			if authority.Header.Type == dnsmessage.TypeNS {
				if ns, ok := authority.Body.(*dnsmessage.NSResource); ok {
					nameServers = append(nameServers, ns.NS.String())
				}
			}
		}

		if len(nameServers) == 0 {
			continue
		}

		fmt.Printf("Found %d nameservers: %v\n", len(nameServers), nameServers)

		// Check for glue records in additional section
		additionals, err := dnsAnswer.AllAdditionals()
		if err != nil {
			return nil, err
		}

		var newServers []net.IP
		glueFound := false

		for _, additional := range additionals {
			if additional.Header.Type == dnsmessage.TypeA {
				nsName := additional.Header.Name.String()
				for _, nameServer := range nameServers {
					if nsName == nameServer {
						ip := additional.Body.(*dnsmessage.AResource).A[:]
						newServers = append(newServers, ip)
						glueFound = true
						fmt.Printf("Found glue record: %s -> %s\n", nsName, net.IP(ip).String())
					}
				}
			}
		}

		// If we found glue records, use them for next query
		if glueFound && len(newServers) > 0 {
			servers = newServers
			continue
		}

		// No glue records found, need to resolve nameservers
		fmt.Printf("No glue records found, resolving nameservers...\n")
		newServers = nil

		for _, nameServer := range nameServers {
			fmt.Printf("Resolving nameserver: %s\n", nameServer)
			res, err := dnsQuery(getRootServers(), dnsmessage.Question{
				Name:  dnsmessage.MustNewName(nameServer),
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			})

			if err != nil {
				fmt.Printf("Failed to resolve nameserver %s: %s\n", nameServer, err)
				continue
			}

			// Extract IP addresses from the response
			for _, answer := range res.Answers {
				if answer.Header.Type == dnsmessage.TypeA {
					ip := answer.Body.(*dnsmessage.AResource).A[:]
					newServers = append(newServers, ip)
					fmt.Printf("Resolved %s -> %s\n", nameServer, net.IP(ip).String())
				}
			}

			// If we got at least one IP, we can proceed
			if len(newServers) > 0 {
				break
			}
		}

		if len(newServers) == 0 {
			return &dnsmessage.Message{
				Header: dnsmessage.Header{
					RCode:    dnsmessage.RCodeServerFailure,
					Response: true,
				},
				Questions: []dnsmessage.Question{question},
			}, nil
		}

		servers = newServers
	}

	// If we've exceeded max iterations, return server failure
	return &dnsmessage.Message{
		Header: dnsmessage.Header{
			RCode:    dnsmessage.RCodeServerFailure,
			Response: true,
		},
		Questions: []dnsmessage.Question{question},
	}, nil
}

func getRootServers() []net.IP {
	var rootServersSlice []net.IP
	for _, rootServer := range strings.Split(ROOT_SERVERS, ",") {
		if ip := net.ParseIP(rootServer); ip != nil {
			rootServersSlice = append(rootServersSlice, ip)
		}
	}
	return rootServersSlice
}

func outgoingDnsQuery(servers []net.IP, question dnsmessage.Question) (*dnsmessage.Parser, *dnsmessage.Header, error) {
	id := uint16(rand.Intn(65536))
	message := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               id,
			Response:         false,
			OpCode:           dnsmessage.OpCode(0),
			RecursionDesired: false, // We're doing iterative resolution
		},
		Questions: []dnsmessage.Question{question},
	}

	buf, err := message.Pack()
	if err != nil {
		return nil, nil, err
	}

	var lastErr error
	for _, server := range servers {
		fmt.Printf("Trying server: %s\n", server.String())

		conn, err := net.DialTimeout("udp", server.String()+":53", 5*time.Second)
		if err != nil {
			lastErr = err
			continue
		}

		// Set read/write timeouts
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))

		_, err = conn.Write(buf)
		if err != nil {
			conn.Close()
			lastErr = err
			continue
		}

		ans := make([]byte, 512)
		n, err := bufio.NewReader(conn).Read(ans)
		conn.Close()

		if err != nil {
			lastErr = err
			continue
		}

		var p dnsmessage.Parser
		headers, err := p.Start(ans[:n])
		if err != nil {
			lastErr = fmt.Errorf("parser start error: %s", err)
			continue
		}

		// Verify this is a response to our query
		if headers.ID != id {
			lastErr = fmt.Errorf("ID mismatch: expected %d, got %d", id, headers.ID)
			continue
		}

		// Skip questions section
		err = p.SkipAllQuestions()
		if err != nil {
			lastErr = fmt.Errorf("parser questions skip error: %s", err)
			continue
		}

		return &p, &headers, nil
	}

	return nil, nil, fmt.Errorf("all servers failed, last error: %v", lastErr)
}
