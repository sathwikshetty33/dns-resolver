package main

import (
	"fmt"
	"github.com/sathwikshetty33/dns-resolver/dns"
	"net"
)

func main() {
	fmt.Println("Hello World!")
	packetConn, err := net.ListenPacket("udp", ":8001")
	if err != nil {
		panic(err)
	}
	defer packetConn.Close()
	for {
		buff := make([]byte, 512)
		bytesRead, addr, err := packetConn.ReadFrom(buff)
		if err != nil {
			fmt.Println("Error reading:", err.Error())
			continue
		}
		go dns.HandlePacket(packetConn, addr, buff[:bytesRead])
	}
}
