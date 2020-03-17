// Copyright (c) 2019, Adel "0x4d31" Karimi.
// All rights reserved.
//
// Licensed under the BSD 3-Clause license.
// For full license text, see the LICENSE file in the repo root
// or https://opensource.org/licenses/BSD-3-Clause

package main

import (
	"flag"
	"fmt"
	"log"

	//
	// using relative path instead of absolute with $GOPATH
	// for non gopath uses (like git clone )
	//
	quick ".."

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	snaplen int32 = 1600
	promisc bool  = false
	handle  *pcap.Handle
	filter  string = "udp and dst port 443"
)

func processPacket(packet gopacket.Packet) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	udpLayer := packet.Layer(layers.LayerTypeUDP)

	// ipLayer returns nil so we can avoid it
	// and use only UDP frame to detect the version

	// if udpLayer != nil && ipLayer != nil {

	if udpLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		udp, _ := udpLayer.(*layers.UDP)
		var clientHello = quick.CHLO{}
		err := clientHello.DecodeCHLO(udp.LayerPayload())
		switch err {
		case nil:
		case quick.ErrWrongType:
			return
		default:
			log.Println("Error:", err)
			return
		}
		log.Printf("%s:%s -> %s:%s [QUIC]  SNI: %s\n", ip.SrcIP, udp.SrcPort, ip.DstIP, udp.DstPort, clientHello.TagValues["SNI"])
		fmt.Println(clientHello)
	}
	return
}

func main() {
	iface := flag.String("i", "en0", "Specify a network interface to capture on")

	// max number of packets
	count := flag.Int("c", 0, "No of Packets (default:0)")

	flag.Parse()

	// Open device
	handle, err := pcap.OpenLive(*iface, snaplen, promisc, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	// Set filter
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Listening on", *iface)
	// Process packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	c := 0
	for packet := range packetSource.Packets() {
		if c > *count {
			return
		}
		processPacket(packet)
		c++
	}
}
