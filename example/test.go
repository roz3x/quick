// Licensed under the BSD 3-Clause license.
// For full license text, see the LICENSE file in the repo root
// or https://opensource.org/licenses/BSD-3-Clause

package main

import (
	"flag"
	"fmt"
	"log"

	"encoding/binary"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	snaplen int32 = 1600
	promisc bool  = false
	handle  *pcap.Handle
	filter  string = "udp and dst port 443"
    count   int   = 0
)

func decode(payload []byte) {

	VersionNumber := binary.BigEndian.Uint32(payload[1:5])

	if VersionNumber&0xffffff00 == 0xff000000 {
		// iQUIC version

		//fmt.Printf("iQUIC version found \n")

	} else if string(payload[1:3]) == "Q0" {
		// gQUIC version

        // formatter 

		fmt.Printf("gQUIC version found \n")
            if bytes.Contains(payload, []byte("CHLO")) {
                fmt.Print("[]byte{")
                for t, i := range payload {
                    fmt.Printf(" 0x%X , ", i)
                       if t % 20 == 0 {
                      fmt.Printf("\n")
                 }
            }
          fmt.Print("}")
          os.Exit(0)
        }
	} else {
		//fmt.Printf("version undefined : %v \n",VersionNumber)
	}
}

func processPacket(packet gopacket.Packet) {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		decode(udp.LayerPayload())
	}
	return
}

func main() {
	iface := flag.String("i", "wlan0", "Specify a network interface to capture on")

	flag.Parse()

	handle, err := pcap.OpenLive(*iface, snaplen, promisc, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}
	//fmt.Println("Listening on", *iface)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		processPacket(packet)
	}
}
