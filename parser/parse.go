package parser

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/miekg/dns"
	"log"
	"os"
	"time"
)

const (
	DnsAnswer     = iota
	DnsAuthority  = iota
	DnsAdditional = iota
)

func ParseFile(file *os.File) {
	handle, err := pcap.OpenOfflineFile(file)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	ParseDns(handle)
}

func ParseDevice(device string) {
	// NOTE: These should probably be parameters of the function
	snapshotLen := int32(4096)
	promiscuous := false
	timeout := 30 * time.Second

	// Open live device
	handle, err := pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	ParseDns(handle)
}

func ParseDns(handle *pcap.Handle) {
	var (
		schema DnsSchema
		eth    layers.Ethernet
		ip4    layers.IPv4
		ip6    layers.IPv6
		tcp    layers.TCP
		udp    layers.UDP
	)

	// Let's reuse the same layers for performance improvement
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp)
	decoded := []gopacket.LayerType{}

	// Setup BPF filter on handle
	handle.SetBPFFilter("port 53")

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.NoCopy = true

	PACKETLOOP:
	for packet := range packetSource.Packets() {
		schema.Timestamp = packet.Metadata().Timestamp.Second()

		if err := parser.DecodeLayers(packet.Data(), &decoded); err != nil {
			// TODO: Add logging
			//fmt.Fprintf(os.Stderr, "Could not decode layers: %v\n", err)
		}

		// Let's decode different layers
		msg := new(dns.Msg)
		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeIPv4:
				schema.SourceAddress = ip4.SrcIP.String()
				schema.DestinationAddress = ip4.DstIP.String()
			case layers.LayerTypeIPv6:
				schema.SourceAddress = ip6.SrcIP.String()
				schema.DestinationAddress = ip6.DstIP.String()
			case layers.LayerTypeTCP:
				schema.SourcePort = uint16(tcp.SrcPort)
				schema.DestinationPort = uint16(tcp.DstPort)
				if err := msg.Unpack(tcp.Payload); err != nil {
					// TODO: Add logging
					//fmt.Fprintf(os.Stderr, "Could not decode DNS: %v\n", err)
					continue PACKETLOOP
				}
			case layers.LayerTypeUDP:
				schema.SourcePort = uint16(udp.SrcPort)
				schema.DestinationPort = uint16(udp.DstPort)
				if err := msg.Unpack(udp.Payload); err != nil {
					// TODO: Add logging
					//fmt.Fprintf(os.Stderr, "Could not decode DNS: %v\n", err)
					continue PACKETLOOP
				}
			}
		}

		// Fill out information from DNS headers
		schema.Id = msg.Id
		schema.RecursionDesired = msg.RecursionDesired
		schema.Nxdomain = msg.Opcode == 3

		// Parse ECS information
		if opt := msg.IsEdns0(); opt != nil {
			for _, s := range opt.Option {
				switch o := s.(type) {
				case *dns.EDNS0_SUBNET:
					schema.EcsClient = o.Address.String()
					schema.EcsSource = o.SourceNetmask
					schema.EcsScope = o.SourceScope
				}
			}
		}

		// Let's get ANSWERS
		for _, rr := range msg.Answer {
			schema.ToJson(rr, DnsAnswer)
		}

		// Let's get AUTHORITATIVE information
		for _, rr := range msg.Ns {
			schema.ToJson(rr, DnsAuthority)
		}

		// Let's get ADDITIONAL information
		for _, rr := range msg.Extra {
			schema.ToJson(rr, DnsAdditional)
		}

		// Let's check and see if we had any errors decoding any of the packets
		if err := packet.ErrorLayer(); err != nil {
			fmt.Println("Error decoding some part of the packet:", err)
		}
	}
}
