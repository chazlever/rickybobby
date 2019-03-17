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

var (
	NoParseTcp       = true
	NoParseEcs       = true
	DoParseQuestions = false
)

func ParseFile(fname string) {
	var (
		handle *pcap.Handle
		err    error
	)

	if "-" == fname {
		handle, err = pcap.OpenOfflineFile(os.Stdin)
	} else {
		handle, err = pcap.OpenOffline(fname)
	}

	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	ParseDns(handle)
}

func ParseDevice(device string, snapshotLen int32, promiscuous bool, timeout time.Duration) {
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
	if NoParseTcp {
		err := handle.SetBPFFilter("udp port 53")
		if err != nil {
			// TODO: Logging here
		}
	} else {
		err := handle.SetBPFFilter("port 53")
		if err != nil {
			// TODO: Logging here
		}
	}

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.NoCopy = true

PACKETLOOP:
	for packet := range packetSource.Packets() {
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
				schema.Udp = false
				if err := msg.Unpack(tcp.Payload); err != nil {
					// TODO: Add logging
					//fmt.Fprintf(os.Stderr, "Could not decode DNS: %v\n", err)
					continue PACKETLOOP
				}
			case layers.LayerTypeUDP:
				schema.SourcePort = uint16(udp.SrcPort)
				schema.DestinationPort = uint16(udp.DstPort)
				schema.Udp = true
				if err := msg.Unpack(udp.Payload); err != nil {
					// TODO: Add logging
					//fmt.Fprintf(os.Stderr, "Could not decode DNS: %v\n", err)
					continue PACKETLOOP
				}
			}
		}

		// Ignore questions unless flag set
		if !msg.Response && !DoParseQuestions {
			continue PACKETLOOP
		}

		// Fill out information from DNS headers
		schema.Timestamp = packet.Metadata().Timestamp.Unix()
		schema.Id = msg.Id
		schema.Truncated = msg.Truncated
		schema.Response = msg.Response
		schema.RecursionDesired = msg.RecursionDesired
		schema.Nxdomain = msg.Rcode == 3

		// Parse ECS information
		schema.EcsClient = nil
		schema.EcsSource = nil
		schema.EcsScope = nil
		if opt := msg.IsEdns0(); (opt != nil) && !NoParseEcs {
			for _, s := range opt.Option {
				switch o := s.(type) {
				case *dns.EDNS0_SUBNET:
					ecsClient := o.Address.String()
					ecsSource := o.SourceNetmask
					ecsScope := o.SourceScope
					schema.EcsClient = &ecsClient
					schema.EcsSource = &ecsSource
					schema.EcsScope = &ecsScope
				}
			}
		}

		// Let's get QUESTION
		// TODO: Throw error if there's more than one question
		for _, qr := range msg.Question {
			schema.Qname = qr.Name
			schema.Qtype = qr.Qtype
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
