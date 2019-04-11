package parser

import (
	"crypto/sha256"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
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
	Source           = ""
	Sensor           = ""
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
		ldns   layers.DNS
	)

	// Keep track of parsing statistics
	stats := Statistics{}

	// Set the source and sensor for packet source
	schema.Sensor = Sensor
	schema.Source = Source

	// Let's reuse the same layers for performance improvement
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &dot1q, &ip4, &ip6, &tcp, &udp, &ldns)
	decoded := []gopacket.LayerType{}

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.NoCopy = true

PACKETLOOP:
	for packet := range packetSource.Packets() {
		stats.PacketTotal += 1

		if err := parser.DecodeLayers(packet.Data(), &decoded); err != nil {
			log.Debugf("Could not decode layers: %v\n", err)
		}

		// Let's decode different layers
		msg := new(dns.Msg)
		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeIPv4:
				stats.PacketIPv4 += 1
				schema.SourceAddress = ip4.SrcIP.String()
				schema.DestinationAddress = ip4.DstIP.String()
				schema.Ipv4 = true
			case layers.LayerTypeIPv6:
				stats.PacketIPv6 += 1
				schema.SourceAddress = ip6.SrcIP.String()
				schema.DestinationAddress = ip6.DstIP.String()
				schema.Ipv4 = false
			case layers.LayerTypeTCP:
				stats.PacketTcp += 1
				schema.SourcePort = uint16(tcp.SrcPort)
				schema.DestinationPort = uint16(tcp.DstPort)
				schema.Udp = false
				schema.Sha256 = fmt.Sprintf("%x", sha256.Sum256(tcp.Payload))
				if err := msg.Unpack(tcp.Payload); err != nil {
					log.Errorf("Could not decode DNS: %v\n", err)
					stats.PacketErrors += 1
					continue PACKETLOOP
				}
			case layers.LayerTypeUDP:
				stats.PacketUdp += 1
				schema.SourcePort = uint16(udp.SrcPort)
				schema.DestinationPort = uint16(udp.DstPort)
				schema.Udp = true
				schema.Sha256 = fmt.Sprintf("%x", sha256.Sum256(udp.Payload))
				if err := msg.Unpack(udp.Payload); err != nil {
					log.Errorf("Could not decode DNS: %v\n", err)
					stats.PacketErrors += 1
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
		schema.Rcode = msg.Rcode
		schema.Truncated = msg.Truncated
		schema.Response = msg.Response
		schema.RecursionDesired = msg.RecursionDesired

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

		// Reset RR information
		schema.Ttl = nil
		schema.Rname = nil
		schema.Rdata = nil
		schema.Rtype = nil

		// Let's get QUESTION
		// TODO: Throw error if there's more than one question
		for _, qr := range msg.Question {
			schema.Qname = qr.Name
			schema.Qtype = qr.Qtype
		}

		// Print questions if configured
		// If we've received an NXDOMAIN without SOA make sure we print
		if (DoParseQuestions && !schema.Response) || (schema.Rcode == 3 && len(msg.Ns) < 1) {
			schema.ToJson(nil, -1)
		}

		// Let's get ANSWERS
		for _, rr := range msg.Answer {
			schema.ToJson(&rr, DnsAnswer)
		}

		// Let's get AUTHORITATIVE information
		for _, rr := range msg.Ns {
			schema.ToJson(&rr, DnsAuthority)
		}

		// Let's get ADDITIONAL information
		for _, rr := range msg.Extra {
			schema.ToJson(&rr, DnsAdditional)
		}

		// Let's check and see if we had any errors decoding any of the packets
		if err := packet.ErrorLayer(); err != nil {
			log.Debugf("Error decoding some part of the packet:", err)
		}
	}

	log.Infof("Number of TOTAL packets: %v", stats.PacketTotal)
	log.Infof("Number of IPv4 packets: %v", stats.PacketIPv4)
	log.Infof("Number of IPv6 packets: %v", stats.PacketIPv6)
	log.Infof("Number of UDP packets: %v", stats.PacketUdp)
	log.Infof("Number of TCP packets: %v", stats.PacketTcp)
	log.Infof("Number of FAILED packets: %v", stats.PacketErrors)
}
