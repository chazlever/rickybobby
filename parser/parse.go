package parser

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/chazlever/rickybobby/iohandlers"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

var (
	DoParseTcp          = true
	DoParseQuestions    = false
	DoParseQuestionsEcs = true
	Source              = ""
	Sensor              = ""
	OutputFormat        = ""
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

	// Setup BPF filter on handle
	bpfFilter := "udp port 53 or (vlan and udp port 53)"
	if DoParseTcp {
		bpfFilter = "port 53 or (vlan and port 53)"
	}
	err = handle.SetBPFFilter(bpfFilter)
	if err != nil {
		log.Warnf("Could not set BPF filter: %v\n", err)
	}

	ParseDns(handle)
}

func ParseDevice(device string, snapshotLen int32, promiscuous bool, timeout time.Duration) {
	handle, err := pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Setup BPF filter on handle
	bpfFilter := "udp port 53 or (vlan and udp port 53)"
	if DoParseTcp {
		bpfFilter = "port 53 or (vlan and port 53)"
	}
	err = handle.SetBPFFilter(bpfFilter)
	if err != nil {
		log.Warnf("Could not set BPF filter: %v\n", err)
	}

	ParseDns(handle)
}

func ParseDns(handle *pcap.Handle) {
	var (
		schema iohandlers.DnsSchema
		stats  Statistics
		ip4    *layers.IPv4
		ip6    *layers.IPv6
		tcp    *layers.TCP
		udp    *layers.UDP
		msg    *dns.Msg
	)

	// Set the source and sensor for packet source
	schema.Sensor = Sensor
	schema.Source = Source

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.NoCopy = true
	packetSource.Lazy = true

	// Initialize IO handler for output format
	iohandlers.Initialize(OutputFormat)

PACKETLOOP:
	for {
		packet, err := packetSource.NextPacket()
		if err == io.EOF {
			break
		}
		stats.PacketTotal += 1

		if err != nil {
			log.Errorf("Error decoding some part of the packet: %v\n", err)
			stats.PacketErrors += 1
			continue
		}

		// Parse network layer information
		networkLayer := packet.NetworkLayer()
		if networkLayer == nil {
			log.Error("Unknown/missing network layer for packet")
			stats.PacketErrors += 1
			continue
		}
		switch networkLayer.LayerType() {
		case layers.LayerTypeIPv4:
			ip4 = networkLayer.(*layers.IPv4)
			schema.SourceAddress = ip4.SrcIP.String()
			schema.DestinationAddress = ip4.DstIP.String()
			schema.Ipv4 = true
			stats.PacketIPv4 += 1
		case layers.LayerTypeIPv6:
			ip6 = networkLayer.(*layers.IPv6)
			schema.SourceAddress = ip6.SrcIP.String()
			schema.DestinationAddress = ip6.DstIP.String()
			schema.Ipv4 = false
			stats.PacketIPv6 += 1
		}

		// Parse DNS and transport layer information
		msg = nil
		transportLayer := packet.TransportLayer()
		if transportLayer == nil {
			log.Error("Unknown/missing transport layer for packet")
			stats.PacketErrors += 1
			continue
		}
		switch transportLayer.LayerType() {
		case layers.LayerTypeTCP:
			tcp = transportLayer.(*layers.TCP)
			stats.PacketTcp += 1

			if !DoParseTcp {
				continue PACKETLOOP
			}

			msg = new(dns.Msg)
			if err := msg.Unpack(tcp.Payload); err != nil {
				log.Errorf("Could not decode DNS: %v\n", err)
				stats.PacketErrors += 1
				continue PACKETLOOP
			}
			stats.PacketDns += 1

			schema.SourcePort = uint16(tcp.SrcPort)
			schema.DestinationPort = uint16(tcp.DstPort)
			schema.Udp = false
			schema.Sha256 = fmt.Sprintf("%x", sha256.Sum256(tcp.Payload))
		case layers.LayerTypeUDP:
			udp = transportLayer.(*layers.UDP)
			stats.PacketUdp += 1

			msg = new(dns.Msg)
			if err := msg.Unpack(udp.Payload); err != nil {
				log.Errorf("Could not decode DNS: %v\n", err)
				stats.PacketErrors += 1
				continue PACKETLOOP
			}
			stats.PacketDns += 1

			schema.SourcePort = uint16(udp.SrcPort)
			schema.DestinationPort = uint16(udp.DstPort)
			schema.Udp = true

			// Hash and salt packet for grouping related records
			tsSalt, err := packet.Metadata().Timestamp.MarshalBinary()
			if err != nil {
				log.Errorf("Could not marshal timestamp: #{err}\n")
			}
			schema.Sha256 = fmt.Sprintf("%x", sha256.Sum256(append(tsSalt, packet.Data()...)))
		}

		// This means we did not attempt to parse a DNS payload and
		// indicates an unexpected transport layer protocol
		if msg == nil {
			log.Debug("Unexpected transport layer protocol")
			continue PACKETLOOP
		}

		// Ignore questions unless flag set
		if !msg.Response && !DoParseQuestions && !DoParseQuestionsEcs {
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
		if opt := msg.IsEdns0(); opt != nil {
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

		// Get a count of RRs in DNS response
		rrCount := 0
		for _, rr := range append(append(msg.Answer, msg.Ns...), msg.Extra...) {
			if rr.Header().Rrtype != 41 {
				rrCount++
			}
		}

		// Let's output records without RRs records if:
		//   1. Questions flag is set and record is question
		//   2. QuestionsEcs flag is set and question record contains ECS information
		//   4. Any response without any RRs (e.g., NXDOMAIN without SOA, REFUSED, etc.)
		if (DoParseQuestions && !schema.Response) ||
			(DoParseQuestionsEcs && schema.EcsClient != nil && !schema.Response) ||
			(schema.Response && rrCount < 1) {
			schema.Marshal(nil, -1, OutputFormat)
		}

		// Let's get ANSWERS
		for _, rr := range msg.Answer {
			schema.Marshal(&rr, iohandlers.DnsAnswer, OutputFormat)
		}

		// Let's get AUTHORITATIVE information
		for _, rr := range msg.Ns {
			schema.Marshal(&rr, iohandlers.DnsAuthority, OutputFormat)
		}

		// Let's get ADDITIONAL information
		for _, rr := range msg.Extra {
			schema.Marshal(&rr, iohandlers.DnsAdditional, OutputFormat)
		}
	}

	// Cleanup IO handler for output format
	iohandlers.Close(OutputFormat)

	log.Infof("Number of TOTAL packets: %v", stats.PacketTotal)
	log.Infof("Number of IPv4 packets: %v", stats.PacketIPv4)
	log.Infof("Number of IPv6 packets: %v", stats.PacketIPv6)
	log.Infof("Number of UDP packets: %v", stats.PacketUdp)
	log.Infof("Number of TCP packets: %v", stats.PacketTcp)
	log.Infof("Number of DNS packets: %v", stats.PacketDns)
	log.Infof("Number of FAILED packets: %v", stats.PacketErrors)
}
