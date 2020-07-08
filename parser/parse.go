package parser

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

const (
	DnsAnswer     = iota
	DnsAuthority  = iota
	DnsAdditional = iota
)

var (
	DoParseTcp          = true
	DoParseQuestions    = false
	DoParseQuestionsEcs = true
	Source              = ""
	Sensor              = ""
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

	// Setup BPF filter on handle
	bpfFilter := "udp port 53"
	if DoParseTcp {
		bpfFilter = "port 53"
	}
	err = handle.SetBPFFilter(bpfFilter)
	if err != nil {
		log.Warnf("Could not set BPF filter: %v\n", err)
	}

	ParseDns(handle)
}

func ParseDns(handle *pcap.Handle) {
	var (
		schema   DnsSchema
		stats    Statistics
		ip4      layers.IPv4
		ip6      layers.IPv6
		tcp      layers.TCP
		udp      layers.UDP
		ethernet layers.Ethernet
		dot1q    layers.Dot1Q
	)

	// Set the source and sensor for packet source
	schema.Sensor = Sensor
	schema.Source = Source

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.NoCopy = true

PACKETLOOP:
	for {
		stats.PacketTotal += 1

		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethernet, &ip4, &ip6, &tcp, &udp, &dot1q)
		parser.IgnoreUnsupported = true
		decodedLayers := make([]gopacket.LayerType, 0, 10)
		bytes, info, err := handle.ZeroCopyReadPacketData()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Errorf("Error reading packet data %v\n", err)
			stats.PacketErrors += 1
			continue PACKETLOOP
		}
		err = parser.DecodeLayers(bytes, &decodedLayers)
		if err != nil {
			log.Errorf("Error decoding packet data %v\n", err)
			stats.PacketErrors += 1
			continue PACKETLOOP
		}

		// Let's analyze decoded layers
		var msg *dns.Msg
		for _, curLayer := range decodedLayers {
			switch curLayer {
			case layers.LayerTypeIPv4:
				schema.SourceAddress = ip4.SrcIP.String()
				schema.DestinationAddress = ip4.DstIP.String()
				schema.Ipv4 = true
				stats.PacketIPv4 += 1
			case layers.LayerTypeIPv6:
				schema.SourceAddress = ip6.SrcIP.String()
				schema.DestinationAddress = ip6.DstIP.String()
				schema.Ipv4 = false
				stats.PacketIPv6 += 1
			case layers.LayerTypeTCP:
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
				schema.Sha256 = fmt.Sprintf("%x", sha256.Sum256(udp.Payload))
			}
		}

		// This means we did not attempt to parse a DNS payload
		if msg == nil {
			log.Debugf("Error decoding some part of the packet")
			stats.PacketErrors += 1
			continue PACKETLOOP
		}

		// Ignore questions unless flag set
		if !msg.Response && !DoParseQuestions && !DoParseQuestionsEcs {
			continue PACKETLOOP
		}

		// Fill out information from DNS headers
		schema.Timestamp = info.Timestamp.Unix()
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

		// Let's get QUESTION information on if:
		//   1. Questions flag is set
		//   2. QuestionsEcs flag is set and ECS information in question
		//   3. NXDOMAINs without RRs (i.e., SOA)
		if (DoParseQuestions && !schema.Response) ||
			(DoParseQuestionsEcs && schema.EcsClient != nil && !schema.Response) ||
			(schema.Rcode == 3 && len(msg.Ns) < 1) {
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
	}

	log.Infof("Number of TOTAL packets: %v", stats.PacketTotal)
	log.Infof("Number of IPv4 packets: %v", stats.PacketIPv4)
	log.Infof("Number of IPv6 packets: %v", stats.PacketIPv6)
	log.Infof("Number of UDP packets: %v", stats.PacketUdp)
	log.Infof("Number of TCP packets: %v", stats.PacketTcp)
	log.Infof("Number of DNS packets: %v", stats.PacketDns)
	log.Infof("Number of FAILED packets: %v", stats.PacketErrors)
}
