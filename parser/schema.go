package parser

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"rickybobby/producer"
	"strings"
	"os"
	"github.com/Shopify/sarama"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

var (
	Format     = "json"
	OutputType = ""
	OutputFile = ""
	OutputStream *os.File
)

// JSON serialization only supports nullifying types that can accept nil.
// The ECS fields are pointers because they're nullable.
type DnsSchema struct {
	Timestamp          int64   `json:"timestamp"`
	Sha256             string  `json:"sha256"`
	Udp                bool    `json:"udp"`
	Ipv4               bool    `json:"ipv4"`
	SourceAddress      string  `json:"src_address"`
	SourcePort         uint16  `json:"src_port"`
	DestinationAddress string  `json:"dst_address"`
	DestinationPort    uint16  `json:"dst_port"`
	Id                 uint16  `json:"id"`
	Rcode              int     `json:"rcode"`
	Truncated          bool    `json:"truncated"`
	Response           bool    `json:"response"`
	RecursionDesired   bool    `json:"recursion_desired"`
	Answer             bool    `json:"answer"`
	Authority          bool    `json:"authority"`
	Additional         bool    `json:"additional"`
	Qname              string  `json:"qname"`
	Qtype              uint16  `json:"qtype"`
	Ttl                *uint32 `json:"ttl"`
	Rname              *string `json:"rname"`
	Rtype              *uint16 `json:"rtype"`
	Rdata              *string `json:"rdata"`
	EcsClient          *string `json:"ecs_client"`
	EcsSource          *uint8  `json:"ecs_source"`
	EcsScope           *uint8  `json:"ecs_scope"`
	Source             string  `json:"source,omitempty"`
	Sensor             string  `json:"sensor,omitempty"`
}

func (d DnsSchema) FormatOutput(rr *dns.RR, section int) {
	if rr != nil {
		// This works because RR.Header().String() prefixes the RDATA
		// in the RR.String() representation.
		// Reference: https://github.com/miekg/dns/blob/master/types.go
		rdata := strings.TrimPrefix((*rr).String(), (*rr).Header().String())

		// Fill in the rest of the parameters
		// This will not alter the underlying DNS schema
		d.Ttl = &(*rr).Header().Ttl
		d.Rname = &(*rr).Header().Name
		d.Rtype = &(*rr).Header().Rrtype
		d.Rdata = &rdata
		d.Answer = section == DnsAnswer
		d.Authority = section == DnsAuthority
		d.Additional = section == DnsAdditional

		// Ignore OPT records
		if *d.Rtype == 41 {
			return
		}
	}
	FormatOutputExport(&d)

}

func FormatOutputExport(schema *DnsSchema) {
	var schemaIdentifier uint32 = 3
	var schemaIdentifierBuffer []byte = make([]byte, 4)
	binary.BigEndian.PutUint32(schemaIdentifierBuffer, schemaIdentifier)

	if Format == "avro" {
		codec, err := producer.NewAvroCodec()

		binary, err := codec.BinaryFromNative(nil, DNSToAvroMap(schema))
		schemaVersion := producer.SchemaVersion
		var confluentAvroHeader []byte = make([]byte, schemaVersion)
		confluentMessage := append(confluentAvroHeader, binary...)
		if err != nil {
			log.Fatalf("Failed to convert Go map to Avro binary data: %v", err)
		}
		if err != nil {
			log.Warnf("Error while initializing avro codec: %v", err)
		}
		if OutputType == "kafka" {
			producer.Producer.Input() <- &sarama.ProducerMessage{
				Topic: producer.Topic,
				Key:   sarama.StringEncoder(producer.MessageKey),
				Value: sarama.ByteEncoder(confluentMessage),
			}
		} else if OutputType == "stdout" {
			fmt.Printf("%s\n", confluentMessage)
		} else if OutputType == "file" {
			_, err := OutputStream.Write(binary)
			if err != nil {
				log.Fatalf("Failed to output JSON to a file: %v", err)
			}
		}
	} else if Format == "json" {
		jsonData, err := json.Marshal(&schema)
		if err != nil {
			log.Warnf("Error converting to JSON: %v", err)
		}
		if OutputType == "stdout" {
			fmt.Printf("%s\n", jsonData)
		} else if OutputType == "kafka" {
			codec, err := producer.NewAvroCodec()
			if err != nil {
				log.Fatalf("Failed to convert Go map to Avro JSON data: %v", err)
			}
			avroJSON, err := codec.TextualFromNative(nil, DNSToAvroMap(schema))
			producer.Producer.Input() <- &sarama.ProducerMessage{
				Topic: producer.Topic,
				Key:   sarama.StringEncoder(producer.MessageKey),
				Value: sarama.ByteEncoder(avroJSON),
			}
		} else if OutputType == "file" {
			_, err := OutputStream.Write(jsonData)
			if err != nil {
				log.Fatalf("Failed to output JSON to a file: %v", err)
			}
		}
	}
}

func DNSToAvroMap(schema *DnsSchema) map[string]interface{} {
	avroMap := map[string]interface{}{
		"timestamp":         schema.Timestamp,
		"ip_src":            schema.Source,
		"ip_dst":            schema.DestinationAddress,
		"dst_port":          int32(schema.DestinationPort),
		"txid":              int32(schema.Id), // ??
		"rcode":             schema.Rcode,
		"qtype":             int32(schema.Qtype),
		"qname":             schema.Qname,
		"recursion_desired": schema.RecursionDesired,
		"response":          schema.Response,
		"answer":            map[string]interface{}{"boolean": schema.Answer},
		"authority":         map[string]interface{}{"boolean": schema.Authority},
		"additional":        map[string]interface{}{"boolean": schema.Additional},
		"source":            schema.Source,
	}
	if schema.Rname != nil {
		avroMap["rname"] = map[string]interface{}{"string": *schema.Rname}
	}
	if schema.Rtype != nil {
		avroMap["rtype"] = map[string]interface{}{"int": int32(*schema.Rtype)}
	}
	if schema.Rdata != nil {
		avroMap["rdata"] = map[string]interface{}{"string": *schema.Rdata}
	}
	if schema.Ttl != nil {
		avroMap["ttl"] = map[string]interface{}{"long": int64(*schema.Ttl)}
	}
	if schema.EcsClient != nil {
		avroMap["ecs_client"] = map[string]interface{}{"string": *schema.EcsClient}
	}
	if schema.EcsSource != nil {
		avroMap["ecs_source"] = map[string]interface{}{"string": string(*schema.EcsSource)}
	}
	if schema.EcsScope != nil {
		avroMap["ecs_scope"] = map[string]interface{}{"string": string(*schema.EcsScope)}
	}
	if schema.Source != "" {
		avroMap["sensor"] = map[string]interface{}{"string": schema.Sensor}
	}

	if schema.Ipv4 {
		avroMap["ip_version"] = 4
	} else {
		avroMap["ip_version"] = 6
	}
	return avroMap
}
