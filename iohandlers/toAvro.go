package iohandlers

import (
	"os"

	"github.com/hamba/avro/ocf"
	log "github.com/sirupsen/logrus"
)

func init() {
	Initializers["avro"] = toAvroInitializer
	Marshalers["avro"] = toAvro
	Closers["avro"] = toAvroCloser
}

var (
	avroEncoder *ocf.Encoder
	avroData    avroDnsSchema
	avroSchema  string
	ttl         int
	rtype       int
	ecsSource   int
	ecsScope    int
)

// Avro doesn't support unsigned integers so we create a new type for serialization.
type avroDnsSchema struct {
	Timestamp          int64   `avro:"timestamp"`
	Sha256             string  `avro:"sha256"`
	Udp                bool    `avro:"udp"`
	Ipv4               bool    `avro:"ipv4"`
	SourceAddress      string  `avro:"src_address"`
	SourcePort         int     `avro:"src_port"`
	DestinationAddress string  `avro:"dst_address"`
	DestinationPort    int     `avro:"dst_port"`
	Id                 int     `avro:"id"`
	Rcode              int     `avro:"rcode"`
	Truncated          bool    `avro:"truncated"`
	Response           bool    `avro:"response"`
	RecursionDesired   bool    `avro:"recursion_desired"`
	Answer             bool    `avro:"answer"`
	Authority          bool    `avro:"authority"`
	Additional         bool    `avro:"additional"`
	Qname              string  `avro:"qname"`
	Qtype              int     `avro:"qtype"`
	Ttl                *int    `avro:"ttl"`
	Rname              *string `avro:"rname"`
	Rtype              *int    `avro:"rtype"`
	Rdata              *string `avro:"rdata"`
	EcsClient          *string `avro:"ecs_client"`
	EcsSource          *int    `avro:"ecs_source"`
	EcsScope           *int    `avro:"ecs_scope"`
	Source             *string `avro:"source"`
	Sensor             *string `avro:"sensor"`
}

func toAvroInitializer() {
	avroSchema = `{
	"type": "record",
	"name": "DnsSchema",
	"namespace": "org.hamba.avro",
		"fields": [
			{
			  "name": "timestamp",
			  "type": "long"
			},
			{
			  "name": "sha256",
			  "type": "string"
			},
			{
			  "name": "udp",
			  "type": "boolean"
			},
			{
			  "name": "ipv4",
			  "type": "boolean"
			},
			{
			  "name": "src_address",
			  "type": "string"
			},
			{
			  "name": "src_port",
			  "type": "int"
			},
			{
			  "name": "dst_address",
			  "type": "string"
			},
			{
			  "name": "dst_port",
			  "type": "int"
			},
			{
			  "name": "id",
			  "type": "int"
			},
			{
			  "name": "rcode",
			  "type": "int"
			},
			{
			  "name": "truncated",
			  "type": "boolean"
			},
			{
			  "name": "response",
			  "type": "boolean"
			},
			{
			  "name": "recursion_desired",
			  "type": "boolean"
			},
			{
			  "name": "answer",
			  "type": "boolean"
			},
			{
			  "name": "authority",
			  "type": "boolean"
			},
			{
			  "name": "additional",
			  "type": "boolean"
			},
			{
			  "name": "qname",
			  "type": "string"
			},
			{
			  "name": "qtype",
			  "type": "int"
			},
			{
			  "name": "ttl",
			  "type": ["null", "int"],
			  "default": null
			},
			{
			  "name": "rname",
			  "type": ["null", "string"],
			  "default": null
			},
			{
			  "name": "rtype",
			  "type": ["null", "int"],
			  "default": null
			},
			{
			  "name": "rdata",
			  "type": ["null", "string"],
			  "default": null
			},
			{
			  "name": "ecs_client",
			  "type": ["null", "string"],
			  "default": null
			},
			{
			  "name": "ecs_source",
			  "type": ["null", "int"],
			  "default": null
			},
			{
			  "name": "ecs_scope",
			  "type": ["null", "int"],
			  "default": null
			},
			{
			  "name": "source",
			  "type": ["null", "string"],
			  "default": null
			},
			{
			  "name": "sensor",
			  "type": ["null", "string"],
			  "default": null
			}
		]
	}`

	var err error
	avroEncoder, err = ocf.NewEncoder(avroSchema, os.Stdout, ocf.WithCodec(ocf.Snappy))
	if err != nil {
		log.Fatalf("Error creating Avro Encoder: %v", err)
	}
}

func toAvro(d *DnsSchema) {
	avroData.Timestamp = d.Timestamp
	avroData.Sha256 = d.Sha256
	avroData.Udp = d.Udp
	avroData.Ipv4 = d.Ipv4
	avroData.SourceAddress = d.SourceAddress
	avroData.SourcePort = int(d.SourcePort)
	avroData.DestinationAddress = d.DestinationAddress
	avroData.DestinationPort = int(d.DestinationPort)
	avroData.Id = int(d.Id)
	avroData.Rcode = d.Rcode
	avroData.Truncated = d.Truncated
	avroData.Response = d.Response
	avroData.RecursionDesired = d.RecursionDesired
	avroData.Answer = d.Answer
	avroData.Authority = d.Authority
	avroData.Additional = d.Additional
	avroData.Qname = d.Qname
	avroData.Qtype = int(d.Qtype)
	avroData.Ttl = nil
	avroData.Rname = d.Rname
	avroData.Rdata = d.Rdata
	avroData.Rtype = nil
	avroData.EcsClient = d.EcsClient
	avroData.EcsSource = nil
	avroData.EcsScope = nil
	avroData.Source = nil
	avroData.Sensor = nil

	// Handle source and sensor
	if len(d.Source) > 0 {
		avroData.Source = &d.Source
	}
	if len(d.Sensor) > 0 {
		avroData.Sensor = &d.Sensor
	}

	// Handle pointers requiring type conversion
	if d.Ttl != nil {
		ttl = int(*d.Ttl)
		avroData.Ttl = &ttl
	}
	if d.Rtype != nil {
		rtype = int(*d.Rtype)
		avroData.Rtype = &rtype
	}
	if d.EcsSource != nil {
		ecsSource = int(*d.EcsSource)
		avroData.EcsSource = &ecsSource
	}
	if d.EcsScope != nil {
		ecsScope = int(*d.EcsScope)
		avroData.EcsScope = &ecsScope
	}

	err := avroEncoder.Encode(&avroData)
	if err != nil {
		log.Warnf("Error encoding Avro: %v", err)
	}
}

func toAvroCloser() {
	avroEncoder.Flush()
	avroEncoder.Close()
}
