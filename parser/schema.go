package parser

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hamba/avro"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

var (
	AvroCodec  avro.Schema
	AvroWriter avro.Writer
)

// JSON serialization only supports nullifying types that can accept nil.
// The ECS fields are pointers because they're nullable.
type DnsSchema struct {
	Timestamp          int64   `json:"timestamp" avro:"timestamp"`
	Sha256             string  `json:"sha256" avro:"-"`
	Udp                bool    `json:"udp" avro:"udp"`
	Ipv4               bool    `json:"ipv4" avro:"-"`
	SourceAddress      string  `json:"src_address" avro:"ip_src"`
	SourcePort         int     `json:"src_port" avro:"-"`
	DestinationAddress string  `json:"dst_address" avro:"ip_dst"`
	DestinationPort    int     `json:"dst_port" avro:"dst_port"`
	Id                 int     `json:"id" avro:"txid"`
	Rcode              int     `json:"rcode" avro:"rcode"`
	Truncated          bool    `json:"truncated" avro:"truncated"`
	Response           bool    `json:"response" avro:"response"`
	RecursionDesired   bool    `json:"recursion_desired" avro:"recursion_desired"`
	Answer             bool    `json:"answer avro:"-""`
	Authority          bool    `json:"authority" avro:"-"`
	Additional         bool    `json:"additional avro:"-""`
	Qname              string  `json:"qname" avro:"qname"`
	Qtype              int     `json:"qtype" avro:"qtype"`
	Ttl                *uint32 `json:"ttl" avro:"-"`
	Rname              *string `json:"rname" avro:"-"`
	Rtype              *uint16 `json:"rtype" avro:"-"`
	Rdata              *string `json:"rdata" avro:"-"`
	EcsClient          *string `json:"ecs_client" avro:"-"`
	EcsSource          *uint8  `json:"ecs_source" avro:"-"`
	EcsScope           *uint8  `json:"ecs_scope" avro:"-"`
	Source             string  `json:"source,omitempty" avro:"source"`
	Sensor             string  `json:"sensor,omitempty" avro:"-"`

	IPVersionAvro  int                    `avro:"ip_version" json:"-"`
	AnswerAvro     map[string]interface{} `avro:"answer" json:"-"`
	AuthorityAvro  map[string]interface{} `avro:"authority" json:"-"`
	AdditionalAvro map[string]interface{} `avro:"additional" json:"-"`
	TTLAvro        longUnion              `avro:"ttl,omitempty" json:"-"`
	RnameAvro      stringUnion            `avro:"rname,omitempty" json:"-"`
	RtypeAvro      intUnion               `avro:"rtype,omitempty" json:"-"`
	RdataAvro      stringUnion            `avro:"rdata,omitempty" json:"-"`
	EcsClientAvro  stringUnion            `avro:"ecs_client,omitempty" json:"-"`
	EcsSourceAvro  stringUnion            `avro:"ecs_source,omitempty" json:"-"`
	EcsScopeAvro   stringUnion            `avro:"ecs_scope,omitempty" json:"-"`
	SensorAvro     stringUnion            `avro:"sensor,omitempty" json:"-"`
}

func (d DnsSchema) Serialize(rr *dns.RR, section int) {
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
	if AvroCodec != nil {
		d.ToAvro()
	} else {
		d.ToJson()
	}
}

func (d DnsSchema) ToJson() {
	jsonData, err := json.Marshal(&d)
	if err != nil {
		log.Warnf("Error converting to JSON: %v", err)
	}
	fmt.Printf("%s\n", jsonData)
}

func (d DnsSchema) ToAvro() {
	d.AnswerAvro = map[string]interface{}{"boolean": d.Answer}
	d.AuthorityAvro = map[string]interface{}{"boolean": d.Authority}
	d.AdditionalAvro = map[string]interface{}{"boolean": d.Additional}

	if d.Rname != nil {
		d.RnameAvro = stringUnion{String: *d.Rname}
	}
	if d.Rtype != nil {
		d.RtypeAvro = intUnion{Int: int(*d.Rtype)}
	}
	if d.Rdata != nil {
		d.RdataAvro = stringUnion{String: *d.Rdata}
	}
	if d.Ttl != nil {
		d.TTLAvro = longUnion{Long: int(*d.Ttl)}
	}
	if d.EcsClient != nil {
		d.EcsClientAvro = stringUnion{String: *d.EcsClient}
	}
	if d.EcsSource != nil {
		d.EcsSourceAvro = stringUnion{String: string(*d.EcsSource)}
	}
	if d.EcsScope != nil {
		d.EcsScopeAvro = stringUnion{String: string(*d.EcsScope)}
	}
	if d.Source != "" {
		d.SensorAvro = stringUnion{String: d.Sensor}
	}

	if d.Ipv4 {
		d.IPVersionAvro = 4
	} else {
		d.IPVersionAvro = 6
	}
	bytes, err := avro.Marshal(AvroCodec, d)

	if err != nil {
		log.Fatal(err)
	}
	AvroWriter.Write(bytes)
	AvroWriter.Flush()
}

func NewAvroCodec() (avro.Schema, error) {
	schema := `{
		"type": "record",
		"name": "dns_record",
		"fields" : [ {
			"name" : "timestamp",
			"type" : "long"
		  }, {
			"name" : "ip_version",
			"type" : "int"
		  }, {
			"name" : "ip_src",
			"type" : "string"
		  }, {
			"name" : "ip_dst",
			"type" : "string"
		  }, {
			"name" : "dst_port",
			"type" : "int"
		  }, {
			"name" : "txid",
			"type" : "int"
		  }, {
			"name" : "rcode",
			"type" : "int"
		  }, {
			"name" : "qtype",
			"type" : "int"
		  }, {
			"name" : "qname",
			"type" : "string"
		  }, {
			"name" : "recursion_desired",
			"type" : "boolean"
		  }, {
			"name" : "response",
			"type" : "boolean"
		  }, {
			"name" : "answer",
			"type" : [ "null", "boolean" ],
			"default": null
		  }, {
			"name" : "authority",
			"type" : [ "null", "boolean" ],
			"default": null
		  }, {
			"name" : "additional",
			"type" : [ "null", "boolean" ],
			"default": null
		  }, {
			"name" : "rname",
			"type" : [ "null", "string" ],
			"default": null
		  }, {
			"name" : "rtype",
			"type" : [ "null", "int" ],
			"default": null
		  }, {
			"name" : "rdata",
			"type" : [ "null", "string" ],
			"default": null
		  }, {
			"name" : "ttl",
			"type" : [ "null", "long" ],
			"default": null
		  }, {
			"name" : "ecs_client",
			"type" : [ "null", "string" ],
			"default": null
		  }, {
			"name" : "ecs_source",
			"type" : [ "null", "string" ],
			"default": null
		  }, {
			"name" : "ecs_scope",
			"type" : [ "null", "string" ],
			"default": null
		  }, {
			"name" : "source",
			"type" : "string"
		  }, {
			"name" : "sensor",
			"type" : [ "null", "string" ],
			"default": null
		  } ]
		}`
	return avro.Parse(schema)
}

type stringUnion struct {
	String string `avro:"string"`
}
type intUnion struct {
	Int int `avro:"int"`
}
type longUnion struct {
	Long int `avro:"long"`
}
