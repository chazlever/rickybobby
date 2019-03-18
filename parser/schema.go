package parser

import (
	"encoding/json"
	"fmt"
	"github.com/miekg/dns"
	"strings"
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
}

func (d DnsSchema) ToJson(rr *dns.RR, section int) {
	if rr != nil {
		// TODO: Fix how RDATA is handled
		// This won't always work if the RDATA has tabs in it.
		answer := strings.Split((*rr).String(), "\t")
		rdata := answer[len(answer)-1]
		ttl := (*rr).Header().Ttl
		rname := (*rr).Header().Name
		rtype := (*rr).Header().Rrtype

		// Fill in the rest of the parameters
		// This will not alter the underlying DNS schema
		d.Ttl = &ttl
		d.Rname = &rname
		d.Rtype = &rtype
		d.Rdata = &rdata
		d.Answer = section == DnsAnswer
		d.Authority = section == DnsAuthority
		d.Additional = section == DnsAdditional

		// Ignore OPT records
		if *d.Rtype == 41 {
			return
		}
	}

	jsonData, err := json.Marshal(d)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(jsonData))
}
