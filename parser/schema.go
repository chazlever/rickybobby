package parser

import (
	"encoding/json"
	"fmt"
	"github.com/miekg/dns"
	"strings"
)

type DnsSchema struct {
	Timestamp          int    `json:"timestamp"`
	Id                 uint16 `json:"id"`
	SourceAddress      string `json:"src_address"`
	SourcePort         uint16 `json:"src_port"`
	DestinationAddress string `json:"dst_address"`
	DestinationPort    uint16 `json:"dst_port"`
	Ttl                uint32 `json:"ttl"`
	RecursionDesired   bool   `json:"recursion_desired"`
	Nxdomain           bool   `json:"nxdomain"`
	Answer             bool   `json:"answer"`
	Authority          bool   `json:"authority"`
	Additional         bool   `json:"additional"`
	Qname              string `json:"qname"`
	Qtype              uint16 `json:"qtype"`
	Rdata              string `json:"rdata"`
	EcsClient          string `json:"ecs_client"`
	EcsSource          uint8  `json:"ecs_source"`
	EcsScope           uint8  `json:"ecs_scope"`
}

func (d DnsSchema) ToJson(rr dns.RR, section int) {
	// NOTE: This won't always work if the RDATA has tabs in it.
	answer := strings.Split(rr.String(), "\t")
	rdata := answer[len(answer)-1]

	// Fill in the rest of the parameters
	// This will not alter the underlying DNS schema
	d.Ttl = rr.Header().Ttl
	d.Qname = rr.Header().Name
	d.Qtype = rr.Header().Rrtype
	d.Rdata = rdata
	d.Answer = section == DnsAnswer
	d.Authority = section == DnsAuthority
	d.Additional = section == DnsAdditional

	// Let's print to Json
	// Don't print OPT records
	if d.Qtype != 41 {
		jsonData, err := json.Marshal(d)
		if err != nil {
			fmt.Println(err)
		}

		fmt.Println(string(jsonData))
	}
}
