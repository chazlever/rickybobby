package parser

import (
	"encoding/json"
	"fmt"
	"github.com/miekg/dns"
	"strings"
)

type DnsSchema struct {
	Timestamp          int64  `json:"timestamp"`
	Id                 uint16 `json:"id"`
	SourceAddress      string `json:"src_address"`
	SourcePort         uint16 `json:"src_port"`
	DestinationAddress string `json:"dst_address"`
	DestinationPort    uint16 `json:"dst_port"`
	Ttl                uint32 `json:"ttl"`
	Udp                bool   `json:"udp"`
	Truncated          bool   `json:"truncated"`
	Response           bool   `json:"response"`
	RecursionDesired   bool   `json:"recursion_desired"`
	Nxdomain           bool   `json:"nxdomain"`
	Answer             bool   `json:"answer"`
	Authority          bool   `json:"authority"`
	Additional         bool   `json:"additional"`
	Qname              string `json:"qname"`
	Qtype              uint16 `json:"qtype"`
	Rname              string `json:"rname"`
	Rtype              uint16 `json:"rtype"`
	Rdata              string `json:"rdata"`
	EcsClient          string `json:"ecs_client"`
	EcsSource          uint8  `json:"ecs_source"`
	EcsScope           uint8  `json:"ecs_scope"`
}

func (d DnsSchema) ToJson(rr dns.RR, section int) {
	// TODO: Fix how RDATA is handled
	// This won't always work if the RDATA has tabs in it.
	answer := strings.Split(rr.String(), "\t")
	rdata := answer[len(answer)-1]

	// Fill in the rest of the parameters
	// This will not alter the underlying DNS schema
	d.Ttl = rr.Header().Ttl
	d.Rname = rr.Header().Name
	d.Rtype = rr.Header().Rrtype
	d.Rdata = rdata
	d.Answer = section == DnsAnswer
	d.Authority = section == DnsAuthority
	d.Additional = section == DnsAdditional

	// Let's print to Json
	// Don't print OPT records
	if d.Rtype != 41 {
		jsonData, err := json.Marshal(d)
		if err != nil {
			fmt.Println(err)
		}

		fmt.Println(string(jsonData))
	}
}
