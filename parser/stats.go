package parser

import (
	"encoding/json"
	"fmt"
	"github.com/rs/zerolog"

	"github.com/rs/zerolog/log"
)

type Statistics struct {
	PacketTotal  uint `json:"packetTotal"`
	PacketIPv4   uint `json:"packetIPv4"`
	PacketIPv6   uint `json:"packetIPv6"`
	PacketTcp    uint `json:"packetTcp"`
	PacketUdp    uint `json:"packetUdp"`
	PacketDns    uint `json:"packetDns"`
	PacketErrors uint `json:"packetErrors"`
}

func (s Statistics) ToJson() {
	jsonData, err := json.Marshal(&s)
	if err != nil {
		log.Warn().Msgf("Error converting to JSON: %v", err)
	}
	fmt.Printf("%s\n", jsonData)
}

func (s Statistics) MarshalZerologObject(e *zerolog.Event) {
	e.Uint("Total", s.PacketTotal).
		Uint("IPv4", s.PacketIPv4).
		Uint("IPv6", s.PacketIPv6).
		Uint("TCP", s.PacketTcp).
		Uint("UDP", s.PacketUdp).
		Uint("DNS", s.PacketDns).
		Uint("Failed", s.PacketErrors)
}
