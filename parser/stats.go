package parser

import (
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
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
		log.Warnf("Error converting to JSON: %v", err)
	}
	fmt.Printf("%s\n", jsonData)
}
