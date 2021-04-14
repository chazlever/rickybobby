package iohandlers

import (
	"encoding/json"
	"fmt"

	log "github.com/sirupsen/logrus"
)

func init() {
	Marshalers["json"] = toJson
}

func toJson(d *DnsSchema) {
	jsonData, err := json.Marshal(d)
	if err != nil {
		log.Warnf("Error converting to JSON: %v", err)
	}
	fmt.Printf("%s\n", jsonData)
}
