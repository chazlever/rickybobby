package iohandlers

import (
	"encoding/json"
	"fmt"

	"github.com/rs/zerolog/log"
)

func init() {
	Marshalers["json"] = toJson
}

func toJson(d *DnsSchema) {
	jsonData, err := json.Marshal(d)
	if err != nil {
		log.Warn().Msgf("Error converting to JSON: %v", err)
	}
	fmt.Printf("%s\n", jsonData)
}
