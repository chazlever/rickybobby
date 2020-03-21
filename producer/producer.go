package producer

import (
	"log"
	"time"

	"github.com/Shopify/sarama"
	"github.com/linkedin/goavro"
)

func NewAccessLogProducer(brokerList []string) sarama.AsyncProducer {

	// For the access log, we are looking for AP semantics, with high throughput.
	// By creating batches of compressed messages, we reduce network I/O at a cost of more latency.
	config := sarama.NewConfig()
	// if tlsConfig != nil {
	// 	config.Net.TLS.Enable = true
	// 	config.Net.TLS.Config = tlsConfig
	// }
	config.Producer.RequiredAcks = sarama.WaitForLocal       // Only wait for the leader to ack
	config.Producer.Compression = sarama.CompressionSnappy   // Compress messages
	config.Producer.Flush.Frequency = 500 * time.Millisecond // Flush batches every 500ms

	producer, err := sarama.NewAsyncProducer(brokerList, config)
	if err != nil {
		log.Fatalln("Failed to start Sarama producer:", err)
	}

	// We will just log to STDOUT if we're not able to produce messages.
	// Note: messages will only be returned here after all retry attempts are exhausted.
	go func() {
		for err := range producer.Errors() {
			log.Println("Failed to write access log entry:", err)
		}
	}()

	return producer
}

func NewAvroCodec() (*goavro.Codec, error) {
	// schema := readSchema()
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
	return goavro.NewCodec(schema)
}
