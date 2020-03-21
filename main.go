package main

import (
	"log"
	"os"
	"rickybobby/parser"
	"rickybobby/producer"
	"time"

	"github.com/pkg/profile"
	"github.com/spf13/viper"
	"gopkg.in/urfave/cli.v1"
)

func loadGlobalOptions(c *cli.Context) {
	parser.DoParseTcp = c.GlobalBool("tcp")
	parser.DoParseQuestions = c.GlobalBool("questions")
	parser.DoParseQuestionsEcs = c.GlobalBool("questions-ecs")
	parser.Source = c.GlobalString("source")
	parser.Sensor = c.GlobalString("sensor")
	parser.Format = c.GlobalString("format")
	parser.OutputType = c.GlobalString("output-type")
	parser.Config = c.GlobalString("config")

	producer.MessageKey = c.GlobalString("kafka-key")
	producer.Topic = c.GlobalString("kafka-topic")
	producer.SASLUsername = c.GlobalString("kafka-username")
	producer.SASLPassword = c.GlobalString("kafka-password")
	producer.Brokers = c.GlobalStringSlice("kafka-brokers")

}

func pcapCommand(c *cli.Context) error {

	if c.NArg() < 1 {
		return cli.NewExitError("ERROR: must provide at least one filename", 1)
	}

	if c.GlobalBool("profile") {
		defer profile.Start().Stop()
	}

	loadGlobalOptions(c)

	if parser.Config != "" {
		viper.SetDefault("KafkaSASL", true)
		viper.SetDefault("KafkaTopic", "rickybobby")
		viper.SetDefault("KafkaSASLUsername", "user")
		viper.SetDefault("KafkaSASLPassword", "thisisabadpassword")
		viper.SetConfigFile(parser.Config)
		viper.ReadInConfig()
	}
	if parser.OutputType == "kafka" {
		if producer.MessageKey == "" {
			producer.MessageKey = viper.GetString("KafkaMessageKey")
		}
		if len(producer.Brokers) == 0 {
			producer.Brokers = viper.GetStringSlice("KafkaBrokers")
		}
		if producer.SASLUsername == "" {
			producer.SASLUsername = viper.GetString("KafkaSASLUsername")
		}
		if producer.SASLPassword == "" {
			producer.SASLUsername = viper.GetString("KafkaSASLPassword")
		}
		if producer.Topic == "" {
			producer.Topic = viper.GetString("KafkaTopic")
		}
		producer.Producer = producer.NewProducer()
	}

	for _, f := range c.Args() {
		parser.ParseFile(f)
	}
	return nil
}

func liveCommand(c *cli.Context) error {
	if c.NArg() != 1 {
		return cli.NewExitError("ERROR: must supply exactly one interface", 1)
	}

	if c.GlobalBool("profile") {
		defer profile.Start().Stop()
	}

	loadGlobalOptions(c)

	if parser.Config != "" {
		viper.SetDefault("KafkaSASL", true)
		viper.SetDefault("KafkaSASLUsername", "user")
		viper.SetDefault("KafkaSASLPassword", "thisisabadpassword")
		viper.SetConfigFile(parser.Config)
		viper.ReadInConfig()
	}

	// Load command specific flags
	snapshotLen := int32(c.Int("snaplen"))
	promiscuous := c.Bool("promiscuous")
	timeout := time.Duration(c.Int("timeout")) * time.Second

	parser.ParseDevice(c.Args().First(), snapshotLen, promiscuous, timeout)
	return nil
}

func main() {
	app := cli.NewApp()
	app.Name = "rickybobby"
	app.Usage = "Parsing DNS packets when you wanna GO fast!"
	app.Version = "1.0.0"
	app.Compiled = time.Now()

	app.Authors = []cli.Author{
		{
			Name:  "Chaz Lever",
			Email: "chazlever@gatech.edu",
		},
	}

	app.Commands = []cli.Command{
		{
			Name:      "pcap",
			Usage:     "read packets from a PCAP file",
			Action:    pcapCommand,
			ArgsUsage: "[file...]",
		},
		{
			Name:      "live",
			Usage:     "read packets from a live interface",
			Action:    liveCommand,
			ArgsUsage: "[interface]",
			Flags: []cli.Flag{
				cli.IntFlag{
					Name:  "snaplen",
					Usage: "set snapshot length for PCAP collection",
					Value: 4096,
				},
				cli.BoolFlag{
					Name:  "promiscuous",
					Usage: "set promiscuous mode for traffic collection",
				},
				cli.IntFlag{
					Name:  "timeout",
					Usage: "set timeout value for traffic collection",
					Value: 30,
				},
			},
		},
	}

	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "tcp",
			Usage: "attempt to parse TCP packets",
		},
		cli.BoolFlag{
			Name:  "questions",
			Usage: "parse questions in addition to responses",
		},
		cli.BoolFlag{
			Name:  "questions-ecs",
			Usage: "parse questions only if they contain ECS information",
		},
		cli.BoolFlag{
			Name:  "profile",
			Usage: "toggle performance profiler",
		},
		cli.StringFlag{
			Name:  "sensor",
			Usage: "name of sensor DNS traffic was collected from",
		},
		cli.StringFlag{
			Name:  "source",
			Usage: "name of source DNS traffic was collected from",
		},
		cli.StringFlag{
			Name:  "output-type",
			Usage: "where to output parsed traffic [stdout (default), kafka]",
			Value: "stdout",
		},
		cli.StringFlag{
			Name:  "format",
			Usage: "output format of parsed traffic [json (default), avro]",
			Value: "json",
		},
		cli.StringFlag{
			Name:  "config",
			Usage: "YML config file with config options",
		},
		cli.StringFlag{
			Name:  "kafka-key",
			Usage: "(kafka) Key to use when sending data to Kafka",
		},
		cli.StringFlag{
			Name:  "kafka-topic",
			Usage: "(kafka) Topic",
		},
		cli.StringFlag{
			Name:  "kafka-username",
			Usage: "(kafka) Username for SASL authentication to Kafka brokers",
		},
		cli.StringFlag{
			Name:  "kafka-password",
			Usage: "(kafka) Password for SASL authentication to Kafka brokers",
		},
		cli.StringSliceFlag{
			Name:  "kafka-brokers",
			Usage: "(kafka) List of Kafka brokers",
		},
	}

	app.Action = cli.ShowAppHelp

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
