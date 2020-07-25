package main

import (
	"os"
	"rickybobby/parser"
	"time"

	"github.com/hamba/avro"
	"github.com/hamba/avro/ocf"
	"github.com/pkg/profile"
	log "github.com/sirupsen/logrus"
	"gopkg.in/urfave/cli.v1"
)

func loadGlobalOptions(c *cli.Context) {
	parser.DoParseTcp = c.GlobalBool("tcp")
	parser.DoParseQuestions = c.GlobalBool("questions")
	parser.DoParseQuestionsEcs = c.GlobalBool("questions-ecs")
	parser.Source = c.GlobalString("source")
	parser.Sensor = c.GlobalString("sensor")
}

func pcapCommand(c *cli.Context) error {
	if c.NArg() < 1 {
		return cli.NewExitError("ERROR: must provide at least one filename", 1)
	}

	if c.GlobalBool("profile") {
		defer profile.Start().Stop()
	}

	loadGlobalOptions(c)

	// TODO: Implement for liveCommand too

	if c.GlobalString("format") == "avro" {
		codec, err := parser.NewAvroCodec()
		var avroWriter = avro.NewWriter(os.Stdout, 1000)
		var magicBytes = [4]byte{'O', 'b', 'j', 1}
		var HeaderSchema = ocf.HeaderSchema
		header := ocf.Header{
			Magic: magicBytes,
			Meta:  nil,
		}
		avroWriter.WriteVal(HeaderSchema, header)

		if err != nil {
			log.Fatal("Failed to initialize avro codec.")
		}
		parser.AvroWriter = *avroWriter
		parser.AvroCodec = codec
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
	app.Version = "1.0.2"
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
			Name:  "format",
			Usage: "output format of parsed traffic [json (default), avro]",
			Value: "json",
		},
	}

	app.Action = cli.ShowAppHelp

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
