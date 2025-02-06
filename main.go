package main

import (
	"fmt"
	"os"
	"time"

	"github.com/chazlever/rickybobby/iohandlers"
	"github.com/chazlever/rickybobby/parser"
	"github.com/pkg/profile"
	"github.com/rs/zerolog/log"
	"gopkg.in/urfave/cli.v1"
)

func getOutputFormats() []string {
	marshalers := make([]string, 0, len(iohandlers.Marshalers))
	for m := range iohandlers.Marshalers {
		marshalers = append(marshalers, m)
	}

	return marshalers
}

func loadGlobalOptions(c *cli.Context) error {
	parser.BpfFilter = c.GlobalString("bpf-filter")
	parser.DoParseQuestions = c.GlobalBool("questions")
	parser.DoParseQuestionsEcs = c.GlobalBool("questions-ecs")
	parser.Source = c.GlobalString("source")
	parser.Sensor = c.GlobalString("sensor")
	outputFormat := c.GlobalString("format")
	parser.OutputFormat = outputFormat

	outputFormats := make(map[string]bool)
	for _, format := range getOutputFormats() {
		outputFormats[format] = true
	}

	if _, ok := outputFormats[outputFormat]; !ok {
		return cli.NewExitError(
			fmt.Sprintf("ERROR: Invalid output format: \"%s\" not in %v",
				outputFormat,
				getOutputFormats()),
			1)
	}

	return nil
}

func pcapCommand(c *cli.Context) error {
	if c.NArg() < 1 {
		return cli.NewExitError("ERROR: must provide at least one filename", 1)
	}

	if c.GlobalBool("profile") {
		defer profile.Start().Stop()
	}

	if err := loadGlobalOptions(c); err != nil {
		return err
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

	if err := loadGlobalOptions(c); err != nil {
		return err
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
	app.Version = "1.0.5"
	app.Compiled = time.Now()

	app.Authors = []cli.Author{
		{
			Name:  "Chaz Lever",
			Email: "chazlever@users.noreply.github.com",
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
		cli.StringFlag{
			Name:  "bpf-filter",
			Usage: "specify a BPF filter to use for filtering packets",
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
			Usage: fmt.Sprintf("specify the output formatter to use %+q", getOutputFormats()),
			Value: "json",
		},
	}

	app.Action = cli.ShowAppHelp

	if err := app.Run(os.Args); err != nil {
		log.Fatal().Err(err)
	}
}
