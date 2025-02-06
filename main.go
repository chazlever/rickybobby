package main

import (
	"fmt"
	"github.com/rs/zerolog"
	"os"
	"time"

	"github.com/chazlever/rickybobby/iohandlers"
	"github.com/chazlever/rickybobby/parser"
	"github.com/pkg/profile"
	"github.com/rs/zerolog/log"
	"gopkg.in/urfave/cli.v1"
)

var logLevels = []string{"debug", "info", "warn", "error"}

func isValidLogLevel(level string) bool {
	if level == "" {
		return true
	}
	for _, l := range logLevels {
		if l == level {
			return true
		}
	}
	return false
}

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
	logLevel := c.GlobalString("log-level")

	outputFormats := make(map[string]bool)
	for _, format := range getOutputFormats() {
		outputFormats[format] = true
	}

	if isValidLogLevel(logLevel) {
		switch logLevel {
		case "debug":
			zerolog.SetGlobalLevel(zerolog.DebugLevel)
		case "warn":
			zerolog.SetGlobalLevel(zerolog.WarnLevel)
		case "error":
			zerolog.SetGlobalLevel(zerolog.ErrorLevel)
		case "info":
			zerolog.SetGlobalLevel(zerolog.InfoLevel)
		default:
			zerolog.SetGlobalLevel(zerolog.NoLevel)
		}
	} else {
		return cli.NewExitError(
			fmt.Sprintf("ERROR: Invalid log level: \"%s\" not in %v",
				logLevel,
				logLevels),
			1)
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

	parser.ParseDevice(c.Args().First(), snapshotLen, promiscuous)
	return nil
}

func main() {
	app := cli.NewApp()
	app.Name = "rickybobby"
	app.Usage = "Parsing DNS packets when you wanna GO fast!"
	app.Version = "1.0.6"
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
		cli.StringFlag{
			Name:  "log-level",
			Usage: fmt.Sprintf("specify the log level to use %+q", logLevels),
		},
	}

	app.Action = cli.ShowAppHelp

	if err := app.Run(os.Args); err != nil {
		log.Fatal().Err(err)
	}
}
