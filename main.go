package main

import (
	"gopkg.in/urfave/cli.v1"
	"log"
	"os"
	"rickybobby/parser"
	"time"
)

func pcapCommand(c *cli.Context) error {
	if c.NArg()	< 1 {
		return cli.NewExitError("ERROR: must provide at least one filename", 1)
	}

	// Load global flags
	parser.NoParseTcp = c.GlobalBool("no-tcp")
	parser.NoParseEcs = c.GlobalBool("no-ecs")
	parser.DoParseQuestions = c.GlobalBool("questions")

	for _, f := range c.Args() {
		parser.ParseFile(f)
	}
	return nil
}

func liveCommand(c *cli.Context) error {
	if c.NArg() != 1 {
		return cli.NewExitError("ERROR: must supply exactly one interface", 1)
	}

	// Load global flags
	parser.NoParseTcp = c.GlobalBool("no-tcp")
	parser.NoParseEcs = c.GlobalBool("no-ecs")
	parser.DoParseQuestions = c.GlobalBool("questions")

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
			Name: "Chaz Lever",
			Email: "chazlever@gatech.edu",
		},
	}

	app.Commands = []cli.Command{
		{
			Name: "pcap",
			Usage: "read packets from a PCAP file",
			Action: pcapCommand,
			ArgsUsage: "[file...]",
		},
		{
			Name: "live",
			Usage: "read packets from a live interface",
			Action: liveCommand,
			ArgsUsage: "[interface]",
			Flags: []cli.Flag {
				cli.IntFlag{
					Name: "snaplen",
					Usage: "set snapshot length for PCAP collection",
					Value: 4096,
				},
				cli.BoolFlag{
					Name: "promiscuous",
					Usage: "set promiscuous mode for traffic collection",
				},
				cli.IntFlag{
					Name: "timeout",
					Usage: "set timeout value for traffic collection",
					Value: 30,
				},
			},
		},
	}

	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name: "no-tcp",
			Usage: "do not attempt to parse TCP packets",
		},
		cli.BoolFlag{
			Name: "no-ecs",
			Usage: "do not attempt to parse ECS information",
		},
		cli.BoolFlag{
			Name: "questions",
			Usage: "parse questions in addition to responses",
		},
	}

	app.Action = cli.ShowAppHelp

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}