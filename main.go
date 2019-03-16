package main

import (
	"rickybobby/parser"
)

func main() {
	//defer profile.Start().Stop()

	// Let's try grabbing some live packets
	parser.ParseDevice("en0")

	// NOTE: Just hacking this together for now
	// Should probably use a command line parsing library
	//parser.ParseFile(os.Stdin)
}
