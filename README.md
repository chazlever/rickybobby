# rickybobby

For parsing DNS packets when you wanna **Go** fast!

> "If you ain't first, you're last" - Ricky Bobby

<img alt="Wanna Go Fast!" src="https://i.pinimg.com/originals/92/9d/32/929d3292c4d7c11c8d6c0899b4e29567.jpg" width=400 />

<!-- toc -->

- [Installation](#installation)
    + [Dependencies](#dependencies)
    + [Binaries](#binaries)
    + [Via Go](#via-go)
- [Usage](#usage)
    + [Parsing PCAP File](#parsing-pcap-file)
    + [Parsing Live Interface](#parsing-live-interface)

<!-- tocstop -->

## Installation

### Dependencies

To run a pre-built binary, the only dependency is `libpcap`.  If you're running
on a Debian based distribution, you can install this with the following
command:

    sudo apt-get install libpcap
    
If you're planning on building from source, you will need a version of Go that
supports Modules (Go 1.11+). See the Go Wiki page on
[Modules](https://github.com/golang/go/wiki/Modules) for more information.

### Binaries

For installation instruction from binaries, please visit the [Releases
Page](https://github.gatech.edu/clever3/rickybobby/releases).

### Via Go

You can use the Go tool to download and install the binary for you.

    $ go get github.gatech.edu/clever3/rickybobby
  
Or you can manually clone the repository and build the binaries yourself.

    $ git clone https://github.gatech.edu/clever3/rickybobby.git
    $ cd rickybobby
    $ go build && go install

Each of the above methods will install the `rickybobby` binary into
`$GOPATH/bin`.

## Usage

To view the help documentation for the application, you can simply call the
application without any arguments.

    $ rickybobby
    NAME:
       rickybobby - Parsing DNS packets when you wanna GO fast!
    
    USAGE:
       rickybobby [global options] command [command options] [arguments...]
    
    VERSION:
       1.0.0
    
    AUTHOR:
       Chaz Lever <chazlever@gatech.edu>
    
    COMMANDS:
         pcap     read packets from a PCAP file
         live     read packets from a live interface
         help, h  Shows a list of commands or help for one command
    
    GLOBAL OPTIONS:
       --tcp            attempt to parse TCP packets
       --questions      parse questions in addition to responses
       --questions-ecs  parse questions only if they contain ECS information
       --profile        toggle performance profiler
       --sensor value   name of sensor DNS traffic was collected from
       --source value   name of source DNS traffic was collected from
       --help, -h       show help
       --version, -v    print the version

The application is broken out into two different commands that affect where
traffic is parsed from. More details on each of these commands is provided
below.

### Parsing PCAP File

To view the help documentation for the `pcap` command, invoke the application
as follows:

    $ rickybobby pcap -h
    NAME:
       rickybobby pcap - read packets from a PCAP file
    
    USAGE:
       rickybobby pcap [file...]

As shown above, the `pcap` command takes one more more arguments where each
argument is simply a path to an uncompressed PCAP file. It is also possible to
parse from STDIN by pass `-` as the filename. 

The following shows an example of how you can parse a compressed PCAP using
STDIN:

    $ zcat compressed.pcap.gz | rickybobby pcap - 

### Parsing Live Interface

To view the help documentation for the `live` command, invoke the applicatijon
as follows:

    $ rickybobby live -h
    NAME:
       rickybobby live - read packets from a live interface
    
    USAGE:
       rickybobby live [command options] [interface]
    
    OPTIONS:
       --snaplen value  set snapshot length for PCAP collection (default: 4096)
       --promiscuous    set promiscuous mode for traffic collection
       --timeout value  set timeout value for traffic collection (default: 30)
       
As shown above, the `live` command accepts the name of an interface to parse
from as its sole argument. There are also a number of command specific flags
that can be set.

The following shows an example of how you can parse from `eth0` in promiscuous
mode.

    $ rickybobby live --promiscuous eth0
