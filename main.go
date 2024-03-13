package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	docker "github.com/docker/docker/client"
)

type envVar []string

func (e *envVar) String() string {
	return fmt.Sprintf("%v", *e)
}

func (e *envVar) Set(value string) error {
	*e = append(*e, value)
	return nil
}

func main() {
	port := flag.Int("port", 1337, "Port to listen on")
	difficulty := flag.Int("difficulty", 6, "Difficulty of the proof of work")
	image := flag.String("image", "", "Docker image to run")
	timeout := flag.Int("timeout", 10, "Socket timeout")
	containerTimeout := flag.Int("container-timeout", 10*60, "Container timeout")
	enablesTTY := flag.Bool("tty", false, "Enable TTY")
	skipPoW := flag.Bool("skip-pow", false, "Skip proof of work")
	networkIsolation := flag.Bool("network-isolation", true, "Enable network isolation")
	internetAccess := flag.Bool("internet-access", false, "Enable internet access")

	var envs envVar
	flag.Var(&envs, "env", "Environment variables to set")
	flag.Parse()
	remainder := flag.Args()

	log.Default().SetFlags(log.LstdFlags | log.Lshortfile)

	if *image == "" {
		panic("Image not specified")
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		panic(err)
	}
	dockerCli, err := docker.NewClientWithOpts(docker.FromEnv, docker.WithAPIVersionNegotiation())
	if err != nil {
		panic(err)
	}

	log.Printf("Listening on port %d", *port)
	for {
		conn, err := listener.Accept()
		if err != nil {
			panic(err)
		}
		log.Printf("Accepted connection from %s", conn.RemoteAddr())

		var commands []string
		if len(remainder) > 0 {
			commands = remainder
		} else {
			commands = nil
		}
		pow := powClient{
			conn:             conn,
			difficulty:       *difficulty,
			dockerCli:        dockerCli,
			image:            *image,
			envs:             envs,
			commands:         commands,
			timeout:          *timeout,
			containerTimeout: *containerTimeout,
			ttyEnabled:       *enablesTTY,
			skipPoW:          *skipPoW,
			networkIsolation: *networkIsolation,
			internetAccess:   *internetAccess,
		}
		go pow.handle()
	}
}
