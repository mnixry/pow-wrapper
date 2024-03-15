package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

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
	exposePorts := flag.String("expose-ports", "", "Comma separated list of ports to expose")
	maxInstances := flag.Int("max-instances", 0, "Maximum number of instances")
	maxInstancesPerIP := flag.Int("max-instances-per-ip", 2, "Maximum number of instances per IP")

	var envs envVar
	flag.Var(&envs, "env", "Environment variables to set")
	flag.Parse()
	remainder := flag.Args()

	log.Default().SetFlags(log.LstdFlags | log.Lshortfile)

	if *image == "" {
		panic("Image not specified")
	}

	if !*internetAccess && *exposePorts != "" {
		panic("Cannot expose ports without internet access")
	}

	var exposedPorts []uint16
	if *exposePorts != "" {
		for _, port := range strings.Split(*exposePorts, ",") {
			portNumber, err := strconv.Atoi(port)
			if err != nil || portNumber < 1 || portNumber > 0xffff {
				panic("Invalid port number")
			}
			exposedPorts = append(exposedPorts, uint16(portNumber))
		}
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		panic(err)
	}
	dockerCli, err := docker.NewClientWithOpts(docker.FromEnv, docker.WithAPIVersionNegotiation())
	if err != nil {
		panic(err)
	}

	instances := make(map[string]int)

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
		client := powClient{
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
			exposedPorts:     exposedPorts,
		}
		go func() {
			remoteIP := conn.RemoteAddr().(*net.TCPAddr).IP.String()
			instances[remoteIP]++

			defer conn.Close()
			defer func() {
				<-time.After(5 * time.Second)
				instances[remoteIP]--
			}()

			allInstances := func() int {
				count := 0
				for _, v := range instances {
					count += v
				}
				return count
			}()

			if *maxInstances > 0 && allInstances > *maxInstances {
				log.Printf("Global limit exceed %d", allInstances)
				client.sendLine("Too many instances created, exceeded limit")
				return
			}

			if *maxInstancesPerIP > 0 && instances[remoteIP] > *maxInstancesPerIP {
				log.Printf("IP limit exceed %d, %d instances", instances[remoteIP], *maxInstancesPerIP)
				client.sendLine("Too many instances for your IP, exceeded limit")
				return
			}

			client.handle()
		}()
	}
}
