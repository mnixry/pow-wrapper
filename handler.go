package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/network"
	docker "github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/docker/go-connections/nat"
)

type powClient struct {
	conn             net.Conn
	difficulty       int
	dockerCli        *docker.Client
	image            string
	envs             []string
	commands         []string
	timeout          int
	containerTimeout int
	ttyEnabled       bool
	skipPoW          bool
	networkIsolation bool
	internetAccess   bool
	exposedPorts     []uint16
}

func (p *powClient) sendLine(line string, args ...interface{}) {
	if len(args) > 0 {
		line = fmt.Sprintf(line, args...)
	}
	p.conn.Write([]byte(line + "\n"))
}

func (p *powClient) readTimeout(buf []byte) (int, error) {
	p.conn.SetReadDeadline(time.Now().Add(time.Duration(p.timeout) * time.Second))
	defer p.conn.SetReadDeadline(time.Time{})
	return p.conn.Read(buf)
}

func (p *powClient) pow() bool {
	p.sendLine("Welcome to the proof of work challenge")
	p.sendLine("You have %d seconds to solve the PoW", p.timeout)

	nonce := make([]byte, 6)
	_, err := rand.Read(nonce)
	if err != nil {
		panic(err)
	}
	nonceStr := base64.StdEncoding.EncodeToString(nonce)
	p.sendLine(
		"assert sha256('%s' + ?).hexdigest().startswith('0' * %d) == True",
		nonceStr, p.difficulty)
	p.sendLine("? = ")

	buf := make([]byte, 1024)
	start := time.Now()
	n, err := p.readTimeout(buf)
	if err != nil || n == 0 {
		log.Printf("Error reading pow: %v", err)
		return false
	}
	elapsed := time.Since(start)

	salt := bytes.TrimRight(buf[:n], "\x00\r\n")
	checker := sha256.New()
	checker.Write([]byte(nonceStr))
	checker.Write(salt)
	hashHex := fmt.Sprintf("%x", checker.Sum(nil))

	if hashHex[:p.difficulty] != strings.Repeat("0", p.difficulty) {
		log.Printf("Invalid PoW from %s", p.conn.RemoteAddr())
		p.sendLine("Invalid PoW")
		return false
	}

	log.Printf("PoW accepted from %s, took client %v", p.conn.RemoteAddr(), elapsed)
	p.sendLine("PoW accepted, starting container, you have %d seconds", p.containerTimeout)
	return true
}

func (p *powClient) handle() {
	defer p.conn.Close()

	if !p.skipPoW {
		result := p.pow()
		if !result {
			return
		}
	} else {
		p.sendLine("Starting container, you have %d seconds before it is killed", p.containerTimeout)
	}

	if err := p.runContainer(); err != nil {
		p.sendLine("Error running container, please report to the author")
		log.Printf("Error running container: %v", err)
		return
	}
}

func (p *powClient) runContainer() error {
	ctx := context.Background()
	imageName := strings.Split(p.image, ":")[0]
	clientName := regexp.MustCompile(`[^a-zA-Z0-9]`).ReplaceAllString(p.conn.RemoteAddr().String(), "")
	containerName := fmt.Sprintf("%s-%s", imageName, clientName)
	networkName := containerName + "-network"

	var networkID string
	if p.networkIsolation {
		res, err := p.dockerCli.NetworkCreate(ctx, networkName, types.NetworkCreate{
			Internal: !p.internetAccess,
		})
		if err != nil {
			log.Printf("Error creating network: %v", err)
			return err
		}
		networkID = res.ID
		defer func() {
			if err := p.dockerCli.NetworkRemove(ctx, networkID); err != nil {
				log.Printf("Error removing network: %v", err)
			}
		}()
	}

	var networkConfig *network.NetworkingConfig
	if p.networkIsolation {
		networkConfig = &network.NetworkingConfig{
			EndpointsConfig: map[string]*network.EndpointSettings{
				"sandbox": {
					NetworkID: networkID,
				},
			},
		}
	}

	var hostConfig *container.HostConfig
	exposedPorts := nat.PortSet{}
	if len(p.exposedPorts) > 0 {
		for _, port := range p.exposedPorts {
			portStr := nat.Port(fmt.Sprintf("%d/tcp", port))
			exposedPorts[portStr] = struct{}{}
		}
		hostConfig = &container.HostConfig{
			PublishAllPorts: true,
		}
	}

	resp, err := p.dockerCli.ContainerCreate(ctx, &container.Config{
		Image:           p.image,
		Env:             p.envs,
		Cmd:             p.commands,
		OpenStdin:       true,
		AttachStdin:     true,
		AttachStdout:    true,
		AttachStderr:    true,
		Tty:             p.ttyEnabled,
		NetworkDisabled: !p.internetAccess && !p.networkIsolation,
		ExposedPorts:    exposedPorts,
	}, hostConfig, networkConfig, nil, containerName)

	if err != nil {
		log.Printf("Error creating container: %v", err)
		return err
	}
	log.Printf("Created container %s to resp client %s, inside network %s", resp.ID, p.conn.RemoteAddr(), networkName)
	defer func() {
		if err := p.dockerCli.ContainerRemove(ctx, resp.ID, container.RemoveOptions{
			Force:         true,
			RemoveVolumes: true,
			RemoveLinks:   true,
		}); err != nil {
			log.Printf("Error removing container: %v", err)
		}
	}()

	// There is no need to attach to the container if we are exposing ports
	if len(p.exposedPorts) > 0 {
		return p.exposePortFlow(ctx, resp.ID)
	}
	return p.attachFlow(ctx, resp.ID)
}

func (p *powClient) attachFlow(ctx context.Context, containerID string) error {
	attachResp, err := p.dockerCli.ContainerAttach(ctx, containerID, container.AttachOptions{
		Logs:   true,
		Stream: true,
		Stdin:  true,
		Stdout: true,
		Stderr: true,
	})
	if err != nil {
		log.Printf("Error attaching to container: %v", err)
		return err
	}
	defer attachResp.Close()

	go func() {
		<-time.After(time.Duration(p.containerTimeout) * time.Second)
		err := p.dockerCli.ContainerKill(ctx, containerID, "SIGKILL")
		if err != nil && !strings.Contains(err.Error(), "No such container") {
			log.Printf("Error killing timeouted container: %v", err)
		}
	}()

	if err := p.dockerCli.ContainerStart(ctx, containerID, container.StartOptions{}); err != nil {
		log.Printf("Error starting container: %v", err)
		return err
	}
	defer func() {
		if resp, err := p.dockerCli.ContainerInspect(ctx, containerID); err != nil {
			log.Printf("Error inspecting container: %v", err)
		} else if resp.State.Running {
			if err := p.dockerCli.ContainerKill(ctx, containerID, "SIGKILL"); err != nil {
				log.Printf("Error stopping container: %v", err)
			}
		}
	}()

	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer p.conn.Close()
		var err error
		if p.ttyEnabled {
			_, err = io.Copy(p.conn, attachResp.Reader)
		} else {
			_, err = stdcopy.StdCopy(p.conn, p.conn, attachResp.Reader)
		}
		if err != nil && !errors.Is(err, net.ErrClosed) {
			log.Printf("Error copying from container: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		defer attachResp.CloseWrite()
		if _, err := io.Copy(attachResp.Conn, p.conn); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Printf("Error copying to container: %v", err)
		}
	}()
	wg.Wait()

	return nil
}

func (p *powClient) exposePortFlow(ctx context.Context, containerID string) error {
	err := p.dockerCli.ContainerStart(ctx, containerID, container.StartOptions{})
	if err != nil {
		log.Printf("Error starting container: %v", err)
		return err
	}
	defer func() {
		if resp, err := p.dockerCli.ContainerInspect(ctx, containerID); err != nil {
			log.Printf("Error inspecting container: %v", err)
		} else if resp.State.Running {
			if err := p.dockerCli.ContainerKill(ctx, containerID, "SIGKILL"); err != nil {
				log.Printf("Error stopping container: %v", err)
			}
		}
	}()

	filter := filters.NewArgs()
	filter.Add("id", containerID)
	resp, err := p.dockerCli.ContainerList(ctx, container.ListOptions{
		Filters: filter,
	})
	if err != nil {
		log.Printf("Error listing containers: %v", err)
		return err
	}
	containerInfo := resp[0]
	exposedPortsPairs := map[uint16]uint16{}
	for port := range containerInfo.Ports {
		portInfo := containerInfo.Ports[port]
		exposedPortsPairs[portInfo.PrivatePort] = portInfo.PublicPort
	}

	for exposedPortIndex := range p.exposedPorts {
		privatePort := p.exposedPorts[exposedPortIndex]
		publicPort := exposedPortsPairs[privatePort]
		p.sendLine("Port %d is exposed on %d", privatePort, publicPort)
	}
	p.sendLine("You can now connect to the exposed ports")
	p.conn.Close()

	<-time.After(time.Duration(p.containerTimeout) * time.Second)
	log.Printf("Container %s created by %s timed out", containerID, p.conn.RemoteAddr())
	return nil
}
