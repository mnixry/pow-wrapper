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

	"github.com/docker/docker/api/types/container"
	docker "github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
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
}

func (p *powClient) sendLine(line string) {
	p.conn.Write([]byte(line + "\n"))
}

func (p *powClient) readTimeout(buf []byte) (int, error) {
	p.conn.SetReadDeadline(time.Now().Add(time.Duration(p.timeout) * time.Second))
	defer p.conn.SetReadDeadline(time.Time{})
	return p.conn.Read(buf)
}

func (p *powClient) handle() {
	defer p.conn.Close()

	p.sendLine("Welcome to the proof of work challenge")
	nonce := make([]byte, 6)
	_, err := rand.Read(nonce)
	if err != nil {
		panic(err)
	}
	nonceStr := base64.StdEncoding.EncodeToString(nonce)
	powString := fmt.Sprintf(
		"assert sha256('%s' + ?).hexdigest().startswith('0' * %d) == True",
		nonceStr, p.difficulty)
	p.sendLine(powString)
	p.sendLine("? = ")

	buf := make([]byte, 1024)
	start := time.Now()
	n, err := p.readTimeout(buf)
	if err != nil || n == 0 {
		log.Printf("Error reading pow: %v", err)
		return
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
		return
	}

	log.Printf("PoW accepted from %s, took client %v", p.conn.RemoteAddr(), elapsed)
	p.sendLine("PoW accepted, preparing challenge")

	if err := p.runContainer(); err != nil {
		p.sendLine("Error running container, please report to the author")
		log.Printf("Error running container: %v", err)
		return
	}
}

func (p *powClient) runContainer() error {
	ctx := context.Background()
	imageName := strings.Split(p.image, ":")[0]
	clientName := regexp.MustCompile(`[^a-zA-Z0-9]`).ReplaceAllString(imageName, "")
	containerName := fmt.Sprintf("%s-%s", imageName, clientName)

	resp, err := p.dockerCli.ContainerCreate(ctx, &container.Config{
		Image:        p.image,
		Env:          p.envs,
		Cmd:          p.commands,
		OpenStdin:    true,
		AttachStdin:  true,
		AttachStdout: true,
		AttachStderr: true,
		Tty:          p.ttyEnabled,
	}, nil, nil, nil, containerName)

	if err != nil {
		log.Printf("Error creating container: %v", err)
		return err
	}
	defer func() {
		if err := p.dockerCli.ContainerRemove(ctx, resp.ID, container.RemoveOptions{}); err != nil {
			log.Printf("Error removing container: %v", err)
		}
	}()

	attachResp, err := p.dockerCli.ContainerAttach(ctx, resp.ID, container.AttachOptions{
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

	attachResp.Conn.SetReadDeadline(time.Now().Add(time.Duration(p.containerTimeout) * time.Second))
	defer attachResp.Conn.SetReadDeadline(time.Time{})

	if err := p.dockerCli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		log.Printf("Error starting container: %v", err)
		return err
	}
	defer func() {
		if resp, err := p.dockerCli.ContainerInspect(ctx, resp.ID); err != nil {
			log.Printf("Error inspecting container: %v", err)
		} else if resp.State.Running {
			if err := p.dockerCli.ContainerKill(ctx, resp.ID, "SIGKILL"); err != nil {
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
