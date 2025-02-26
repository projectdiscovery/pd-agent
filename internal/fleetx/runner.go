package fleetx

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"

	"github.com/kr/pretty"
	"github.com/masterzen/winrm"
	syncutil "github.com/projectdiscovery/utils/sync"
	"golang.org/x/crypto/ssh"
)

// Runner handles fleet operations
type Runner struct {
}

// New creates and returns a new Runner instance
func New() (*Runner, error) {
	return &Runner{}, nil
}

// Run executes the runner with the given context and options
func (r *Runner) Run(ctx context.Context, session Session) error {
	awg, err := syncutil.New(syncutil.WithSize(16))
	if err != nil {
		return err
	}

	for _, host := range session.Hosts {
		for _, task := range session.Tasks {
			awg.Add()

			go func(host Host, task Task) {
				defer awg.Done()

				select {
				case <-ctx.Done():
					return
				default:
					taskResult, err := r.RunTask(ctx, host, task)
					if err != nil {
						log.Printf("error running task: %v", err)
						return
					}

					log.Printf("task result: %s", pretty.Sprint(taskResult))
				}

			}(host, task)
		}
	}

	awg.Wait()
	return nil
}

func (r *Runner) RunTask(ctx context.Context, host Host, task Task) (*TaskResult, error) {
	switch host.Authentication.Protocol {
	case AuthenticationProtocolSSH:
		return r.runSSHTask(ctx, host, task)
	case AuthenticationProtocolWinRMI:
		return r.runWinRMITask(ctx, host, task)
	default:
		return nil, fmt.Errorf("unsupported protocol: %v", host.Authentication.Protocol)
	}
}

func (r *Runner) runSSHTask(ctx context.Context, host Host, task Task) (*TaskResult, error) {
	hostPort := net.JoinHostPort(host.Address, strconv.Itoa(host.Port))
	sshClient, err := ssh.Dial("tcp", hostPort, &ssh.ClientConfig{
		User:            host.Authentication.Username,
		Auth:            []ssh.AuthMethod{ssh.Password(host.Authentication.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		return nil, err
	}

	session, err := sshClient.NewSession()
	if err != nil {
		return nil, err
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		return nil, err
	}

	stderr, err := session.StderrPipe()
	if err != nil {
		return nil, err
	}

	err = session.Run(task.Command)
	if err != nil {
		return nil, err
	}

	stdoutBytes, err := io.ReadAll(stdout)
	if err != nil {
		return nil, err
	}

	stderrBytes, err := io.ReadAll(stderr)
	if err != nil {
		return nil, err
	}

	taskResult := &TaskResult{
		StdOut: string(stdoutBytes),
		StdErr: string(stderrBytes),
	}

	return taskResult, nil
}

func (r *Runner) runWinRMITask(ctx context.Context, host Host, task Task) (*TaskResult, error) {
	endpoint := winrm.NewEndpoint(host.Address, host.Port, false, false, nil, nil, nil, 0)
	client, err := winrm.NewClient(endpoint, host.Authentication.Username, host.Authentication.Password)
	if err != nil {
		return nil, err
	}

	var stdout, stderr bytes.Buffer

	_, err = client.RunWithContext(ctx, task.Command, &stdout, &stderr)
	if err != nil {
		return nil, err
	}

	taskResult := &TaskResult{
		StdOut: stdout.String(),
		StdErr: stderr.String(),
	}

	return taskResult, nil
}

func (r *Runner) Close(ctx context.Context) error {
	return nil
}
