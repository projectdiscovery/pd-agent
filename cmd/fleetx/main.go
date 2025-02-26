package main

import (
	"context"
	"log"

	"github.com/projectdiscovery/pdtm-agent/internal/fleetx"
)

func main() {
	session := fleetx.Session{
		Hosts: []fleetx.Host{
			{
				Address: "127.0.0.1",
				Port:    22222,
				Authentication: fleetx.Authentication{
					Protocol: fleetx.AuthenticationProtocolSSH,
					Username: "root",
					Password: "password"},
			},
		},
		Tasks: []fleetx.Task{
			{
				Description: "Task 1 Description",
				Command:     "echo hello"},
		},
	}

	runner, err := fleetx.New()
	if err != nil {
		log.Fatalf("Failed to create runner: %v", err)
	}
	defer runner.Close(context.Background())

	err = runner.Run(context.Background(), session)
	if err != nil {
		log.Fatalf("Failed to run runner: %v", err)
	}
}
