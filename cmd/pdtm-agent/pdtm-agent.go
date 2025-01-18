package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/pdtm-agent/internal/runner"
)

func main() {
	options := runner.ParseOptions()
	pdtmRunner, err := runner.NewRunner(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup close handler
	go func() {
		<-c
		fmt.Println("\r- Ctrl+C pressed in Terminal, Exiting...")
		pdtmRunner.Close()
		cancel()
	}()

	err = pdtmRunner.Run(ctx)
	if err != nil {
		gologger.Fatal().Msgf("Could not run pdtm: %s\n", err)
	}
}
