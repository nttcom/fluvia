// Copyright (c) 2023 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/fluvia/blob/main/LICENSE

package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/nttcom/fluvia/internal/config"
	"github.com/nttcom/fluvia/internal/pkg/version"
	"github.com/nttcom/fluvia/pkg/client"
)

type flags struct {
	configFile string
	ifName     string
}

func main() {
	// Check if --version flag was passed
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println("fluvia " + version.Version())
		return
	}

	// Parse flags
	f := &flags{}
	flag.StringVar(&f.configFile, "f", "fluvia.yaml", "Specify a configuration file")
	flag.StringVar(&f.ifName, "i", "", "Specify a configuration file")
	flag.Parse()

	// Read configuration file
	c, err := config.ReadConfigFile(f.configFile)
	if err != nil {
		log.Panic(err)
	}

	raddr, err := net.ResolveUDPAddr("udp", c.Ipfix.Address+":"+c.Ipfix.Port)
	if err != nil {
		log.Panic(err)
	}

	client.New(f.ifName, raddr)
}
