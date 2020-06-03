package main

import (
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"

	"path/filepath"

	"github.com/comail/colog"
	proxy "github.com/openstandia/ntlm2basic"
)

var (
	version  string
	revision string

	fs = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	bindAddr    = fs.String("b", ":3128", "Bind address and port")
	domain      = fs.String("d", "", "Domain")
	upstreamURL = fs.String("u", "", "Upstream URL")

	loglevel = fs.String(
		"log-level",
		"info",
		"Log level, one of: debug, info, warn, error, panic",
	)

	enableDump = fs.Bool("enable-dump", false, "Enable request/response dump")
)

func main() {
	fs.Usage = func() {
		_, exe := filepath.Split(os.Args[0])
		fmt.Fprintf(os.Stderr, "ntlm2basic %s (rev: %s)\n", version, revision)
		fmt.Fprintf(os.Stderr, "Usage:\n\n  %s [options]\n\nOptions:\n\n", exe)
		fs.PrintDefaults()
	}
	fs.Parse(os.Args[1:])

	// setup logger
	colog.SetDefaultLevel(colog.LDebug)
	colog.SetMinLevel(colog.LInfo)
	level, err := colog.ParseLevel(*loglevel)
	if err != nil {
		log.Fatalf("alert: Invalid log level: %s", err.Error())
	}
	colog.SetMinLevel(level)
	colog.SetFormatter(&colog.StdFormatter{
		Colors: true,
		Flag:   log.Ldate | log.Ltime | log.Lmicroseconds,
	})
	colog.ParseFields(true)
	colog.Register()

	if *upstreamURL == "" {
		fs.PrintDefaults()
		return
	}

	upURL, err := url.Parse(*upstreamURL)
	if err != nil {
		log.Fatalf("Invalid upstreamURL")
	}

	f := proxy.NewServer(&proxy.ServerConfig{
		BindAddr:    *bindAddr,
		UpstreamURL: upURL,
		Domain:      *domain,
		EnableDump:  *enableDump,
	})

	log.Printf("info: Starting ntlm2basic: %s", *bindAddr)

	if err := f.Start(); err != nil {
		log.Fatalf("alert: %s", err.Error())
	}
}
