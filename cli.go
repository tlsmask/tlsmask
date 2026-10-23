package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

var Version = "dev"

type flagGroup struct {
	title string
	names []string
}

var groups []flagGroup

func group(title string, names ...string) {
	groups = append(groups, flagGroup{title: title, names: names})
}

func usage() {
	out := flag.CommandLine.Output()

	fmt.Fprintf(out, "tlsmask %s - TLS behaviour emulation proxy\n\n", Version)
	fmt.Fprintf(out, "Usage:\n  tlsmask [flags]\n  tlsmask [flags] reset-password\n\n")
	fmt.Fprintf(out, "Commands\n"+
		"  reset-password\n"+
		"      Clear the web UI password and print a setup token to set a new one.\n"+
		"      The proxy username and password are kept, so clients keep working.\n"+
		"      In Docker:\n"+
		"        docker exec tlsmask tlsmask reset-password\n\n")

	claimed := map[string]bool{}
	for _, g := range groups {
		var lines []string
		for _, name := range g.names {
			f := flag.Lookup(name)
			if f == nil {
				continue
			}
			claimed[name] = true
			lines = append(lines, describeFlag(f))
		}
		if len(lines) == 0 {
			continue
		}
		fmt.Fprintf(out, "%s\n%s\n\n", g.title, strings.Join(lines, "\n"))
	}

	var rest []string
	flag.VisitAll(func(f *flag.Flag) {
		if !claimed[f.Name] {
			rest = append(rest, describeFlag(f))
		}
	})
	if len(rest) > 0 {
		sort.Strings(rest)
		fmt.Fprintf(out, "Other\n%s\n\n", strings.Join(rest, "\n"))
	}

	fmt.Fprintf(out, "Environment\n"+
		"  TLSMASK_UI_ADDR, TLSMASK_DATA_DIR\n"+
		"      Defaults for the matching flags, so a container needs no command.\n\n"+
		"Everything else (the fingerprint, the upstream proxies, the timeouts and\n"+
		"the session rules) is configured in the web UI and stored in --data-dir.\n")
}

func describeFlag(f *flag.Flag) string {
	name, _ := flag.UnquoteUsage(f)
	head := "  --" + f.Name
	if name != "" {
		head += " " + name
	}

	body := f.Usage
	if f.DefValue != "" && f.DefValue != "false" && f.DefValue != "0" && f.DefValue != "0s" {
		body += fmt.Sprintf(" (default %s)", f.DefValue)
	}
	return head + "\n      " + body
}

func envOr(name, fallback string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}
	return fallback
}
