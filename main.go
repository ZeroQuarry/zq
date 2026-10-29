// Command zq is the ZeroQuarry companion CLI: it moves scan
// credentials to the platform without the web app and without the
// values ever entering agent context.
//
// Output contract: `zq creds add ...` prints ONLY the reference id on
// stdout; prompts, progress, and errors go to stderr.
package main

import (
	"context"
	"os"

	"github.com/ZeroQuarry/zq/internal/cli"
)

// version is set at build time: -ldflags "-X main.version=v0.1.0".
var version = "dev"

func main() {
	cli.Version = version
	os.Exit(cli.Main(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
