// Command drs-encrypt seals a plaintext file into an at-rest envelope: the
// form a filesystem dataset root must hold when the DRS server runs with
// -encryption at-rest (architecture.md § "storage backend と暗号化").
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ddbj/humandbs-drs/internal/buildinfo"
	"github.com/ddbj/humandbs-drs/internal/encryption"
)

const toolName = "drs-encrypt"

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, toolName+":", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet(toolName, flag.ContinueOnError)
	fs.SetOutput(stdout)
	fs.Usage = func() {
		_, _ = fmt.Fprintln(stdout, "usage: "+toolName+" -key-file <path> <src> <dst>")
		fs.PrintDefaults()
	}
	showVersion := fs.Bool("version", false, "print version and exit")
	keyFile := fs.String("key-file", "", "hex file of the 32-byte at-rest key (required)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}

		return err
	}

	if *showVersion {
		_, err := fmt.Fprintln(stdout, toolName+" "+buildinfo.String())

		return err
	}

	if *keyFile == "" {
		return errors.New("key-file is required")
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("expected <src> and <dst> arguments, got %d", fs.NArg())
	}

	key, err := encryption.ReadKeyFile(*keyFile)
	if err != nil {
		return err
	}
	enc, err := encryption.NewAtRest(key, encryption.DefaultChunkSize)
	if err != nil {
		return err
	}

	return encryptFile(enc, fs.Arg(0), fs.Arg(1))
}

// encryptFile seals srcPath into a freshly created dstPath. It refuses to
// overwrite an existing destination, and removes a partly written one on
// failure, so a dataset root never holds a truncated envelope.
func encryptFile(enc *encryption.AtRest, srcPath, dstPath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()

	dst, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if err := enc.Encrypt(dst, src); err != nil {
		_ = dst.Close()
		_ = os.Remove(dstPath)

		return err
	}
	if err := dst.Close(); err != nil {
		_ = os.Remove(dstPath)

		return err
	}

	return nil
}
