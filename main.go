// Command age-plugin-jade is an age plugin that uses a Blockstream Jade
// hardware wallet to protect age identities.
//
// The decryption key is a SLIP-0017 ECDH key on the P-256 curve, derived on
// the Jade from its wallet seed and an identity URI. It never leaves the
// device: encryption is fully offline using the public key, and decryption
// asks the Jade to compute an ECDH shared secret after on-screen confirmation.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/plugin"

	"github.com/alex27riva/age-plugin-jade/internal/version"
)

const usage = `age-plugin-jade: use a Blockstream Jade as an age identity.

Usage:
    age-plugin-jade --generate [--uri URI] [--index N] [-o OUTPUT]
    age-plugin-jade -y [IDENTITY_FILE...]
    age-plugin-jade --version

Options:
    --generate      Read a public key from the Jade and print an identity file
                    (identity files contain no secrets; the key stays on the Jade).
    --uri URI       Identity URI the key is derived from. Must start with ssh://
                    or gpg://. Default: ssh://age@jade
    --index N       Key index for the URI, to derive several keys. Default: 0
    -o OUTPUT       Write the identity file to OUTPUT instead of stdout.
    -y              Convert identity files (or stdin) to recipients. Offline.
    --port PORT     Serial port, or tcp:HOST:PORT for the Jade emulator.
                    Default: auto-detect, or $JADE_PORT.
    --network NET   mainnet or testnet, as the Jade wallet is locked to.
                    Default: mainnet, or $JADE_NETWORK.

Then encrypt and decrypt with age as usual:
    age -r age1jade1... -o secret.age secret.txt
    age -d -i jade-identity.txt secret.age > secret.txt

Environment (also used when age runs the plugin): JADE_PORT, JADE_NETWORK.`

func main() {
	fs := flag.NewFlagSet("age-plugin-jade", flag.ExitOnError)
	fs.Usage = func() { fmt.Fprintln(os.Stderr, usage) }

	p, err := plugin.New(pluginName)
	if err != nil {
		fatalf("%v", err)
	}
	p.RegisterFlags(fs)

	var (
		generateFlag = fs.Bool("generate", false, "")
		uriFlag      = fs.String("uri", "ssh://age@jade", "")
		indexFlag    = fs.Uint("index", 0, "")
		outFlag      = fs.String("o", "", "")
		toRecipient  = fs.Bool("y", false, "")
		portFlag     = fs.String("port", "", "")
		networkFlag  = fs.String("network", "", "")
		versionFlag  = fs.Bool("version", false, "")
	)
	fs.Parse(os.Args[1:])

	network := *networkFlag
	if network == "" {
		network = os.Getenv("JADE_NETWORK")
	}
	if network == "" {
		network = "mainnet"
	}

	if sm := fs.Lookup("age-plugin").Value.String(); sm != "" {
		os.Exit(runPlugin(p, *portFlag, network))
	}

	switch {
	case *versionFlag:
		fmt.Println(version.String())
	case *generateFlag:
		if *indexFlag > maxIndex {
			fatalf("--index must be at most %d", maxIndex)
		}
		generate(*uriFlag, uint32(*indexFlag), *outFlag, *portFlag, network)
	case *toRecipient:
		convert(fs.Args())
	default:
		fs.Usage()
		os.Exit(1)
	}
}

func runPlugin(p *plugin.Plugin, port, network string) int {
	sess := &deviceSession{
		port:    port,
		network: network,
		msg: func(m string) {
			if p.DisplayMessage(m) != nil {
				fmt.Fprintln(os.Stderr, "age-plugin-jade:", m)
			}
		},
	}
	defer sess.Close()

	p.HandleRecipient(func(data []byte) (age.Recipient, error) {
		return newRecipient(data)
	})
	p.HandleIdentityAsRecipient(func(data []byte) (age.Recipient, error) {
		k, err := parseIdentityPayload(data)
		if err != nil {
			return nil, err
		}
		return newRecipient(k.PubKey)
	})
	p.HandleIdentity(func(data []byte) (age.Identity, error) {
		k, err := parseIdentityPayload(data)
		if err != nil {
			return nil, err
		}
		return &Identity{key: k, device: func() (Device, error) { return sess, nil }}, nil
	})
	return p.Main()
}

func generate(uri string, index uint32, out, port, network string) {
	if err := validateURI(uri); err != nil {
		fatalf("%v", err)
	}
	sess := &deviceSession{port: port, network: network,
		msg: func(m string) { fmt.Fprintln(os.Stderr, m) }}
	defer sess.Close()

	pk, err := sess.PubKey(uri, index)
	if err != nil {
		fatalf("%v", err)
	}
	k := &jadeKey{URI: uri, Index: index, PubKey: pk}
	recipient := encodeRecipient(pk)

	w := io.Writer(os.Stdout)
	if out != "" {
		f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			fatalf("%v", err)
		}
		defer f.Close()
		w = f
	}
	fmt.Fprintf(w, "# created: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(w, "# jade identity: %s (index %d)\n", uri, index)
	fmt.Fprintf(w, "# public key: %s\n", recipient)
	fmt.Fprintf(w, "# This file holds no secret: the private key never leaves the Jade.\n")
	fmt.Fprintf(w, "# Losing it is fine as long as you remember the URI and index above;\n")
	fmt.Fprintf(w, "# regenerate it with: age-plugin-jade --generate --uri '%s' --index %d\n", uri, index)
	fmt.Fprintln(w, plugin.EncodeIdentity(pluginName, k.identityPayload()))
	if out != "" {
		fmt.Fprintf(os.Stderr, "Public key: %s\n", recipient)
	}
}

func convert(files []string) {
	read := func(r io.Reader, name string) {
		sc := bufio.NewScanner(r)
		n := 0
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			name2, data, err := plugin.ParseIdentity(line)
			if err != nil || name2 != pluginName {
				fatalf("%s: not an age-plugin-jade identity", name)
			}
			k, err := parseIdentityPayload(data)
			if err != nil {
				fatalf("%s: %v", name, err)
			}
			fmt.Println(encodeRecipient(k.PubKey))
			n++
		}
		if err := sc.Err(); err != nil {
			fatalf("%s: %v", name, err)
		}
		if n == 0 {
			fatalf("%s: no identities found", name)
		}
	}
	if len(files) == 0 {
		read(os.Stdin, "standard input")
		return
	}
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			fatalf("%v", err)
		}
		read(fh, f)
		fh.Close()
	}
}

func encodeRecipient(compressedPub []byte) string {
	return plugin.EncodeRecipient(pluginName, compressedPub)
}

func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "age-plugin-jade: error: "+format+"\n", a...)
	os.Exit(1)
}
