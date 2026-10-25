// Command jade-mock runs a software stand-in for a Blockstream Jade over TCP,
// for testing age-plugin-jade without hardware:
//
//	jade-mock -listen 127.0.0.1:30121 &
//	JADE_PORT=tcp:127.0.0.1:30121 age-plugin-jade --generate
//
// It is NOT secure: the seed lives in process memory. Never use a real
// mnemonic with it.
package main

import (
	"flag"
	"log"
	"net"

	"github.com/alex27riva/age-plugin-jade/internal/mockjade"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:30121", "TCP address to listen on")
	mnemonic := flag.String("mnemonic", mockjade.TestMnemonic, "BIP-39 mnemonic (TEST VALUES ONLY)")
	passphrase := flag.String("passphrase", "", "BIP-39 passphrase")
	decline := flag.Bool("decline", false, "simulate the user declining every confirmation")
	testnet := flag.Bool("testnet", false, "wallet locked to testnet networks")
	flag.Parse()

	j := mockjade.New(*mnemonic, *passphrase)
	defer j.Close()
	j.Decline = *decline
	if *testnet {
		j.Networks = "TEST"
	}
	l, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("mock Jade listening on %s (use JADE_PORT=tcp:%s)", l.Addr(), l.Addr())
	log.Fatal(j.Serve(l))
}
