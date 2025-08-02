package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/r4lrgx/DPUnlock/DPAPI"
)

func main() {
	var inputB64, entropyB64, scopeStr string
	flag.StringVar(&inputB64, "input", "", "Base64-encoded encrypted data")
	flag.StringVar(&entropyB64, "entropy", "", "Base64-encoded optional entropy")
	flag.StringVar(&scopeStr, "scope", "CurrentUser", "Scope: CurrentUser or LocalMachine")
	flag.Parse()

	if inputB64 == "" {
		fmt.Fprintln(os.Stderr, "Error: --input is required")
		flag.Usage()
		os.Exit(1)
	}

	encryptPass, err := base64.StdEncoding.DecodeString(inputB64)
	check("Failed to decode input:", err)

	var entropy []byte
	if entropyB64 != "" {
		entropy, err = base64.StdEncoding.DecodeString(entropyB64)
		check("Failed to decode entropy:", err)
	}

	scope, err := DPAPI.ParseScope(scopeStr)
	check("Invalid scope:", err)

	plaintext, err := DPAPI.Unprotect(encryptPass, entropy, scope)
	check("Decryption failed:", err)

	fmt.Print(base64.StdEncoding.EncodeToString(plaintext))
}

func check(msg string, err error) {
	if err != nil {
		log.Fatalf("%s %v\n", msg, err)
	}
}
