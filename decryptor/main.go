package main

import (
	decryptor "breakend-decryptor/internal/chacha20"
	"embed"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/charmbracelet/log"
)

//go:embed private.pem
var privKey embed.FS

var sem chan struct{}

func readPEMfile() ([]byte, error) {
	file, err := privKey.ReadFile("private.pem")
	if err != nil {
		log.Error("Error reading file: ", err)
		return nil, err
	}
	return file, nil
}

func init() {
	sem = make(chan struct{}, runtime.NumCPU()*2)
}

func decryptFile(path string, privRsaKeyBytes []byte, wg *sync.WaitGroup) {
	defer wg.Done()
	sem <- struct{}{}
	defer func() { <-sem }()
	file, err := os.Stat(path)
	if err != nil {
		log.Error("Error reading file:", err)
		return
	}

	fileSize := file.Size()

	switch {
	case fileSize < 1400000:
		log.Warn("Decrypting file with T1...")
		err = decryptor.DecryptFileT1(path, privRsaKeyBytes)
	case fileSize >= 1400000 && fileSize <= 5300000:
		log.Warn("Decrypting file with T2...")
		err = decryptor.DecryptFileT2(path, privRsaKeyBytes)
	case fileSize > 5300000:
		log.Warn("Decrypting file with T3...")
		err = decryptor.DecryptLargeFile(path, 50, privRsaKeyBytes)
	}

	if err != nil {
		log.Error("Error decrypting file", err)
	} else {
		log.Info("File decrypted")
		log.Debug("File: ", path)
	}
}

func decryptDirectory(path string, privRsaKeyBytes []byte) error {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return err
	}

	if !fileInfo.IsDir() {
		if strings.HasSuffix(path, ".encrypted") {
			var wg sync.WaitGroup
			wg.Add(1)
			go decryptFile(path, privRsaKeyBytes, &wg)
			wg.Wait()
		} else {
			log.Warn("File is not encrypted: ", path)
		}
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
			if !strings.HasSuffix(file.Name(), ".encrypted") {
				continue
			}
			wg.Add(1)
			go decryptFile(path+"/"+file.Name(), privRsaKeyBytes, &wg)
		}
	}

	wg.Wait()

	for _, dir := range dirs {
		err = decryptDirectory(path+"/"+dir.Name(), privRsaKeyBytes)
		if err != nil {
			return err
		}
	}

	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: breakend-decryptor <directory|filePath>")
		os.Exit(1)
	}

	var path = os.Args[1]

	privRsaKeyBytes, err := readPEMfile()
	if err != nil {
		log.Fatal("Error reading private key: ", err)
	}

	err = decryptDirectory(path, privRsaKeyBytes)
	if err != nil {
		log.Fatal("Error decrypting directory: ", err)
	}

}
