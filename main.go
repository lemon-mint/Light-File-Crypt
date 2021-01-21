package main

import (
	"bufio"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"

	"github.com/lemon-mint/LEA/golea"
)

func main() {
	output, err := os.OpenFile("test.lfc", os.O_CREATE, os.ModeAppend)
	if err != nil {
		fmt.Println(err)
		return
	}
	bc, _ := golea.NewCipher([]byte("mysuperstrongencryptionkey000000"))
	f, err := os.Open("1000MB.bin")
	if err != nil {
		return
	}
	defer f.Sync()
	encryptFileCBC(f, output, bc, make([]byte, 16))
}

func encryptFileCBC(input io.Reader, output io.Writer, bc cipher.Block, iv []byte) error {
	EncBuf := make([]byte, 16)
	EncryptedBuf := make([]byte, 16)
	r := bufio.NewReaderSize(input, 1024*1024*10)
	w := bufio.NewWriterSize(output, 1024*1024*10)
	defer w.Flush()

	w.Write(iv)
	for {
		n, err := r.Read(EncBuf)
		if err == io.EOF {
			EncBuf = make([]byte, 16)
			io.ReadFull(rand.Reader, EncBuf)
			EncBuf[15] = 16
			for i := range EncBuf {
				EncBuf[i] = EncBuf[i] ^ iv[i]
			}
			bc.Encrypt(EncryptedBuf, EncBuf)
			copy(iv, EncryptedBuf)
			w.Write(EncryptedBuf)
			break
		}
		if err != nil {
			return err
		}
		if n == 16 {
			for i := range EncBuf {
				EncBuf[i] = EncBuf[i] ^ iv[i]
			}
			bc.Encrypt(EncryptedBuf, EncBuf)
			copy(iv, EncryptedBuf)
			w.Write(EncryptedBuf)
		} else {
			randbuf := make([]byte, 16)
			tmp := make([]byte, n)
			copy(tmp, EncBuf)
			EncBuf = make([]byte, 16)
			copy(EncBuf, tmp)
			io.ReadFull(rand.Reader, randbuf)
			for i := n; i < 16; i++ {
				EncBuf[i] = randbuf[i]
			}
			EncBuf[15] = byte(16 - n)
			for i := range EncBuf {
				EncBuf[i] = EncBuf[i] ^ iv[i]
			}
			bc.Encrypt(EncryptedBuf, EncBuf)
			copy(iv, EncryptedBuf)
			w.Write(EncryptedBuf)
			break
		}
	}
	return nil
}
