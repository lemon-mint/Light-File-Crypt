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
	f, err := os.Open("test.txt")
	if err != nil {
		return
	}
	encryptFileCBC(f, output, bc, make([]byte, 16))
}

func encryptFileCBC(input *os.File, output *os.File, bc cipher.Block, iv []byte) error {
	EncBuf := make([]byte, 16)
	EncryptedBuf := make([]byte, 16)
	w := bufio.NewWriterSize(output, 1024*1024*10)
	defer w.Flush()
	defer output.Sync()

	input.Write(iv)
	for {
		n, err := input.Read(EncBuf)
		if err != nil {
			return err
		}
		if n == 16 {
			for i := range EncBuf {
				EncBuf[i] = EncBuf[i] ^ iv[i]
			}
			copy(iv, EncryptedBuf)
			w.Write(EncryptedBuf)
		} else {
			randbuf := make([]byte, 16)
			tmp := make([]byte, n)
			copy(tmp, EncBuf)
			EncBuf = make([]byte, 16)
			copy(EncBuf, tmp)
			for i := n; i < 16; i++ {
				io.ReadFull(rand.Reader, randbuf)
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
