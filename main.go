package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {

	inputMode := flag.String("input", "cli", "file or stdin or cli")
	outputMode := flag.String("output", "cli", "file or stdout or cli")
	opMode := flag.String("op", "", "encrypt or decrypt")
	stdKey := flag.String("key", "", "Key used for encryption")
	flag.Parse()

	mode := -1
	filename := ""
	if *inputMode == "cli" {
		fmt.Println("Light-File-Crypt")
		fmt.Println("MIT License Copyright (c) 2021 lemon-mint")
		fmt.Println()
		fmt.Println("Please select an operation mode")
		fmt.Println("0. Encrypt")
		fmt.Println("1. Decrypt")
		fmt.Print("mode >>")
		fmt.Scanln(&mode)
		fmt.Println()
		if mode == 0 {
			fmt.Println("Please enter the file to be encrypted")
			fmt.Print("file >>")
			fmt.Scanln(&filename)
			fmt.Println()
			if _, err := os.Stat(filename + ".lfc"); err == nil {
				fmt.Printf("File %s already exists.", filename+".lfc")
				return
			}
			fmt.Println("Please enter the encryption key")
			fmt.Print("key >>")
			keyString, err := terminal.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			salt := make([]byte, 32)
			io.ReadFull(rand.Reader, salt)
			fmt.Println("Hashing")
			key := argon2.IDKey(keyString, salt, 32, 64*1024, 2, 32)

			io.ReadFull(rand.Reader, keyString)
			io.ReadFull(rand.Reader, keyString)
			io.ReadFull(rand.Reader, keyString)
			io.ReadFull(rand.Reader, keyString)
			io.ReadFull(rand.Reader, keyString)
			defer io.ReadFull(rand.Reader, key)
			defer io.ReadFull(rand.Reader, key)
			defer io.ReadFull(rand.Reader, key)
			defer io.ReadFull(rand.Reader, key)
			defer io.ReadFull(rand.Reader, key)

			bc, _ := aes.NewCipher(key)
			f, err := os.Open(filename)
			if err != nil {
				fmt.Println("File Open Error")
				return
			}
			output, err := os.OpenFile(filename+".lfc", os.O_CREATE, os.ModeAppend)
			defer output.Sync()
			if err != nil {
				fmt.Println(err)
				return
			}

			iv := make([]byte, 16)
			io.ReadFull(rand.Reader, iv)
			fmt.Println("Encryption is in progress. Please wait patiently.")
			encryptFileCBC(f, output, bc, iv, salt)
			return
		} else if mode == 1 {
			fmt.Println("Please enter the file to be decrypted")
			fmt.Print("file >>")
			fmt.Scanln(&filename)
			fmt.Println()
			if !strings.HasSuffix(filename, ".lfc") {
				fmt.Println("The file must have a .lfc extension.")
				return
			}
			if _, err := os.Stat(filename[:len(filename)-4]); err == nil {
				fmt.Printf("File %s already exists.", filename[:len(filename)-4])
				return
			}
			fmt.Println("Please enter the encryption key")
			fmt.Print("key >>")
			keyString, err := terminal.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			salt := make([]byte, 32)

			fmt.Println("Hashing")

			f, err := os.Open(filename)
			if err != nil {
				fmt.Println("File Open Error")
				return
			}
			defer f.Sync()
			output, err := os.OpenFile(filename[:len(filename)-4], os.O_CREATE, os.ModeAppend)
			if err != nil {
				fmt.Println(err)
				return
			}
			f.Read(salt)

			key := argon2.IDKey(keyString, salt, 32, 64*1024, 2, 32)
			io.ReadFull(rand.Reader, keyString)
			io.ReadFull(rand.Reader, keyString)
			io.ReadFull(rand.Reader, keyString)
			io.ReadFull(rand.Reader, keyString)
			io.ReadFull(rand.Reader, keyString)
			defer io.ReadFull(rand.Reader, key)
			defer io.ReadFull(rand.Reader, key)
			defer io.ReadFull(rand.Reader, key)
			defer io.ReadFull(rand.Reader, key)
			defer io.ReadFull(rand.Reader, key)
			bc, _ := aes.NewCipher(key)

			iv := make([]byte, 16)
			io.ReadFull(rand.Reader, iv)
			fmt.Println("Decryption is in progress. Please wait patiently.")
			err = decryptFileCBC(f, output, bc)
			if err != nil {
				fmt.Println("Decryption Failed")
				fmt.Println(err)
				return
			}
			return
		}
	} else if *inputMode == "stdin" && *outputMode == "stdout" {
		if *opMode == "encrypt" || *opMode == "e" || *opMode == "enc" {
			keyString := []byte(*stdKey)
			salt := make([]byte, 32)
			io.ReadFull(rand.Reader, salt)
			key := argon2.IDKey(keyString, salt, 32, 64*1024, 2, 32)
			io.ReadFull(rand.Reader, keyString)
			defer io.ReadFull(rand.Reader, key)
			bc, _ := aes.NewCipher(key)
			f := os.Stdin
			output := os.Stdout
			defer output.Sync()

			iv := make([]byte, 16)
			io.ReadFull(rand.Reader, iv)
			encryptFileCBC(f, output, bc, iv, salt)
		} else if *opMode == "decrypt" || *opMode == "d" || *opMode == "dec" {
			keyString := []byte(*stdKey)

			f := os.Stdin
			salt := make([]byte, 32)
			f.Read(salt)
			output := os.Stdout
			defer output.Sync()
			key := argon2.IDKey(keyString, salt, 32, 64*1024, 2, 32)
			io.ReadFull(rand.Reader, keyString)
			defer io.ReadFull(rand.Reader, key)
			bc, _ := aes.NewCipher(key)
			iv := make([]byte, 16)
			io.ReadFull(rand.Reader, iv)
			decryptFileCBC(f, output, bc)
		}
	}
}

func encryptFileCBC(input io.Reader, output io.Writer, bc cipher.Block, iv, salt []byte) error {
	EncBuf := make([]byte, 16)
	EncryptedBuf := make([]byte, 16)
	r := bufio.NewReaderSize(input, 1024*1024*20)
	w := bufio.NewWriterSize(output, 1024*1024*20)
	defer w.Flush()

	w.Write(salt)
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

var errWrongSize = errors.New("Weong Size")

func decryptFileCBC(input io.Reader, output io.Writer, bc cipher.Block) error {
	r := bufio.NewReaderSize(input, 1024*1024*20)
	w := bufio.NewWriterSize(output, 1024*1024*20)
	defer w.Flush()
	iv := make([]byte, 16)
	n, err := r.Read(iv)
	if err != nil {
		return err
	}
	if n != 16 {
		return errWrongSize
	}
	Buf := make([]byte, 16)
	lastBuf := make([]byte, 16)
	isStart := true
	for {
		n, err := r.Read(Buf)
		if err == io.EOF {
			if lastBuf[15] < 16 {
				w.Write(lastBuf[0 : 16-int(lastBuf[15])])
				break
			} else if lastBuf[15] == 16 {
				break
			} else {
				return errWrongSize
			}
		}
		if err != nil {
			return err
		}
		if n != 16 {
			return errWrongSize
		}
		if !isStart {
			w.Write(lastBuf)
		}
		bc.Decrypt(lastBuf, Buf)
		for i := range lastBuf {
			lastBuf[i] = lastBuf[i] ^ iv[i]
		}
		copy(iv, Buf)
		if isStart {
			isStart = false
		}
	}
	return nil
}
