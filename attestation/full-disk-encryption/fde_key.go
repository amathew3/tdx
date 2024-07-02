package main

import (
    "log"
    "os"
    "fmt"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "encoding/base64"
    "io/ioutil"
    "crypto/x509"
    "encoding/pem"
    //"encoding/binary"
)

func main() {

    if len(os.Args) != 4{
        panic("provide input wrapped_key,wrapped_swk,private key file")
    }
    label := []byte("")
    hash := sha256.New()

    wrapped_key_str:=os.Args[1]
    wrapped_swk_str:=os.Args[2]
    private_key_path:=os.Args[3]

    wrapped_swk_bytes, err := base64.StdEncoding.DecodeString(wrapped_swk_str)
    if err != nil {
        panic(err)
    }
     wrapped_key_bytes, err := base64.StdEncoding.DecodeString(wrapped_key_str)
    if err != nil {
        panic(err)
    }

    privateKeyBytes, err := ioutil.ReadFile(private_key_path)
    if err != nil {
        panic(err)
    }

    block, _ := pem.Decode(privateKeyBytes)
    if block == nil || block.Type != "RSA PRIVATE KEY" {
        panic("failed to decode PEM block containing private key")
    }

    privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
        panic(err)
    }

    swk, err := rsa.DecryptOAEP(hash, rand.Reader, privateKey, wrapped_swk_bytes, label)
    if err != nil {
        panic(err)
    }
    fdeKey, err := Decrypt(swk, wrapped_key_bytes[12:])
    fmt.Printf("FDE Key: %x\n",fdeKey) 

}

func Decrypt(key, cipherText []byte) ([]byte, error) {

        block, err := aes.NewCipher(key)
        if err != nil {
                panic("Error initializing cipher")
        }

        gcm, err := cipher.NewGCM(block)
        if err != nil {
                panic("Error creating a cipher block")
        }

        nonceSize := gcm.NonceSize()
        if len(cipherText) < nonceSize {
                panic("Invalid cipher text")
        }

        nonce, cipherText := cipherText[:nonceSize], cipherText[nonceSize:]
        plainText, err := gcm.Open(nil, nonce, cipherText, nil)
        if err != nil {
                                log.Fatalf("%s\n", err)
                panic("Error decrypting data")
        }

        return plainText, nil
}

