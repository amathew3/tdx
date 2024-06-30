package main

import (
        "crypto/rand"
        "crypto/rsa"
//      "crypto/tls"
        "crypto/x509"
//      "crypto/x509/pkix"
//      "encoding/base64"
        "encoding/binary"
        "encoding/pem"
        "fmt"
//      "math/big"
//      "net"
//      "net/http"
        "os"
//      "path/filepath"
//      "strings"
//      "syscall"
//      "time"
//        "io/ioutil"
)
func main() {
    // Generate a 2048-bit private key with exponent 3.
   /* privateKey, publicKeyBytes, err := generateKeyPair()
    if err != nil {
        panic(err)
    }*/

    privateKey, err := rsa.GenerateKey(rand.Reader, 3072) //rsa.GenerateMultiPrimeKey(rand.Reader, 2, 2048)
    if err != nil {
        panic(err)
    }
//    privateKey.E = 3

    // Derive the corresponding public key.
    publicKey := &privateKey.PublicKey
    fmt.Printf("Public key: %d\n", publicKey.N.Bytes());
    // Save the private key to a file.
//    privateKey.E = 3
//    publicKey.E = 3
    privateKeyFile, err := os.Create("private.pem")
    if err != nil {
        panic(err)
    }
    defer privateKeyFile.Close()

    privateKeyPEM := &pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
    }
    if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
        panic(err)
    }

    // Save the public key to a file.
    publicKeyFile, err := os.Create("public.pem")
    if err != nil {
        panic(err)
    }
    defer publicKeyFile.Close()

    /*publicKeyBytes, err := x509.MarshalPKCS1PublicKey(publicKey)
    if err != nil {
        panic(err)
    }*/
    publicKeyPEM := &pem.Block{
        Type:  "RSA PUBLIC KEY",
        Bytes: x509.MarshalPKCS1PublicKey(publicKey),
    }
    /*if err := ioutil.WriteFile("public_user_data.txt", publicKeyBytes, 0644); err != nil {
        panic(err)
    }*/
    /*
    publicKeyPEM := &pem.Block{
        Type:  "RSA PUBLIC KEY",
        Bytes: publicKeyBytes,
    }*/

    if err := pem.Encode(publicKeyFile, publicKeyPEM); err != nil {
        panic(err)
    }

    fmt.Println("Private and public keys have been generated and saved to files.")
}
func generateKeyPair() (*rsa.PrivateKey, []byte, error) {
        keyPair, err := rsa.GenerateKey(rand.Reader, 2048)
//      defer ZeroizeRSAPrivateKey(keyPair)
        if err != nil {
//              return nil, nil, errors.Wrap(err, "error while generating RSA key pair")
        panic(err)
}

        // Public key format : <exponent:E_SIZE_IN_BYTES><modulus:N_SIZE_IN_BYTES>
        pub := keyPair.PublicKey
        pubBytes := make([]byte, 4)
        binary.LittleEndian.PutUint32(pubBytes, uint32(pub.E))
        pubBytes = append(pubBytes, pub.N.Bytes()...)
        return keyPair, pubBytes, nil
}
