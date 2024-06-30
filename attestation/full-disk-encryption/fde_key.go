package main

import (
    "log"
    "os/exec"
    "os"
    "fmt"
    "strings"
 //   "time"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "encoding/json"
    "encoding/base64"
    "io/ioutil"
    "crypto/x509"
    "encoding/pem"
    "encoding/binary"
)

func main() {

    transfer_link := os.Args[1]
    log.Printf("\ntransferlink = %s\n",transfer_link)
    trusta_path := os.Args[2]
    log.Printf("\ntrustauthority-cli path = %s\n",trusta_path)
    gen_pub_pri_key()
    publicKeyPath := "public.pem"
   publicKey, err := os.ReadFile(publicKeyPath)
   if err != nil {
     log.Fatalf("Error reading public key from file", err)
   }
    publicKeyBlock, _ := pem.Decode(publicKey)
    if publicKeyBlock == nil {
       log.Fatalf("No PEM data found in public key file", err)
    }
    publicKey_user, err := x509.ParsePKCS1PublicKey(publicKeyBlock.Bytes)
    if err != nil {
         panic(err)
    }
    pubBytes := make([]byte, 4)
    binary.LittleEndian.PutUint32(pubBytes, uint32(publicKey_user.E))
    //fmt.Printf("exponent after conversion: %d", pubBytes);
    pubBytes = append(pubBytes, publicKey_user.N.Bytes()...)
    //fmt.Printf("userdatabytes:%d ", pubBytes)
    userDataBytes := base64.StdEncoding.EncodeToString(pubBytes)
    cmd := exec.Command(trusta_path+"/trustauthority-cli", "token", "--config", "config.json", "--pub-path", "public.pem", "-u", userDataBytes)

    output, err := cmd.Output()
    if err != nil {
        log.Fatalf("cmd.Output() failed with %s\n", err)
    }
    //fmt.Printf("Output: %s\n", output)
    token_string := string(output)
    token_string = strings.TrimSuffix(token_string, "\n")
    jsonData := `{"attestation_token":"`+ token_string +`"}`
    jsonData = strings.TrimSuffix(jsonData, "\n")
    attestationType := `Attestion-type: TDX`
    //fmt.Printf("JSON data being sent to transfer link is %s", jsonData)
    cmd2 := exec.Command("curl", "--insecure", "--location", transfer_link, "--header",
                attestationType, "--header", "Accept: application/json", "--header",
                "Content-type: application/json", "--data", jsonData)

    response, err := cmd2.Output()

    if err != nil {
        panic(err)
    }
    //println(string(response))

    var result map[string]interface{}
    json.Unmarshal(response, &result)

    label := []byte("")
    hash := sha256.New()
    wrapped_key := result["wrapped_key"]
    wrapped_swk := result["wrapped_swk"]


    wrapped_swk_str, ok := wrapped_swk.(string)
    if !ok {
        fmt.Println("wrapped_swk is not a string")
        return
    }


    wrapped_swk_bytes, err := base64.StdEncoding.DecodeString(wrapped_swk_str)
    if err != nil {
        panic(err)
    }
    //fmt.Println("wrapped_swk_bytes \n", wrapped_swk_bytes)

        wrapped_key_str, ok := wrapped_key.(string)
    if !ok {
        fmt.Println("wrapped_key is not a string")
        return
    }
        wrapped_key_bytes, err := base64.StdEncoding.DecodeString(wrapped_key_str)
    if err != nil {
        panic(err)
    }
    //fmt.Println("wrapped_key_bytes \n", wrapped_key_bytes)

    privateKeyBytes, err := ioutil.ReadFile("private.pem")
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
    //fmt.Println("swk: ", swk)
    fdeKey, err := Decrypt(swk, wrapped_key_bytes[12:])
    //fmt.Printf("FDE Key Length: %d\n", len(fdeKey))
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
func gen_pub_pri_key() {
    // Generate a 2048-bit private key with exponent 3.

    privateKey, err := rsa.GenerateKey(rand.Reader, 3072) //rsa.GenerateMultiPrimeKey(rand.Reader, 2, 2048)
    if err != nil {
        panic(err)
    }

    // Derive the corresponding public key.
    publicKey := &privateKey.PublicKey
    //fmt.Printf("Public key: %d\n", publicKey.N.Bytes());
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

    publicKeyPEM := &pem.Block{
        Type:  "RSA PUBLIC KEY",
        Bytes: x509.MarshalPKCS1PublicKey(publicKey),
    }

    if err := pem.Encode(publicKeyFile, publicKeyPEM); err != nil {
        panic(err)
    }

    fmt.Println("Private and public keys have been generated and saved to files.")
}
func generateKeyPair() (*rsa.PrivateKey, []byte, error) {
        keyPair, err := rsa.GenerateKey(rand.Reader, 2048)
        if err != nil {
                panic(err)
        }

        pub := keyPair.PublicKey
        pubBytes := make([]byte, 4)
        binary.LittleEndian.PutUint32(pubBytes, uint32(pub.E))
        pubBytes = append(pubBytes, pub.N.Bytes()...)
        return keyPair, pubBytes, nil
}

