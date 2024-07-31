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

   publicKeyPath := "/etc/public.pem"
/*   keyFilepath, err := ValidateFilePath(publicKeyPath)
   if err != nil {
      return errors.Wrap(err, "Invalid public key file path provided")
   }*/
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
    //publicKey_user := pubInterface.(*rsa.PublicKey)
    pubBytes := make([]byte, 4)
    binary.LittleEndian.PutUint32(pubBytes, uint32(publicKey_user.E))
    fmt.Printf("exponent after conversion: %d", pubBytes);
    pubBytes = append(pubBytes, publicKey_user.N.Bytes()...)
    fmt.Printf("userdatabytes:%d ", pubBytes)
    //userDataBytes = pubBytes //publicKeyBlock.Bytes
    userDataBytes := base64.StdEncoding.EncodeToString(pubBytes)
   // println(userDataBytes)
    cmd := exec.Command("trustauthority-cli", "token", "--config", "/etc/config.json", "--pub-path", "/etc/public.pem", "-u", userDataBytes)

    output, err := cmd.Output()
    if err != nil {
        log.Fatalf("cmd.Output() failed with %s\n", err)
    }
    fmt.Printf("Output: %s\n", output)
    token_string := string(output)
    token_string = strings.TrimSuffix(token_string, "\n")
    transfer_link := "https://192.168.6.4:9443/kbs/v1/keys/b8a5f372-5793-4e5a-87ef-7cf06edd15e8/transfer"
    jsonData := `{"attestation_token":"`+ token_string +`"}`
    jsonData = strings.TrimSuffix(jsonData, "\n")
    attestationType := `Attestion-type: TDX`
    fmt.Printf("JSON data being sent to transfer link is %s", jsonData)
    cmd2 := exec.Command("curl", "--insecure", "--location", transfer_link, "--header",
                attestationType, "--header", "Accept: application/json", "--header",
                "Content-type: application/json", "--data", jsonData)

    response, err := cmd2.Output()

    if err != nil {
        panic(err)
    }
    println(string(response))

    var result map[string]interface{}
    json.Unmarshal(response, &result)

    label := []byte("")
    hash := sha256.New()
    wrapped_key := result["wrapped_key"]
    wrapped_swk := result["wrapped_swk"]

    //fmt.Println("wrapped_key %x\n", wrapped_key)
    //fmt.Println("wrapped_swk %x\n", wrapped_swk)

    wrapped_swk_str, ok := wrapped_swk.(string)
    if !ok {
        fmt.Println("wrapped_swk is not a string")
        return
    }

    //fmt.Println("wrapped_swk_str:", wrapped_swk_str)

    wrapped_swk_bytes, err := base64.StdEncoding.DecodeString(wrapped_swk_str)
    if err != nil {
        panic(err)
    }
    fmt.Println("wrapped_swk_bytes \n", wrapped_swk_bytes)

        wrapped_key_str, ok := wrapped_key.(string)
    if !ok {
        fmt.Println("wrapped_key is not a string")
        return
    }
        wrapped_key_bytes, err := base64.StdEncoding.DecodeString(wrapped_key_str)
    if err != nil {
        panic(err)
    }
    fmt.Println("wrapped_key_bytes \n", wrapped_key_bytes)

    privateKeyBytes, err := ioutil.ReadFile("/etc/private.pem")
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
    fmt.Println("swk: ", swk)
    fdeKey, err := Decrypt(swk, wrapped_key_bytes[12:])
    fmt.Printf("FDE Key Length: %d\n", len(fdeKey))
    fmt.Printf("FDE Key: %x\n", string(fdeKey))

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
