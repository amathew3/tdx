package main

import (
    "log"
    "os/exec"
    "os"
    "fmt"
    "strings"
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
    "net/http"
    "crypto/tls"
    "bytes"
    "io"

)

func main() {
    transferLink := os.Args[1]
    log.Printf("\ntransferlink = %s\n",transferLink)
    cmd := exec.Command("/sbin/trustauthority-cli", "token", "--config", "/etc/config.json", "--pub-path", "/etc/public.pem")

    output, err := cmd.Output()
    if err != nil {
        log.Fatalf("cmd.Output() failed with %s\n", err)
    }
    token_string := string(output)
    token_string = strings.TrimSuffix(token_string, "\n")
    transfer_link := strings.TrimSuffix(transferLink, "\n")

    tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }
    client := &http.Client{Transport: tr}
    
    type Payload struct {
            AttestationToken string `json:"attestation_token"`
    }
    
    data := Payload{
            AttestationToken: token_string,
    }
    
    payloadBytes, err := json.Marshal(data)
    if err != nil {
            // handle err
    }
    body := bytes.NewReader(payloadBytes)
    req, err := http.NewRequest("POST", transfer_link, body)
    if err != nil {
            log.Fatal(err)
	    panic(err)
    }
    req.Header.Set("Accept", "application/json")
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Attestion-Type", "\"TDX\"")
    
    resp, err := client.Do(req)
    if err != nil {
            // handle err
    }
    defer resp.Body.Close()
    var response []byte
    if resp.StatusCode == http.StatusOK {
        bodyBytes, err := io.ReadAll(resp.Body)
        if err != nil {
            log.Fatal(err)
        }
	response=bodyBytes
        log.Println(response)
    }

    var result map[string]interface{}
    json.Unmarshal(response, &result)

    label := []byte("")
    hash := sha256.New()
    wrapped_key := result["wrapped_key"]
    wrapped_swk := result["wrapped_swk"]


    wrapped_swk_str, ok := wrapped_swk.(string)
    if !ok {
        log.Println("wrapped_swk is not a string")
        return
    }

//    log.Println("wrapped_swk_str:", wrapped_swk_str)

    wrapped_swk_bytes, err := base64.StdEncoding.DecodeString(wrapped_swk_str)
    if err != nil {
        panic(err)
    }
    //log.Println("wrapped_swk_bytes \n", wrapped_swk_bytes)

        wrapped_key_str, ok := wrapped_key.(string)
    if !ok {
        log.Println("wrapped_key is not a string")
        return
    }
        wrapped_key_bytes, err := base64.StdEncoding.DecodeString(wrapped_key_str)
    if err != nil {
        panic(err)
    }
  //  log.Println("wrapped_key_bytes \n", wrapped_key_bytes)

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
    fdeKey, err := Decrypt(swk, wrapped_key_bytes[12:])
    //log.Printf("FDE Key Length: %d\n", len(fdeKey))
    //log.Printf("FDE Key: %x\n", string(fdeKey))
    f, err := os.Create("/tmp/test.txt")
	if err != nil {
		fmt.Println(err)
		return
	}
    _, err =f.Write([]byte(fmt.Sprintf("%x", string(fdeKey) )))
    err = f.Close()
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
