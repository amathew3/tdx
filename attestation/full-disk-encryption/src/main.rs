#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(warnings)]
use anyhow::{Ok, Result};
//use base64::{engine::general_purpose, Engine as _};
use clap::Parser;
//use zeroize::Zeroize;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE, ACCEPT};
use reqwest::Client;
use serde_json::Value;
mod quote;
use quote::retrieve_quote;
use sha2::{Sha512, Digest};
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey,/* EncodeRsaPrivateKey, EncodeRsaPublicKey*/},
    traits::{/*PrivateKeyParts,*/ PublicKeyParts},
    RsaPrivateKey, RsaPublicKey, Oaep , sha2::Sha256
};
//use rand::rngs::OsRng;
use aes_gcm::Aes256Gcm; // Or `Aes128Gcm`
use aes_gcm::aead::{Aead, NewAead, generic_array::GenericArray};
//use rand::Rng;

//use rsa::pkcs1::LineEnding;

mod ovmf_var;
use ovmf_var::retrieve_kbs_params;

//mod key_broker;
//use key_broker::retreive_key_from_kbs;

mod disk;
use disk::{crypt_setup, KEY_LENGTH};

//use crate::key_broker::RetrieveKeyRequest;

mod td_report;

#[derive(Parser)]
struct Args {
    // Boot partition with rootfs
    #[arg(short, long)]
    root: String,
    // rootfs name
    #[arg(short, long)]
    name: String,
}

#[tokio::main(worker_threads = 1)]
async fn main() -> Result<()> {
    let args = Args::parse();
    let root = args.root;
    let name: String = args.name;

    // 1. get secret

    let secret = retrieve_kbs_params()?;
    let url = String::from_utf8(secret.url)?;
    println!("KBS Parmas Retrieved!");
    
    // 2. get the nonce from trustauthority end point

    let mut headers = HeaderMap::new();
    headers.insert("x-api-key", HeaderValue::from_static("aeKQBT22ux7tZVB1uLyQN58Z1M9J0Bwg8LAQgLpl"));
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    let client = Client::builder()
        .danger_accept_invalid_certs(true) // Accept invalid certificates
        .build()?;

    let trust_url = "https://api.trustauthority.intel.com/appraisal/v1/nonce";
    let res = client.get(trust_url)
        .headers(headers)
        .send()
        .await?;
    //println!("Response: {:?}", res);

    // read the response as json
    let verifier_nonce: Value = res.json().await?;
    //println!("json: {:?}", verifier_nonce);

       // print json keys and values
    //for (key, value) in verifier_nonce.as_object().unwrap() {
    //    println!("{}: {}", key, value);
    //}
    // Parse the nonce response.

    let iat = base64::decode(verifier_nonce["iat"].as_str().unwrap())?;
    let val = base64::decode(verifier_nonce["val"].as_str().unwrap())?;
    //println!("iat: {:?}", iat);
    //println!("val: {:?}", val);
    // append iat and val to form verifier_nonce_bytes

    let mut verifier_nonce_bytes = Vec::new();
    verifier_nonce_bytes.extend_from_slice(&val);
    verifier_nonce_bytes.extend_from_slice(&iat);
    //println!("Nonce bytes {:?}", verifier_nonce_bytes);

    let public_key = RsaPublicKey::read_pkcs1_pem_file("/etc/public.pem").unwrap();
    //println!("Public key modulus: {:?}, size {:?}", public_key.n(), public_key.size());

    // Convert public_key modulus to byte array
    let modulus = public_key.n().to_bytes_be();
    //println!("Public key modulus: {:?}", modulus);

    // Copy exponent of public key to a 32 bit array in little endian format
    let mut exponent_le = [0u8; 4];
    let exponent_bytes = public_key.e().to_bytes_le();
    exponent_le[..exponent_bytes.len()].copy_from_slice(&exponent_bytes);
    //println!("Public key exponent: {:?}", exponent_le);

    // Append modulus to exponent_le
    let mut key = vec![0u8; 4 + modulus.len()];
    key[..4].copy_from_slice(&exponent_le);
    key[4..].copy_from_slice(&modulus);
    //println!("Public key: {:?}", key);
    
    // Convert key to base64
    let key_base64 = base64::encode(&key);
    //println!("Public key base64: {:?}", key_base64);   

    let mut hasher = Sha512::new();
    hasher.update(&verifier_nonce_bytes);
    hasher.update(&key);
    

    // Read hash digest and consume hasher
    let userdata_td = hasher.finalize();
    //println!("SHA-512 hash: {:?}", userdata_td);

    let mut userdata_td_u8 = [0u8; 64];
    userdata_td_u8.copy_from_slice(&userdata_td);
    //println!("Report data: {:?}", userdata_td_u8);

   // 3. Get the quote 

    let quote = retrieve_quote(&userdata_td_u8)?;
    //println!("Quote Bytes: {:?}", quote);
    //println!("Quote_64: {}", base64::encode(&quote));
    
    //4. Get the token

    let mut headers = HeaderMap::new();
    headers.insert("x-api-key", HeaderValue::from_static("aeKQBT22ux7tZVB1uLyQN58Z1M9J0Bwg8LAQgLpl"));
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(ACCEPT, HeaderValue::from_static("application/json")); 
    
    let data = format!(r#"{{"quote":"{}","verifier_nonce":{},"runtime_data":"{}"}}"#, base64::encode(&quote), verifier_nonce, key_base64);
    let data = data.replace("\n", "");
    //println!("data: {}", data);
    let client = Client::builder()
        .danger_accept_invalid_certs(true) // Accept invalid certificates
        .build()?;

    let trust_url = "https://api.trustauthority.intel.com/appraisal/v1/attest";

    let res = client.post(trust_url)
        .headers(headers)
        .body(data)
        .send()
        .await?;

    //println!("Response: {:?}", res);

    let itaToken: Value = res.json().await?;
    let transfer_data = format!(r#"{{"attestation_token":"{}"}}"#, itaToken["token"].as_str().unwrap());

    let mut headers = HeaderMap::new();
    headers.insert("Attestion-type", HeaderValue::from_static("TDX"));
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    //println!("unwrapped token {}", transfer_data);

    let client = Client::builder()
       .danger_accept_invalid_certs(true) // Accept invalid certificates
       .build()?;

    let res = client.post(url)
        .headers(headers)
        .body(transfer_data)
        .send()
        .await?;

    if res.status() != 200 {
        println!("Get key request failed, Error: {:?}", res.status());
        return Ok(());
    }
    //println!("Response: {:?}", res);
    
    
    let json: Value = res.json().await?;
    let wrapped_key = base64::decode(json["wrapped_key"].as_str().unwrap())?;
    let wrapped_key_bytes = wrapped_key.as_slice();
    //println!("wrapped_key: {:?}, length {:?}", wrapped_key_bytes, wrapped_key_bytes.len());
    let wrapped_swk = base64::decode(json["wrapped_swk"].as_str().unwrap())?;
    let wrapped_swk_bytes = wrapped_swk.as_slice();
    //println!("wrapped_swk: {:?} length {:?}", wrapped_swk_bytes, wrapped_swk_bytes.len());
    

    let padding = Oaep::new::<Sha256>();
    let private_key = RsaPrivateKey::read_pkcs1_pem_file("/etc/private.pem").unwrap();//expect("Failed to read public key");
    let dec_data = private_key.decrypt(padding, &wrapped_swk_bytes).expect("failed to decrypt");
    //println!("SWK {:?}, Length {:?}", dec_data, dec_data.len());

    let mut rng = rand::thread_rng();
    let key = GenericArray::from_slice(&dec_data);
    // Create cipher instance

    let cipher = Aes256Gcm::new(key);
    let copied_array: &[u8] = &wrapped_key_bytes[12..]; 
    const nonce_len: usize = 12;
    let ciphertext: &[u8] = &copied_array[nonce_len..];
    let nonce: &[u8] = &copied_array[..nonce_len];
    
    let nonce = GenericArray::from_slice(&nonce);
   // println!("nonce: {:?}", nonce);
   // println!("ciphertext: {:?}", ciphertext);
   // println!("Nonce length is {:?}, length of wrapped key bytes after removing nonce {:?}", nonce.len(), ciphertext.len());
    let FDEKeyBytes = cipher.decrypt(nonce, ciphertext.as_ref()).expect("decryption failure!");
    //println!("FDE Key Bytes {:?}", FDEKeyBytes);
    let  mut hex: Vec<String> = FDEKeyBytes.iter().map(|n| format!("{:02x}", n)).collect();
    let  mut key_string = hex.join("");

    println!("Encryption Key Retrieved!");

    // 4. disk
    //println!(" Length {:?}",key.len());

    if key.len() != KEY_LENGTH {
        panic!("FDE Key not Support!");
    }
    let mut  key=key_string.as_bytes();
    crypt_setup(root.to_string(), name.to_string(), &key);
    //key.zeroize();

    Ok(())
 
}
