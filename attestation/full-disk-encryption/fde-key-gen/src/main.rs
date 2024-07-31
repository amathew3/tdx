#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(warnings)]
use anyhow::{Ok, Result};
use clap::Parser;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE, ACCEPT};
use reqwest::Client;
use serde_json::Value;
use sha2::{Sha512, Digest};
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey,/* EncodeRsaPrivateKey, EncodeRsaPublicKey*/},
    traits::{/*PrivateKeyParts,*/ PublicKeyParts},
    RsaPrivateKey, RsaPublicKey, Oaep , sha2::Sha256
};
use aes_gcm::Aes256Gcm; // Or `Aes128Gcm`
use aes_gcm::aead::{Aead, NewAead, generic_array::GenericArray};

#[derive(Parser)]
struct Args {
    // key transfer link
    #[arg(short, long)]
    transfer_link: String,
    // quote bytes
    #[arg(short, long)]
    quote_bytes: String,
    // kbs url 
    #[arg(short, long)]
    url: String,
}


#[tokio::main(worker_threads = 1)]
async fn main() -> Result<()> {
    let args = Args::parse();
    let transfer_link: String = args.transfer_link;
    let quote_bytes: String = args.quote_bytes;
    let url: String = args.url;

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
    println!("Public key: {:?}", key);
    
    // Convert key to base64
    let key_base64 = base64::encode(&key);
    println!("Public key base64: {:?}", key_base64);   

    let mut hasher = Sha512::new();
    //hasher.update(&verifier_nonce_bytes);
    hasher.update(&key);
    

    // Read hash digest and consume hasher
    let userdata_td = hasher.finalize();
    //println!("SHA-512 hash: {:?}", userdata_td);

    let mut userdata_td_u8 = [0u8; 64];
    userdata_td_u8.copy_from_slice(&userdata_td);
    println!("Report data: {:?}", userdata_td_u8);

   // 3. Get the quote 

   let data = format!(r#"{{"quote":"{}","user_data":"{}"}}"#, quote_bytes,  key_base64);
   let data = data.replace("\n", "");
  // println!("data: {}", data);

    let mut headers = HeaderMap::new();
    headers.insert("Attestation-type", HeaderValue::from_static("TDX"));
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    //println!("unwrapped token {}", transfer_data);
    //let ca_cert = reqwest::Certificate::from_pem(&cert)?;
    //let client = Client::builder().add_root_certificate(ca_cert)
    let client = Client::builder()
       .danger_accept_invalid_certs(true)
       //.use_rustls_tls()
       .build()?;
    let act_url=url+&transfer_link;
    let res = client.post(act_url)
        .headers(headers)
        .body(data)
        .send()
        .await?;

    if res.status() != 200 {
        println!("Get key request failed, Error: {:?}", res.status());
        return Ok(());
    }
    println!("Response: {:?}", res);
    
    
    let json: Value = res.json().await?;
    let wrapped_key = base64::decode(json["wrapped_key"].as_str().unwrap())?;
    let wrapped_key_bytes = wrapped_key.as_slice();
    println!("wrapped_key: {:?}, length {:?}", wrapped_key_bytes, wrapped_key_bytes.len());
    let wrapped_swk = base64::decode(json["wrapped_swk"].as_str().unwrap())?;
    let wrapped_swk_bytes = wrapped_swk.as_slice();
    println!("wrapped_swk: {:?} length {:?}", wrapped_swk_bytes, wrapped_swk_bytes.len());
    

    let padding = Oaep::new::<Sha256>();
    //get_private_key_bytes(); Implement the logic to get the private.pem file content here.
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
    let FDEKeyBytes = cipher.decrypt(nonce, ciphertext.as_ref()).expect("decryption failure!");
    //println!("FDE Key Bytes {:?}", FDEKeyBytes);
    let  mut hex: Vec<String> = FDEKeyBytes.iter().map(|n| format!("{:02x}", n)).collect();
    let  mut key_string = hex.join("");
    println!("Encryption Key Retrieved!");
    println!("FDE Key Bytes {:?}", key_string);
    Ok(())
}
