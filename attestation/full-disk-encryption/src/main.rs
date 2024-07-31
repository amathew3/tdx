#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(warnings)]
use anyhow::{Ok, Result};
use clap::Parser;
//use zeroize::Zeroize;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE, ACCEPT};
use reqwest::Client;
use serde_json::Value;
use std::io::{Write}; // bring trait into scope

mod quote;
use quote::retrieve_quote;
use sha2::{Sha512, Digest};
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey,/* EncodeRsaPrivateKey, EncodeRsaPublicKey*/},
    traits::{/*PrivateKeyParts,*/ PublicKeyParts},
    RsaPrivateKey, RsaPublicKey, Oaep , sha2::Sha256
};
use aes_gcm::Aes256Gcm; // Or `Aes128Gcm`
use aes_gcm::aead::{Aead, NewAead, generic_array::GenericArray};

mod ovmf_var;
use ovmf_var::retrieve_kbs_params;


mod disk;
use disk::{crypt_setup, KEY_LENGTH};


mod td_report;

#[derive(Parser)]
struct Args {
    // Boot partition with rootfs
    #[arg(short, long)]
    root: String,
    // rootfs name
    #[arg(short, long)]
    name: String,
    // boot type
    #[arg(short, long)]
    boot_type: u8,
}

#[tokio::main(worker_threads = 1)]
async fn main() -> Result<()> {
    let args = Args::parse();
    let root = args.root;
    let name: String = args.name;
    let boot_type:u8 = args.boot_type;

    // 1. get secret

    let secret = retrieve_kbs_params()?;
    let url = String::from_utf8(secret.url)?;
    let mut cert = secret.certification;
    println!("KBS Parmas Retrieved!");
    

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
    hasher.update(&key);
    

    // Read hash digest and consume hasher
    let userdata_td = hasher.finalize();
    //println!("SHA-512 hash: {:?}", userdata_td);

    let mut userdata_td_u8 = [0u8; 64];
    userdata_td_u8.copy_from_slice(&userdata_td);
    //println!("Report data: {:?}", userdata_td_u8);

   // 3. Get the quote 

    let quote = retrieve_quote(&userdata_td_u8,boot_type)?;
    //println!("Quote Bytes: {:?}", quote);
    //println!("Quote_64: {}", base64::encode(&quote));
    let data = format!(r#"{{"quote":"{}","user_data":"{}"}}"#, base64::encode(&quote), key_base64);
    let data = data.replace("\n", "");
    //println!("data: {}", data);
    //println!("url: {}", url);

    let mut headers = HeaderMap::new();
    headers.insert("Attestation-type", HeaderValue::from_static("TDX"));
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    if boot_type > 2{
        let ca_cert = reqwest::Certificate::from_pem(&cert)?;
        let client = Client::builder().add_root_certificate(ca_cert)
           .use_rustls_tls()
           //.danger_accept_invalid_certs(true)
           .build()?;

        let res = client.post(url)
            .headers(headers)
            .body(data)
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
        let FDEKeyBytes = cipher.decrypt(nonce, ciphertext.as_ref()).expect("decryption failure!");
        //println!("FDE Key Bytes {:?}", FDEKeyBytes);
        let  mut hex: Vec<String> = FDEKeyBytes.iter().map(|n| format!("{:02x}", n)).collect();
        let  mut key_string = hex.join("");
        println!("Encryption Key Retrieved!");

        // 4. disk

        if key.len() != KEY_LENGTH {
            panic!("FDE Key not Support!");
        }
        let mut  key=key_string.as_bytes();
        crypt_setup(root.to_string(), name.to_string(), &key);
        //key.zeroize();

        Ok(())
    }
    else if boot_type == 2 {
        Ok(())
    }
    else if boot_type == 1 {
       let mut  key_string="123456";
       let mut  key=key_string.as_bytes();
       crypt_setup(root.to_string(), name.to_string(), &key);
       Ok(())
    }
    else{
       println!("Wrong option");
       Ok(())
    }

}
