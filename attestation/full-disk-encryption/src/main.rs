//use anyhow::{Ok, Result};
use anyhow::{ Result};
use base64::{engine::general_purpose, Engine as _};
use clap::Parser;
use zeroize::Zeroize;
use std::process::{Command, Stdio};
use std::io::{BufReader, BufRead};
use std::result::Result::Ok;
use std::fs::File;
use std::io::ErrorKind;
use std::io::Read;
use std::io::prelude::*;
use std::path::Path;
//use serde::{Deserialize, Serialize};
//use serde_json::Result;
mod quote;
use quote::retrieve_quote;

mod ovmf_var;
use ovmf_var::retrieve_kbs_params;

mod key_broker;
use key_broker::retreive_key_from_kbs;

mod disk;
use disk::{crypt_setup, KEY_LENGTH};

use crate::key_broker::RetrieveKeyRequest;

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

    println!("url received= {}",url);
    // 2. get quote
    let quote = retrieve_quote()?;
    println!("TD Report & Quote Retrieved!");
    println!("Quote Bytes: {:?}", quote);
    //let mut tmp_key;
    let mut command = Command::new("/sbin/go_key_gen")
       .arg(url)
       .stdout(Stdio::piped())
       .spawn()
       .unwrap();

     let mut file = match File::open("/tmp/test.txt") {
        Err(why) => panic!("couldn't open {}: {}", "/tmp/test.txt", why),
        Ok(file) => file,
    };

    // Read the file contents into a string, returns `io::Result<usize>`
    let mut s = String::new();
    match file.read_to_string(&mut s) {
        Err(why) => panic!("couldn't read {}: {}", "/tmp/test.txt", why),
        Ok(_) => print!("{} contains:\n{}", "/tmp/test.txt", s),
    }
    println!("\nKey received= {}",s);
    let key=s.as_bytes();
      crypt_setup(root.to_string(), name.to_string(), &key);
   // key.zeroize();
    println!("Encryption Disk Mounted!");
    Ok(())
}
