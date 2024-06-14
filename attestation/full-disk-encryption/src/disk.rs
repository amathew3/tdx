use cryptsetup_rs::{open, CryptDevice, LuksCryptDevice};
use log::info;
use std::process::Command;
use std::io::Write;

pub const KEY_LENGTH: usize = 256;

pub fn crypt_setup(root: String, name: String, key: &[u8]) {
    println!("Inside the crypt setup code!root= {}",root);
    //let mut _dev = open(root.clone())
    //    .expect("FDE: root deivce is not available")
    //    .luks2()
    //    .expect("FDE: Loading LUKS2 failed.");
    //println!("Checking _dev name!_dev_name= {}",_dev.uuid());
    //info!("FDE Device UUID: {}", _dev.uuid());
    //info!("FDE Device cipher: {}", _dev.cipher());
    //println!("open passed!");

    //println!("Printing name {}",name.as_str());
    //let mut _name = name.as_str();
    //if _name.is_empty() {
    //    _name = root
    //        .split('/')
    //        .last()
    //        .expect("FDE: Set device name failed.");
    //}
    //println!("Before the device activate!");
    //println!("Printing name {}!",_name);
    //let _ = _dev.activate(_name, key);
    //println!("device activate done!");
    println!("forcing the cryptsetup from cli!");
  //  let key="IDLjkkH0i9FUt+z9nDFFkPfB1b4Ri3gnqbKMJwDOCZfncxjZ6uCtGPBhfQKrSUq6iwtkljrAWudE5pZzyedRoN2FHylh+bCA9VwXbqKMqyTyik3g6VesAdZnnOypDEZQJ7t5q4/678C4Xa9+yNo1nKOqxeg911arldcvjWVhLS/qrgorheQ7SmITsPCgpdQHeuKIbIWOqQEJ6NfpEOhTWmzrQqQc9jMsv+w7c3e0UBcK5Tgp1gBSATQ0XxJ4+97wll85NdRJdUg70b5pX6fHV0ksNQpd4Cel2i1OEBkZuGk6Tnza4tRQUwGu6VY8MW7xd842pVj1qLOFy6AvmrnlzQd0nTZtmO9YkECiHiOHDLlh98pv92gqeimSTjMn40Sh";

    let output = Command::new("cryptsetup")
        .arg("-v") // suppress all interactive prompts
        .arg("luksOpen")
        .arg(root)
        .arg("rootfs-enc-dev")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to run cryptsetup");

    // Write the password to cryptsetup's stdin

    output.stdin.unwrap().write_all(key);

    println!("LUKS formatted loop device created successfully");



    
}
