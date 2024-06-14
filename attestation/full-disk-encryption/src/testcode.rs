use std::process::Command;
use std::io::Write;
fn main() {
let key="IDLjkkH0i9FUt+z9nDFFkPfB1b4Ri3gnqbKMJwDOCZfncxjZ6uCtGPBhfQKrSUq6iwtkljrAWudE5pZzyedRoN2FHylh+bCA9VwXbqKMqyTyik3g6VesAdZnnOypDEZQJ7t5q4/678C4Xa9+yNo1nKOqxeg911arldcvjWVhLS/qrgorheQ7SmITsPCgpdQHeuKIbIWOqQEJ6NfpEOhTWmzrQqQc9jMsv+w7c3e0UBcK5Tgp1gBSATQ0XxJ4+97wll85NdRJdUg70b5pX6fHV0ksNQpd4Cel2i1OEBkZuGk6Tnza4tRQUwGu6VY8MW7xd842pVj1qLOFy6AvmrnlzQd0nTZtmO9YkECiHiOHDLlh98pv92gqeimSTjMn40Sh";
let output = Command::new("cryptsetup")
        .arg("-v") // suppress all interactive prompts
        .arg("luksOpen")
        .arg("/dev/vda1")
        .arg("rootfs-enc-dev")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to run cryptsetup");

    // Write the password to cryptsetup's stdin

    output.stdin.unwrap().write_all(key.as_bytes()).unwrap();

    println!("LUKS formatted loop device created successfully");
}
