use std::{env, fs, io::{Read, self, Write}};
use aes::{Aes256, cipher::{KeyInit, generic_array::GenericArray, BlockEncrypt, BlockDecrypt}};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Invalid input");
        return;
    }
    let decrypt = args[1].ends_with(".enc");
    let password = rpassword::prompt_password("Password: ").unwrap();
    if !decrypt {
        let confirm = rpassword::prompt_password("Confirm: ").unwrap();
        if password != confirm {
            println!("Password do not match");
            return;
        }
    }
    match do_cipher(&args[1], &password, !decrypt) {
        Ok(()) => println!("Encryption / Decryption successful"), 
        Err(e) => println!("An error occurred: {}", e)
    }
}

fn do_cipher(path: &String, password: &String, encrypt: bool) -> std::io::Result<()> {
    let file = fs::File::open(path)?;
    let mut reader = io::BufReader::new(file);


    let output = fs::File::create(
        if encrypt {
            path.to_owned() + ".enc"
        } else {
            path.strip_suffix(".enc").unwrap().to_string()
        }
    )?;

    let mut writer = io::BufWriter::new(output);

    let cipher = Aes256::new(
        &GenericArray::from_iter(password.bytes().cycle().take(32))
    );
    let mut buffer = [0u8; 16];
    while reader.read(&mut buffer)? > 0 {
        // TODO: Add padding
        let mut gen_arr = GenericArray::from(buffer);
        if encrypt {
            cipher.encrypt_block(&mut gen_arr);
        } else {
            cipher.decrypt_block(&mut gen_arr);
        }
        writer.write(gen_arr.as_mut_slice())?;
        buffer = [0u8; 16];
    }
    Ok(())
}
