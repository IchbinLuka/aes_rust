#![feature(buf_read_has_data_left)]
use std::{env, fs::{self, File}, io::{Read, self, Write, BufRead, BufReader, BufWriter}};
use aes::{Aes256, cipher::{KeyInit, generic_array::GenericArray, BlockEncrypt, BlockDecrypt}};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Invalid input. Usage: aes [filename]");
        return;
    }
    let decrypt = args[1].ends_with(".enc");
    let password = rpassword::prompt_password("Password: ").unwrap();
    if !decrypt {
        let confirm = rpassword::prompt_password("Confirm: ").unwrap();
        if password != confirm {
            println!("Passwords do not match");
            return;
        }
    }
    match do_cipher(&args[1], &password, !decrypt) {
        Ok(()) => println!("Encryption / Decryption successful"), 
        Err(cipher_err) => match cipher_err {
            CipherError::BadPaddingError => println!("Could not resolve padding. Probably due to an invalid password"), 
            CipherError::IOError(e) => println!("An error occurred: {}", e)
        }
    }
}

fn do_cipher(path: &String, password: &String, should_encrypt: bool) -> Result<(), CipherError> {
    let file = fs::File::open(path)?;
    let reader = io::BufReader::new(file);

    let output_path = if should_encrypt {
        path.to_owned() + ".enc"
    } else {
        path.strip_suffix(".enc").unwrap().to_string()
    };
    let output = fs::File::create(output_path.clone())?;

    let writer = io::BufWriter::new(output);

    let cipher = Aes256::new(
        &GenericArray::from_iter(password.bytes().cycle().take(32))
    );

    let result = if should_encrypt {
        encrypt(reader, writer, cipher)
    } else {
        decrypt(reader, writer, cipher)
    };
    if let Err(error) = result {
        fs::remove_file(output_path.clone())?;
        return Err(error)
    }
    Ok(())
}

enum CipherError {
    IOError(std::io::Error), 
    BadPaddingError
}

impl From<std::io::Error> for CipherError {
    fn from(value: std::io::Error) -> Self {
        Self::IOError(value)
    }
}


fn encrypt(mut reader: BufReader<File>, mut writer: BufWriter<File>, cipher: Aes256) -> Result<(), CipherError> {
    let mut buffer = [0u8; 16];
    loop {
        let count = reader.read(&mut buffer)?;
        let reached_end = !reader.has_data_left()?;
        if reached_end  {
            // Add PKCS5 Padding
            let padding: u8 = 16 - count as u8;
            for i in count..16 {
                buffer[i] = padding;
            }
        }
        let mut gen_arr = GenericArray::from(buffer);
        cipher.encrypt_block(&mut gen_arr);

        writer.write(gen_arr.as_mut_slice())?;
        buffer = [0u8; 16];
        if reached_end { break; }
    }
    Ok(())
}

fn decrypt(mut reader: BufReader<File>, mut writer: BufWriter<File>, cipher: Aes256) -> Result<(), CipherError> {
    let mut buffer = [0u8; 16];
    while reader.read(&mut buffer)? > 0 {
        // TODO: Add padding
        let mut gen_arr = GenericArray::from(buffer);
        cipher.decrypt_block(&mut gen_arr);

        let reached_end = !reader.has_data_left()?;
        let mut e = gen_arr.as_mut_slice();
        if reached_end {
            let padding = *e.last().unwrap(); // Get number of padded bytes
            if padding > 16 { return Err(CipherError::BadPaddingError) }
            let (a, b) = e.split_at_mut(16 - padding as usize);
            // Check if padding is valid
            for x in &(*b) {
                if *x != padding {
                    return Err(CipherError::BadPaddingError);
                }
            }
            e = a;
            
        }
        writer.write(e)?;
        buffer = [0u8; 16];
    }
    Ok(())
}
