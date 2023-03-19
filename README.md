# aes_rust
A small command line AES encryption tool written in Rust.


## Usage
Simply call `aes [path to file]` in a terminal to encrypt or decrypt a file. The encrypted file will have the same filename as the encrypted file but with an `.enc` file ending added.
So calling `aes test.txt` will result in a file with the name `test.txt.enc`.

The program decides whether it should encrypt or decrypt based on the filename. This means that if you want to encrypt files with an `.enc` ending you should first 
rename them.
