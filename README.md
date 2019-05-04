![GitHub](https://img.shields.io/github/license/gabrielmbmb/aes.svg) 

# What is this?

An implementation of the AES algorithm in Python 3 and the block cipher operation of mode ECB, CBC and CTR.

# Why did you do this?

Because of learning purposes and also for being a project for Information and Coding Theory course.

# Can I use it?

Yes, for sure.

# Basic usage

## Setup

    pip3 install -r requirements.txt
    chmod +x crypt.py

## Encrypt

Encrypt "file_to_encrypt" using block cipher mode of operation CTR and with a key of length 256 bits. Output file "file_name_encrypted"

    ./crypt -i <file_to_encrypt> -o <file_name_encrypted> -m CTR -l 256

The key used for encryption will be displayed and saved in the file "key.txt".

## Decrypt

The key used for decryption will be read from "key.txt"

    ./crypt.py -d -i <file_to_decrypt> -o <file_decrypted> -m CTR -l 256

# References

1. [Nist Fips 197](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf)
2. The Design of Rijndael
3. [Block cipher mode of operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)
4. [Using Padding in Encryption](https://www.di-mgt.com.au/cryptopad.html)
