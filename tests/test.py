import unittest
import sys
sys.path.append("../aes")

from aes import AES


class AesTest(unittest.TestCase):
    def setUp(self):
        self.text_to_cipher = "00112233445566778899aabbccddeeff"
        self.AES_128 = AES("000102030405060708090a0b0c0d0e0f")
        self.AES_192 = AES(
            "000102030405060708090a0b0c0d0e0f1011121314151617", 192)
        self.AES_256 = AES(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 256)

    def test_encrypt_128(self):
        cipher = self.AES_128.cipher(self.text_to_cipher)

        self.assertEqual(cipher, "69c4e0d86a7b0430d8cdb78070b4c55a")

    def test_decrypt_128(self):
        text = self.AES_128.decipher("69c4e0d86a7b0430d8cdb78070b4c55a")

        self.assertEqual(text, self.text_to_cipher)

    def test_encrypt_192(self):
        cipher = self.AES_192.cipher(self.text_to_cipher)

        self.assertEqual(cipher, "dda97ca4864cdfe06eaf70a0ec0d7191")

    def test_decrypt_192(self):
        text = self.AES_192.decipher("dda97ca4864cdfe06eaf70a0ec0d7191")

        self.assertEqual(text, self.text_to_cipher)

    def test_encrypt_256(self):
        cipher = self.AES_256.cipher(self.text_to_cipher)

        self.assertEqual(cipher, "8ea2b7ca516745bfeafc49904b496089")

    def test_decrypt_256(self):
        text = self.AES_256.decipher("8ea2b7ca516745bfeafc49904b496089")

        self.assertEqual(text, self.text_to_cipher)


if __name__ == "__main__":
    unittest.main()
