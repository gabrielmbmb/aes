import unittest
from aes import AES


class AesTest(unittest.TestCase):
    def setUp(self):
        self.text_to_cypher = "00112233445566778899aabbccddeeff"
        self.AES_128 = AES("000102030405060708090a0b0c0d0e0f")
        self.AES_192 = AES("000102030405060708090a0b0c0d0e0f1011121314151617", 192)
        self.AES_256 = AES("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 256)

    def test_encrypt_128(self):
        cypher = self.AES_128.cypher(self.text_to_cypher)

        self.assertEqual(cypher, "69c4e0d86a7b0430d8cdb78070b4c55a")

    def test_decrypt_128(self):
        text = self.AES_128.decipher("69c4e0d86a7b0430d8cdb78070b4c55a")

        self.assertEqual(text, self.text_to_cypher)

    def test_encrypt_192(self):
        cypher = self.AES_192.cypher(self.text_to_cypher)

        self.assertEqual(cypher, "dda97ca4864cdfe06eaf70a0ec0d7191")

    def test_decrypt_192(self):
        text = self.AES_192.decipher("dda97ca4864cdfe06eaf70a0ec0d7191")

        self.assertEqual(text, self.text_to_cypher)

    def test_encrypt_256(self):
        cypher = self.AES_256.cypher(self.text_to_cypher)

        self.assertEqual(cypher, "8ea2b7ca516745bfeafc49904b496089")

    def test_decrypt_256(self):
        text = self.AES_256.decipher("8ea2b7ca516745bfeafc49904b496089")

        self.assertEqual(text, self.text_to_cypher)


if __name__ == "__main__":
    unittest.main()
