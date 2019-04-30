import unittest
from aes import AES

class aes_Test(unittest.TestCase):
  def setUp(self):
    self.AES = AES("2b7e151628aed2a6abf7158809cf4f3c")

  def test_encrypt(self):
    cypher = self.AES.cypher("3243f6a8885a308d313198a2e0370734")

    self.assertEqual(cypher, "3925841d02dc09fbdc118597196a0b32")

  def test_decrypt(self):
    text = self.AES.decipher("3925841d02dc09fbdc118597196a0b32")

    self.assertEqual(text, "3243f6a8885a308d313198a2e0370734")

if __name__ == "__main__":
  unittest.main()
