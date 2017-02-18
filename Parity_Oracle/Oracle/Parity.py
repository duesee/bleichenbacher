from Crypto.PublicKey import RSA



class Oracle():
        """
        Parity Oracle implementing all methods available to eve.
        """
        
        def __init__(self):
                """
                Constructor.
                """
                self.rsa = RSA.generate(2048)
        
        def get_n(self):
                """
                Returns the public RSA modulus.
                """
                return self.rsa.n
                
        def get_e(self):
                """
                Returns the public RSA exponent.
                """
                return self.rsa.e

        def encrypt(self, plaintext):
                """
                Returns the encrypted plaintext.
                """
                return self.rsa.encrypt(plaintext, None)[0]

        def decrypt(self, ciphertext):
                """
                Returns true if the decrypted plaintext is even - false otherwise.
                """
                return (self.rsa.decrypt(ciphertext) % 2 == 0)
