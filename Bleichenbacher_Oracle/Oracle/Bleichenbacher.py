from TypeChecking.Annotations import typecheck
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5


class Oracle():
    """
    Bleichebacher's oracle implementing methods available to eve.
    """

    @typecheck
    def __init__(self):
        """
        Setup keys, secret message and encryption/decryption schemes.
        """
        self._key = RSA.generate(1024)
        self._pkcs = PKCS1_v1_5.new(self._key)
        self._secret = b'This is how Daniel Bleichenbachers adaptive chosen-ciphertext attack works...'
        self._pkcsmsg = self._pkcs.encrypt(self._secret)

    @typecheck
    def get_n(self) -> int:
        """
        Returns the public RSA modulus.
        """
        return self._key.n

    @typecheck
    def get_e(self) -> int:
        """
        Returns the public RSA exponent.
        """
        return self._key.e

    @typecheck
    def get_k(self) -> int:
        """
        Returns the length of the RSA modulus in bytes.
        """
        return (self._key.size() + 1) // 8

    @typecheck
    def eavesdrop(self) -> bytes:
        return self._pkcsmsg

    @typecheck
    def decrypt(self, ciphertext: bytes) -> bool:
        """
        Modified decrypt method for demonstration purposes.
        See 'Cipher/PKCS1-v1_5.py' for the correct version.

        :param ciphertext: Ciphertext that contains the message to recover.
        :return: True iff the decrypted message is correctly padded according to PKCS#1 v1.5; otherwise False.
        """

        # Step 1
        if len(ciphertext) != self.get_k():
            raise ValueError("Ciphertext with incorrect length.")

        # Step 2a (OS2IP), 2b (RSADP), and part of 2c (I2OSP)
        m = self._key.decrypt(ciphertext)

        # Complete step 2c (I2OSP)
        em = b"\x00" * (self.get_k() - len(m)) + m

        # Step 3 (modified)
        sep = em.find(b"\x00", 2)

        # TODO: Justify oracle strength... --> for testing purposes

        if not em.startswith(b'\x00\x02'):
            return False

        #if not em.startswith(b'\x00\x02') or sep < 10:  # typically sep position will be checked
        #    return False

        # Step 4 (modified)
        return True
