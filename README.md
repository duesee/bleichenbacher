# Bleichenbachers "Million Message Attack" on RSA

This repo contains a python project to demonstrate Daniel Bleichenbacher's million message attack against RSA encryption and PKCS #1 padding.

# RSA Parity Oracle

The effects of leaking the LSB (the Parity-Bit) of an RSA plaintext is demonstrated in `Parity_Oracle`. 

The code is mostly taken from [Practical-Padding-Oracle-Attacks-on-RSA](http://secgroup.dais.unive.it/wp-content/uploads/2012/11/Practical-Padding-Oracle-Attacks-on-RSA.html). Snce we find it very helpful to understand the Bleichenbacher oracle, it is included here as well.

# Good to know

* The `python-crypto` package is needed. Please install it.
* Text is always Unicode and is represented by the str type -- binary data is represented by the bytes type. Please refer to http://eli.thegreenplace.net/2012/01/30/the-bytesstr-dichotomy-in-python-3 for further information.
* We experienced many type errors during development. Thus, many functions are type-checked via a custom decorator and special annotations.

# Literature

* "Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1" by Daniel Bleichenbacher.

* [Practical-Padding-Oracle-Attacks-on-RSA](http://secgroup.dais.unive.it/wp-content/uploads/2012/11/Practical-Padding-Oracle-Attacks-on-RSA.html)
