from Oracle.Parity import Oracle
from decimal import *
from math import ceil, floor, log


if __name__ == "__main__":
    """
    http://secgroup.dais.unive.it/wp-content/uploads/2012/11/Practical-Padding-Oracle-Attacks-on-RSA.html
    """
    oracle = Oracle()
    
    e, n = oracle.get_e(), oracle.get_n()

    c = oracle.encrypt(123456789123456789123456789)
    
    enctwo = pow(2, e, n)

    lb = Decimal(0)
    ub = Decimal(n)

    k = int(ceil(log(n, 2)))  # n. of iterations
    getcontext().prec = k     # allows for 'precise enough' floats

    for i in range(1, k + 1):
        c = (c * enctwo) % n  # Adapting c...
        
        nb = (lb + ub) / 2
        
        if oracle.decrypt(c):
            ub = nb
        else:
            lb = nb

        print("{:>4}: [{}, {}]".format(i, int(lb), int(ub)))
