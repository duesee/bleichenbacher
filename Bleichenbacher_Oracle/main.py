from TypeChecking.Annotations import typecheck
from Oracle.Bleichenbacher import Oracle
from PKCS.Formatting import os2ip, i2osp
from sys import stdout


@typecheck
def extended_gcd(aa: int, bb: int) -> tuple:
    """
    http://rosettacode.org/wiki/Modular_inverse#Python
    """
    lastremainder, remainder = abs(aa), abs(bb)
    x, lastx, y, lasty = 0, 1, 1, 0
    while remainder:
        lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
        x, lastx = lastx - quotient * x, x
        y, lasty = lasty - quotient * y, y
    return lastremainder, lastx * (-1 if aa < 0 else 1), lasty * (-1 if bb < 0 else 1)


@typecheck
def modinv(a: int, m: int) -> int:
    """
    http://rosettacode.org/wiki/Modular_inverse#Python
    """
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError
    return x % m


@typecheck
def interval(a: int, b: int) -> range:
    return range(a, b + 1)


@typecheck
def ceildiv(a: int, b: int) -> int:
    """
    http://stackoverflow.com/a/17511341
    """
    return -(-a // b)


@typecheck
def floordiv(a: int, b: int) -> int:
    """
    http://stackoverflow.com/a/17511341
    """
    return a // b


@typecheck
def bleichenbacher(oracle: Oracle):
    """
    Bleichenbacher's attack

    Good ideas taken from:
        http://secgroup.dais.unive.it/wp-content/uploads/2012/11/Practical-Padding-Oracle-Attacks-on-RSA.html
    """

    k, n, e = oracle.get_k(), oracle.get_n(), oracle.get_e()

    B = pow(2, 8 * (k - 2))
    B2 = 2 * B
    B3 = B2 + B

    @typecheck
    def pkcs_conformant(c_param: int, s_param: int) -> bool:
        """
        Helper-Function to check for PKCS conformance.
        """
        pkcs_conformant.counter += 1
        return oracle.decrypt(i2osp(c_param * pow(s_param, e, n) % n, k))

    pkcs_conformant.counter = 0

    cipher = os2ip(oracle.eavesdrop())

    assert(pkcs_conformant(cipher, 1))

    c_0 = cipher
    set_m_old = {(B2, B3 - 1)}
    i = 1

    s_old = 0
    while True:
        if i == 1:
            s_new = ceildiv(n, B3)
            while not pkcs_conformant(c_0, s_new):
                s_new += 1

        elif i > 1 and len(set_m_old) >= 2:
            s_new = s_old + 1
            while not pkcs_conformant(c_0, s_new):
                s_new += 1

        elif len(set_m_old) == 1:
            a, b = next(iter(set_m_old))
            found = False
            r = ceildiv(2 * (b * s_old - B2), n)
            while not found:
                for s in interval(ceildiv(B2 + r*n, b), floordiv(B3 - 1 + r*n, a)):
                    if pkcs_conformant(c_0, s):
                        found = True
                        s_new = s
                        break
                r += 1

        set_m_new = set()
        for a, b in set_m_old:
            r_min = ceildiv(a * s_new - B3 + 1, n)
            r_max = floordiv(b * s_new - B2, n)
            for r in interval(r_min, r_max):
                new_lb = max(a, ceildiv(B2 + r*n, s_new))
                new_ub = min(b, floordiv(B3 - 1 + r*n, s_new))
                if new_lb <= new_ub:  # intersection must be non-empty
                    set_m_new |= {(new_lb, new_ub)}

        print("Calculated new intervals set_m_new = {} in Step 3".format(set_m_new))

        if len(set_m_new) == 1:
            a, b = next(iter(set_m_new))
            if a == b:
                print("Calculated:     ", i2osp(a, k))
                print("Calculated int: ", a)
                print("Success after {} calls to the oracle.".format(pkcs_conformant.counter))
                return a

        i += 1
        s_old = s_new
        set_m_old = set_m_new


@typecheck
def bleichenbacher_simulation(k, n, m):
    """
    Bleichenbacher's attack

    Good ideas taken from:
        http://secgroup.dais.unive.it/wp-content/uploads/2012/11/Practical-Padding-Oracle-Attacks-on-RSA.html
    """

    B = pow(2, 8 * (k - 2))
    B2 = 2 * B
    B3 = B2 + B

    print("---------------")
    print("k", k)
    print("n", n)
    print("m", m)
    print("B2", B2)
    print("B3-1", B3-1)
    print("---------------")

    @typecheck
    def pkcs_conformant(s: int, m: int) -> bool:
        """
        Helper-Function to check for PKCS conformance with unencrypted m.
        """
        pkcs_conformant.counter += 1
        return B2 <= ((s * m) % n) < B3  # Chained comparisons are allowed in Python... :-)

    pkcs_conformant.counter = 0

    """
    Step 1: Blinding.
    Can be skipped if c is already PKCS conforming (i.e., when c is an encrypted message).
    In that case, we set s_0 = 1.
    """

    print("Starting with Step 1")

    assert(pkcs_conformant(1, m))

    s_0 = 1  # Since we know that c_0 is PKCS-conformant, we don't need to find a new s in the first step.
    m_0 = m * s_0 % n  # Mathematically trivial - only for explanation purposes...
    set_m_old = {(B2, B3 - 1)}
    i = 1

    for v in set_m_old:
        stdout.write(str(v))
        stdout.write(";")

    print("")

    s_old = 0
    while True:
        """
        Step 2: Searching for PKCS conforming messages.
        """

        print("Starting with Step 2")

        if i == 1:
            """
            Step 2.a: Starting the search.
            If i = 1, then search for the smallest positive integer s_1 \geq n/(3B),
            such that the ciphertext c_0*(s_1)^e mod n is PKCS conforming.
            """

            print("Starting with Step 2.a")

            s_new = ceildiv(n, B3)  # Explanation follows...
            while not pkcs_conformant(s_new, m_0):
                s_new += 1

            print("Found s_new = {} in Step 2.a".format(s_new))

        elif i > 1 and len(set_m_old) >= 2:
            """
            Step 2.b: Searching with more than one interval left.
            If i > 1 and the number of intervals in M_{i−1} is at least 2, then search for the
            smallest integer s_i > s_{i−1}, such that the ciphertext c_0*(s_i)^e mod n is PKCS conforming.
            """

            print("Starting with Step 2.b")

            s_new = s_old + 1
            while not pkcs_conformant(s_new, m_0):
                s_new += 1

            print("Found s_new = {} in Step 2.b".format(s_new))

        elif len(set_m_old) == 1:
            """
            Step 2.c: Searching with one interval left.
            If M_{i−1} contains exactly one interval (i.e., M_{i−1} = {[a, b]}),
            then choose small integer values r_i, s_i such that

                r_i \geq 2 * (bs_{i-1} - 2B) / n

            and

                (2B + r_i*n) / b \leq s_i < (3B + r_i*n) / a,

            until the ciphertext c_0*(s_i)^e mod n is PKCS conforming.
            """

            print("Starting with Step 2.c")

            a, b = next(iter(set_m_old))
            found = False
            r = ceildiv(2 * (b * s_old - B2), n)
            while not found:
                for s in interval(ceildiv(B2 + r*n, b), floordiv(B3 - 1 + r*n, a)):
                    if pkcs_conformant(s, m_0):
                        found = True
                        s_new = s
                        break
                r += 1

            print("Found s_new = {} in Step 2.c".format(s_new))

        """
        Step 3: Narrowing the set of solutions.
        After s_i has been found, the set M_i is computed as

            M_i = \bigcup_{(a, b, r)} { [max(a, [2B+rn / s_i]), min(b, [3B-1+rn / s_i])] }

        for all [a, b] \in M_{i-1} and (as_i - 3B + 1)/(n) \leq r \leq (bs_i - 2B)/(n).
        """

        print("Starting with Step 3")

        set_m_new = set()
        for a, b in set_m_old:
            r_min = ceildiv(a * s_new - B3 + 1, n)
            r_max = floordiv(b * s_new - B2, n)

            print("Found new values for r and a = {}, b = {} -- {} <= r <= {}".format(a, b, r_min, r_max))

            for r in interval(r_min, r_max):
                new_lb = max(a, ceildiv(B2 + r*n, s_new))
                new_ub = min(b, floordiv(B3 - 1 + r*n, s_new))
                if new_lb <= new_ub:  # intersection must be non-empty
                    set_m_new |= {(new_lb, new_ub)}

        for v in set_m_new:
            stdout.write(str(v))
            stdout.write(";")

        print("")

        """
        Step 4: Computing the solution.
        If M_i contains only one interval of length 1 (i.e., M_i = {[a, a]}),
        then set m = a(s_0)^{−1} mod n, and return m as solution of m \equiv c^d (mod n).
        Otherwise, set i = i + 1 and go to step 2.
        """

        print("Starting with Step 4")

        if len(set_m_new) == 1:
            a, b = next(iter(set_m_new))
            if a == b:
                print("Original:   ", hex(m))
                print("Calculated: ", hex(a))
                print("Success after {} calls to the oracle.".format(pkcs_conformant.counter))
                return a

        i += 1
        #print("Intervals retry", set_m_new)
        print("Going back to step 2")
        s_old = s_new
        set_m_old = set_m_new

        print("No luck for set_m_new = {} in Step 4".format(set_m_new))


@typecheck
def run_tests():
    """
    Tests to validate the algorithm.
    """
    tests = [
        #{"k": 4, "p": 10007, "q": 10037},
        #{"k": 8, "p": 1000000007, "q": 1000000009},
        #{"k": 16, "p": 15309168720959725921, "q": 12819619822143804367},
        #{"k": 32, "p": 313115142601654954062569328755831304743, "q": 255336707253239299888475776540791782543},
        #{"k": 128, "p": 13244628888829977635820637741951867212791935321427723006722254687460420690588887758810928307766709750393036804634467753421052044765639091747501507784485213, "q": 11583722350869317111812024666321163171121150655325205224246499810906481321757898291274629991421369420603573230614994104724581115295807013606297300412089473},
        {"k": 256, "p": 167230636094866282461211664159158428279902699551992447152002026086321450931356694020366071860452874936312114743689156451204955885905421523426919810372766672329365549589557666294538091910136590569719360771818561583316969574158815755289605442067349031803550793473499645742177046498728201139371344588674279678939, "q": 153746015991426629737627279764483089360526745536038013938043722107713599542535853191396561623967198520570205780805436781605500829408932188321165836162114053101365153759076284383142329005938490083741368370827739032497065588280706602245858167496933285469691492972704468586486254156236192774677901155398324342253}
    ]

    for test in tests:
        n = test["p"] * test["q"]
        B = pow(2, 8 * (test["k"] - 2))
        B2 = 2 * B
        m = b"ABCD"
        m = B2 + int(m, 16)
        bleichenbacher_simulation(test["k"], n, m)


if __name__ == "__main__":
    oracle = Oracle()
    #run_tests()
    bleichenbacher(oracle), oracle.get_k()
