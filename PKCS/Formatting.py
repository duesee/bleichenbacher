from TypeChecking.Annotations import typecheck


@typecheck
def os2ip(octets: bytes) -> int:
    """
    Octet-String-to-Integer primitive
    PKCS #1 Version 1.5 (RFC2313)
    """
    return int.from_bytes(octets, 'big')


@typecheck
def i2osp(i: int, k: int) -> bytes:
    """
    Integer-to-Octet-String primitive
    PKCS #1 Version 1.5 (RFC2313)
    """
    return i.to_bytes(k, byteorder='big')
