"""Passkey (WebAuthn) registration and login, standard library only.

There is no crypto library available here, so the pieces WebAuthn needs are
implemented directly: a small CBOR reader, ECDSA-P256 verification, and RSA
PKCS#1 v1.5 verification.

That is a defensible thing to hand-roll *for verification specifically*: it
operates entirely on public values - a public key, a signature, a message - so
there is no secret to leak through timing, which is the usual reason not to
write your own. Signing, which does handle secrets, happens on the
authenticator, never here.

Verified against the RFC 6979 / FIPS 186-4 test vectors in test_webauthn.py.
"""

import hashlib
import json
import secrets
import struct
import time
from base64 import urlsafe_b64encode, urlsafe_b64decode

# ------------------------------------------------------------------ base64url


def b64u(data):
    return urlsafe_b64encode(data).decode().rstrip("=")


def unb64u(s):
    s = str(s or "")
    return urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ----------------------------------------------------------------------- CBOR

MAX_CBOR_DEPTH = 16


def cbor_decode(data, pos=0, depth=0):
    """Decode one CBOR item. Returns (value, next_pos).

    Only the subset WebAuthn uses: unsigned/negative ints, byte and text
    strings, arrays, maps, and the simple values true/false/null.
    """
    if depth > MAX_CBOR_DEPTH:
        # Reached with unauthenticated bytes on the assertion path, so a
        # nesting bomb must cost nothing rather than blow the stack.
        raise ValueError("CBOR nested too deeply")
    first = data[pos]; pos += 1
    major, info = first >> 5, first & 0x1F

    def length(info, pos):
        if info < 24:
            return info, pos
        if info == 24:
            return data[pos], pos + 1
        if info == 25:
            return struct.unpack_from(">H", data, pos)[0], pos + 2
        if info == 26:
            return struct.unpack_from(">I", data, pos)[0], pos + 4
        if info == 27:
            return struct.unpack_from(">Q", data, pos)[0], pos + 8
        raise ValueError("bad CBOR length")

    if major == 0:
        n, pos = length(info, pos); return n, pos
    if major == 1:
        n, pos = length(info, pos); return -1 - n, pos
    if major == 2:
        n, pos = length(info, pos); return data[pos:pos + n], pos + n
    if major == 3:
        n, pos = length(info, pos)
        return data[pos:pos + n].decode("utf-8", "replace"), pos + n
    if major == 4:
        n, pos = length(info, pos)
        out = []
        for _ in range(n):
            v, pos = cbor_decode(data, pos, depth + 1); out.append(v)
        return out, pos
    if major == 5:
        n, pos = length(info, pos)
        out = {}
        for _ in range(n):
            k, pos = cbor_decode(data, pos, depth + 1)
            v, pos = cbor_decode(data, pos, depth + 1)
            out[k] = v
        return out, pos
    if major == 7:
        if info == 20: return False, pos
        if info == 21: return True, pos
        if info == 22: return None, pos
        raise ValueError("unsupported CBOR simple value")
    raise ValueError(f"unsupported CBOR major type {major}")


# ------------------------------------------------------------- ECDSA on P-256

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5


def _inv(x, m):
    return pow(x, m - 2, m)


def _add(p1, p2):
    """Affine point addition on P-256. None is the point at infinity."""
    if p1 is None: return p2
    if p2 is None: return p1
    x1, y1 = p1; x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + A) * _inv(2 * y1 % P, P) % P
    else:
        lam = (y2 - y1) * _inv((x2 - x1) % P, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def _mul(k, point):
    """Double-and-add. Verification is public-data only, so a constant-time
    ladder buys nothing here."""
    result, addend = None, point
    while k:
        if k & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        k >>= 1
    return result


def _der_sig(sig):
    """Pull (r, s) out of a DER SEQUENCE of two INTEGERs."""
    if len(sig) < 8 or sig[0] != 0x30:
        raise ValueError("not a DER signature")
    pos = 2 if sig[1] < 0x80 else 3 + (sig[1] & 0x7F) - 1
    if sig[pos] != 0x02:
        raise ValueError("expected INTEGER")
    rlen = sig[pos + 1]; r = int.from_bytes(sig[pos + 2:pos + 2 + rlen], "big")
    pos += 2 + rlen
    if sig[pos] != 0x02:
        raise ValueError("expected INTEGER")
    slen = sig[pos + 1]; s = int.from_bytes(sig[pos + 2:pos + 2 + slen], "big")
    return r, s


def verify_es256(x, y, message, signature):
    """ECDSA-SHA256 verification over P-256."""
    try:
        r, s = _der_sig(signature)
    except (ValueError, IndexError):
        return False
    if not (1 <= r < N and 1 <= s < N):
        return False
    # the public key must actually be on the curve
    if (y * y - (x * x * x + A * x + B)) % P != 0:
        return False
    e = int.from_bytes(hashlib.sha256(message).digest(), "big")
    w = _inv(s, N)
    p1 = _mul(e * w % N, (GX, GY))
    p2 = _mul(r * w % N, (x, y))
    pt = _add(p1, p2)
    if pt is None:
        return False
    return pt[0] % N == r


# --------------------------------------------------------------- RSA (RS256)

SHA256_DIGESTINFO = bytes.fromhex("3031300d060960864801650304020105000420")


def verify_rs256(n, e, message, signature):
    """RSASSA-PKCS1-v1_5 with SHA-256."""
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    m = pow(int.from_bytes(signature, "big"), e, n)
    em = m.to_bytes(k, "big")
    expect = (b"\x00\x01" + b"\xff" * (k - len(SHA256_DIGESTINFO) - 35)
              + b"\x00" + SHA256_DIGESTINFO + hashlib.sha256(message).digest())
    return secrets.compare_digest(em, expect)


# ------------------------------------------------------------------- COSE key

def cose_verify(cose_bytes, message, signature):
    """Verify against a COSE_Key as stored at registration."""
    try:
        key, _ = cbor_decode(cose_bytes)
    except Exception:
        return False
    kty, alg = key.get(1), key.get(3)
    if kty == 2 and alg == -7:                      # EC2 / ES256
        x = int.from_bytes(key.get(-2, b""), "big")
        y = int.from_bytes(key.get(-3, b""), "big")
        return verify_es256(x, y, message, signature)
    if kty == 3 and alg == -257:                    # RSA / RS256
        n = int.from_bytes(key.get(-1, b""), "big")
        e = int.from_bytes(key.get(-2, b""), "big")
        return verify_rs256(n, e, message, signature)
    return False


# ------------------------------------------------------------- authenticator

def parse_auth_data(data):
    """rpIdHash | flags | signCount | [attestedCredentialData]"""
    if len(data) < 37:
        raise ValueError("authenticator data too short")
    out = {"rp_id_hash": data[:32], "flags": data[32],
           "sign_count": struct.unpack_from(">I", data, 33)[0]}
    out["user_present"] = bool(out["flags"] & 0x01)
    out["user_verified"] = bool(out["flags"] & 0x04)
    if out["flags"] & 0x40:                          # attested credential data
        pos = 37 + 16
        cid_len = struct.unpack_from(">H", data, pos)[0]; pos += 2
        out["credential_id"] = data[pos:pos + cid_len]; pos += cid_len
        _, end = cbor_decode(data, pos)              # the COSE key
        out["public_key"] = data[pos:end]
    return out


def check_client_data(raw, expect_type, challenge, origins):
    cd = json.loads(raw.decode("utf-8"))
    if cd.get("type") != expect_type:
        raise ValueError(f"wrong ceremony type: {cd.get('type')}")
    if not secrets.compare_digest(str(cd.get("challenge", "")), challenge):
        raise ValueError("challenge did not match")
    if cd.get("origin") not in origins:
        raise ValueError(f"unexpected origin {cd.get('origin')}")
    return cd


def register(client_data_json, attestation_object, challenge, origins, rp_id):
    """Verify a create() response. Returns (credential_id, cose_key, count)."""
    check_client_data(client_data_json, "webauthn.create", challenge, origins)
    att, _ = cbor_decode(attestation_object)
    auth = parse_auth_data(att["authData"])
    if not secrets.compare_digest(auth["rp_id_hash"],
                                  hashlib.sha256(rp_id.encode()).digest()):
        raise ValueError("this passkey belongs to a different site")
    if not auth["user_present"]:
        raise ValueError("the authenticator reported no user presence")
    if "credential_id" not in auth:
        raise ValueError("no credential in the attestation")
    # Attestation statements are deliberately not verified: we care that the
    # key works, not which manufacturer vouched for it.
    return auth["credential_id"], auth["public_key"], auth["sign_count"]


def authenticate(client_data_json, authenticator_data, signature,
                 cose_key, challenge, origins, rp_id, last_count=0):
    """Verify a get() response. Returns the new signature counter."""
    check_client_data(client_data_json, "webauthn.get", challenge, origins)
    if len(authenticator_data) > 32 and (authenticator_data[32] & 0x40):
        # Attested credential data belongs to registration only; seeing it here
        # means the client is feeding us the wrong ceremony's bytes.
        raise ValueError("unexpected attestation data in an assertion")
    auth = parse_auth_data(authenticator_data)
    if not secrets.compare_digest(auth["rp_id_hash"],
                                  hashlib.sha256(rp_id.encode()).digest()):
        raise ValueError("this passkey belongs to a different site")
    if not auth["user_present"]:
        raise ValueError("the authenticator reported no user presence")
    signed = authenticator_data + hashlib.sha256(client_data_json).digest()
    if not cose_verify(cose_key, signed, signature):
        raise ValueError("signature did not verify")
    # A counter that goes backwards suggests a cloned authenticator. Many
    # platform passkeys always report 0, so only a genuine regression counts.
    if auth["sign_count"] and last_count and auth["sign_count"] <= last_count:
        raise ValueError("replayed or cloned authenticator")
    return auth["sign_count"]


def new_challenge():
    return b64u(secrets.token_bytes(32))
