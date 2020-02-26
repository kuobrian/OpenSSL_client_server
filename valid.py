from OpenSSL.crypto import (
    FILETYPE_ASN1, X509Store, X509StoreContext, X509StoreContextError,
    load_certificate)
from base64 import b64decode

class VerificationError(ValueError):
    pass


class BaseCert:
    @classmethod
    def from_pem(cls, pem_data):
        try:
            assert isinstance(pem_data, str), pem_data
            pem_lines = [l.strip() for l in pem_data.strip().split('\n')]
            assert pem_lines, 'Empty data'
            assert pem_lines[0] == '-----BEGIN CERTIFICATE-----', 'Bad begin'
            assert pem_lines[-1] == '-----END CERTIFICATE-----', 'Bad end'
        except AssertionError as e:
            raise ValueError('{} in {!r}'.format(e.args[0], pem_data)) from e

        try:
            der_data = b64decode(''.join(pem_lines[1:-1]))
        except ValueError as e:
            raise ValueError('Illegal base64 in {!r}'.format(pem_data)) from e

        return cls.from_der(der_data)

    @classmethod
    def from_der(cls, der_data):
        assert isinstance(der_data, bytes)
        cert = load_certificate(FILETYPE_ASN1, der_data)
        return cls(cert)

    def __init__(self, x509):
        self._x509 = x509
        self._revoked_fingerprints = set()

    def __str__(self):
        try:
            cn = self.get_common_name()
        except Exception:
            cn = '<could_not_get_common_name>'
        try:
            issuer = self.get_issuer_common_name()
        except Exception:
            issuer = '<could_not_get_issuer>'

        return '{} issued by {}'.format(cn, issuer)

    def get_common_name(self):
        return self._get_common_name_from_components(self._x509.get_subject())

    def get_fingerprints(self):
        ret = {
            'SHA-1': self._x509.digest('sha1').decode('ascii'),
            'SHA-256': self._x509.digest('sha256').decode('ascii'),
        }
        assert len(ret['SHA-1']) == 59, ret
        assert all(i in '0123456789ABCDEF:' for i in ret['SHA-1']), ret
        assert len(ret['SHA-256']) == 95, ret
        assert all(i in '0123456789ABCDEF:' for i in ret['SHA-256']), ret
        return ret

    def get_issuer_common_name(self):
        return self._get_common_name_from_components(self._x509.get_issuer())

    def _get_common_name_from_components(self, obj):
        return (
            # May contain other components as well, 'C', 'O', etc..
            dict(obj.get_components())[b'CN'].decode('utf-8'))

    def set_trusted_ca(self, cert):
        self._trusted_ca = cert

    def add_revoked_fingerprint(self, fingerprint_type, fingerprint):
        if fingerprint_type not in ('SHA-1', 'SHA-256'):
            raise ValueError('fingerprint_type should be SHA-1 or SHA-256')

        fingerprint = fingerprint.upper()
        assert all(i in '0123456789ABCDEF:' for i in fingerprint), fingerprint
        self._revoked_fingerprints.add((fingerprint_type, fingerprint))

    def verify(self):
        self.verify_expiry()
        self.verify_against_revoked()
        self.verify_against_ca()

    def verify_expiry(self):
        if self._x509.has_expired():
            raise VerificationError(str(self), 'is expired')

    def verify_against_revoked(self):
        fingerprints = self.get_fingerprints()
        for fingerprint_type, fingerprint in self._revoked_fingerprints:
            if fingerprints.get(fingerprint_type) == fingerprint:
                raise VerificationError(
                    str(self), 'matches revoked fingerprint', fingerprint)

    def verify_against_ca(self):
        if not hasattr(self, '_trusted_ca'):
            raise VerificationError(str(self), 'did not load trusted CA')

        store = X509Store()
        store.add_cert(self._trusted_ca._x509)
        store_ctx = X509StoreContext(store, self._x509)
        try:
            store_ctx.verify_certificate()
        except X509StoreContextError as e:
            # [20, 0, 'unable to get local issuer certificate']
            raise VerificationError(str(self), *e.args)

if __name__ == '__main__':
    def example():
        # "Creating a CA with openssl"
        # openssl genrsa -out ca.key 4096
        # openssl req -new -x509 -days 365 -key ca.key -out ca.crt \
        #   -subj '/C=NL/CN=MY-CA'
        f = open("local_ca.crt")
        cacert = f.read()

        # cacert = '''-----BEGIN CERTIFICATE-----
        # MIIB8DCCAVkCFFKBqrdVLe1slcv4TnseuC9vtQ2vMA0GCSqGSIb3DQEBBQUAMDcx
        # NTAzBgNVBAoMLFNTTCBURVNUIFByb2plY3QgRG9kZ3kgQ2VydGlmaWNhdGUgQXV0
        # aG9yaXR5MB4XDTIwMDIyNjAzMzg1MloXDTMzMTEwNDAzMzg1MlowNzE1MDMGA1UE
        # CgwsU1NMIFRFU1QgUHJvamVjdCBEb2RneSBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkw
        # gZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAOYUKr0QfMUlzgbKh9TMhtjVtj/p
        # owFSkN3p2gMzEhZpbAmcYjcJsSdA9+lfm77rWrwOAkELLSBRR3e4P9+fc61n803F
        # rfDKTtko47URuQA6CBgbUIDZy3KDYfO4xkffSfOB1uT967iusn7Lj/6xjsJYcV+f
        # 06dkG4/WRk92r0sfAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEALj6npiVb9Gi9s6ZC
        # SlisAiukaT94ROGXfG4uNM5HIhH4DRhcgqtyvxgkFxrTxSV6psEiyH5J/CoG6NMw
        # KBP8x64RO5pwnUq6NQCFEn0QYgVkiw1JJ35ZXSTv+CbmE5Ou6MwNJGnv199i0rzt
        # READ/ppym+qwLAHJj+eTcHzD3N4=
        # -----END CERTIFICATE-----
# '''

        # "Creating a CA-signed client cert with openssl"
        # openssl genrsa -out client.key 1024
        # openssl req -new -key client.key -out client.csr \
        #   -subj '/C=NL/CN=MY-CLIENT'
        # openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key \
        #    -set_serial 01 -out client.crt
        f = open("local_client.crt")
        clientcert = f.read()
#         clientcert = '''-----BEGIN CERTIFICATE-----
# MIIB+zCCAWQCFBE3IzAOl2Dr1t2AWP/HZT7QKcLgMA0GCSqGSIb3DQEBBQUAMDcx
# NTAzBgNVBAoMLFNTTCBURVNUIFByb2plY3QgRG9kZ3kgQ2VydGlmaWNhdGUgQXV0
# aG9yaXR5MB4XDTIwMDIyNjAzMzg1M1oXDTMzMTEwNDAzMzg1M1owQjEsMCoGA1UE
# CgwjU1NMIFRFU1QgUHJvamVjdCBEZXZpY2UgQ2VydGlmaWNhdGUxEjAQBgNVBAMM
# CWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA7Bv1s3oLwC4T
# OylaCmjsGkCVHWF+GNV/PYRVXxttjrgR1YsDm36VMBN1UpcLjOMDvXnUVHZfzTIA
# 5ueGRFS2zsi3DB08mgO/49CEVq0NU0AlRHjONUfg0fmUMblmkAhsbRYr+Gq8NzcT
# 2qWWz20dzQTJBNWJ/nzlXw8y4QuWVRMCAwEAATANBgkqhkiG9w0BAQUFAAOBgQB3
# OlVJHxzFGbXotYMq0Uc0wT64G8RRO08pzjXQOuGkmSGt9CnH/v0YsJjSSjo5kHDy
# yH+t680l25Rj9NfN18KJnhRDvW7yfG/0QTgExPYVzLLBj5a2W9Dts47xA9MUPbKT
# ADyG/5QGtm7076+kgVAWwvjaaYgY3dm6+f6fIA+f5A==
# -----END CERTIFICATE-----
# '''

        ca = BaseCert.from_pem(cacert)
        cert = BaseCert.from_pem(clientcert)
        cert.set_trusted_ca(ca)

        print('Certificate:', cert)
        print('Fingerprints:', cert.get_fingerprints())
        # cert.add_revoked_fingerprint('SHA-1',
        #     cert.get_fingerprints()['SHA-1'])
        # cert.add_revoked_fingerprint(
        #     'SHA-1',
        #     '05:62:27:A5:6E:A1:52:F3:E7:E7:44:16:D6:F4:BD:27:B4:D8:1B:E5')

        cert.verify()
        print('Verification: OK')

    example()