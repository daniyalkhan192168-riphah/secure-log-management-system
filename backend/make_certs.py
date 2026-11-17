#!/usr/bin/env python3
"""
Creates the certificates for HTTPS:

  a private certificate authority, "SecureLog Local CA"
      - name-constrained: it can ONLY issue certificates for localhost and
        the addresses listed below, so even a stolen CA key cannot be used
        to impersonate any other website;
  a server certificate for the backend, signed by that CA.

Run from the backend folder (needs: pip install cryptography):

    python make_certs.py                       # localhost, 127.0.0.1, 10.0.2.2, 192.168.56.1
    python make_certs.py --ip 192.168.1.20     # also allow another address
    python make_certs.py --new-ca              # start over with a brand-new CA

Files in backend/tls/ (never commit them):
    ca.crt       give to every agent; import into Windows for the dashboard
    ca.key       the CA's private key, only needed to issue new server certificates
    server.crt   used by uvicorn (--ssl-certfile)
    server.key   used by uvicorn (--ssl-keyfile)

Running it again re-uses the existing CA, so agents keep working; it only
issues a fresh server certificate (they expire after 397 days).
"""
import argparse
import datetime
import hashlib
import ipaddress
import os
import sys

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
except ImportError:
    sys.exit("The 'cryptography' package is missing. Run:  pip install cryptography")

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_IPS = ["127.0.0.1", "10.0.2.2", "192.168.56.1"]
DEFAULT_DNS = ["localhost"]
CA_DAYS = 3650
SERVER_DAYS = 397            # browsers reject server certificates valid for longer


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _write(path, data: bytes, private: bool = False):
    with open(path, "wb") as f:
        f.write(data)
    if private:
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


def _key_pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def make_ca(ips, dns):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SecureLog Local CA"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureLog FYP")])
    permitted = ([x509.DNSName(d) for d in dns] +
                 [x509.IPAddress(ipaddress.ip_network(f"{ip}/32")) for ip in ips])
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_now() - datetime.timedelta(minutes=5))
            .not_valid_after(_now() + datetime.timedelta(days=CA_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, key_cert_sign=True, crl_sign=True,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.NameConstraints(permitted_subtrees=permitted,
                                                excluded_subtrees=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    return key, cert


def make_server(ca_key, ca_cert, ips, dns):
    key = ec.generate_private_key(ec.SECP256R1())
    sans = [x509.DNSName(d) for d in dns] + [x509.IPAddress(ipaddress.ip_address(ip)) for ip in ips]
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SecureLog backend")]))
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_now() - datetime.timedelta(minutes=5))
            .not_valid_after(_now() + datetime.timedelta(days=SERVER_DAYS))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, key_cert_sign=False, crl_sign=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                           critical=False)
            .sign(ca_key, hashes.SHA256()))
    return key, cert


def main():
    ap = argparse.ArgumentParser(description="Create HTTPS certificates for SecureLog")
    ap.add_argument("--ip", action="append", default=[], help="extra IP address (repeatable)")
    ap.add_argument("--dns", action="append", default=[], help="extra host name (repeatable)")
    ap.add_argument("--new-ca", action="store_true", help="replace the CA (agents need the new ca.crt)")
    ap.add_argument("--out", default=os.path.join(HERE, "tls"))
    args = ap.parse_args()

    ips = list(dict.fromkeys(DEFAULT_IPS + args.ip))
    dns = list(dict.fromkeys(DEFAULT_DNS + args.dns))
    os.makedirs(args.out, exist_ok=True)
    ca_crt, ca_key_path = os.path.join(args.out, "ca.crt"), os.path.join(args.out, "ca.key")

    if os.path.exists(ca_crt) and os.path.exists(ca_key_path) and not args.new_ca:
        with open(ca_key_path, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(ca_crt, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        print("Re-using the existing CA (agents keep working).")
        if args.ip or args.dns:
            print("Note: new addresses are only allowed if the CA was created with them; "
                  "otherwise run again with --new-ca.")
    else:
        ca_key, ca_cert = make_ca(ips, dns)
        _write(ca_key_path, _key_pem(ca_key), private=True)
        _write(ca_crt, ca_cert.public_bytes(serialization.Encoding.PEM))
        print("Created a new CA: SecureLog Local CA")

    key, cert = make_server(ca_key, ca_cert, ips, dns)
    _write(os.path.join(args.out, "server.key"), _key_pem(key), private=True)
    _write(os.path.join(args.out, "server.crt"), cert.public_bytes(serialization.Encoding.PEM))

    fp = hashlib.sha256(ca_cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    print(f"Server certificate valid for: {', '.join(dns + ips)}")
    print(f"Server certificate expires:   {cert.not_valid_after_utc:%Y-%m-%d}")
    print(f"CA fingerprint (SHA-256):     {':'.join(fp[i:i + 2] for i in range(0, 16, 2))}...")
    print(f"Files written to {args.out}")


if __name__ == "__main__":
    main()