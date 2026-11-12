"""Create a local self-signed TLS certificate with caller-selected SANs."""
import argparse, ipaddress, os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

def generate(directory: Path, dns_names=None, ip_addresses=None) -> tuple[Path, Path]:
    dns_names = list(dns_names or ["localhost"])
    ip_addresses = list(ip_addresses or [])
    directory.mkdir(parents=True, exist_ok=True)
    ca_key=rsa.generate_private_key(public_exponent=65537,key_size=3072)
    key=rsa.generate_private_key(public_exponent=65537,key_size=3072)
    subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,dns_names[0] if dns_names else "server")])
    ca_name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"Secure Network App Local CA")])
    now=datetime.now(timezone.utc)
    san=[x509.DNSName(name) for name in dns_names]+[x509.IPAddress(ipaddress.ip_address(value)) for value in ip_addresses]
    ca=(x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1))
          .not_valid_after(now+timedelta(days=3650)).add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,key_encipherment=False,
              data_encipherment=False,key_agreement=False,key_cert_sign=True,crl_sign=True,
              encipher_only=None,decipher_only=None),critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),critical=False)
          .sign(ca_key,hashes.SHA256()))
    cert=(x509.CertificateBuilder().subject_name(subject).issuer_name(ca_name).public_key(key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1))
          .not_valid_after(now+timedelta(days=365)).add_extension(x509.SubjectAlternativeName(san),critical=False)
          .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,key_encipherment=True,
              data_encipherment=False,key_agreement=False,key_cert_sign=False,crl_sign=False,
              encipher_only=None,decipher_only=None),critical=True)
          .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),critical=False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),critical=False)
          .sign(ca_key,hashes.SHA256()))
    kp,cp=directory/"server.key",directory/"server.crt"
    kp.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (directory/"ca.crt").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    try: kp.chmod(0o600)
    except OSError: pass
    return cp,kp

if __name__=="__main__":
    p=argparse.ArgumentParser(description="Створити TLS сертифікат із SAN")
    p.add_argument("--directory",default="data"); p.add_argument("--dns",action="append",default=[])
    p.add_argument("--ip",action="append",default=[]); a=p.parse_args()
    cert,key=generate(Path(a.directory),a.dns or [os.getenv("CERT_DNS","localhost")],a.ip or ([os.environ["CERT_IP"]] if os.getenv("CERT_IP") else []))
    print(f"Сертифікат: {cert}\nПриватний ключ: {key}")
