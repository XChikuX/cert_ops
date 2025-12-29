from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Union, Literal
import random
import socket

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519, ed448
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.x509.oid import NameOID

from cert_gen.cert_extensions import EXTENSIONS  # noqa

# Type aliases
KeyType = Literal["rsa", "dsa", "ed25519", "ecdsa", "ed448"]
HashAlgo = Literal["sha1", "sha224", "sha256", "sha384", "sha512"]
CertCategory = Literal["RootCA", "IntCA", "CN"]
FormType = Literal["cert", "key", "crl"]
PathLike = Union[str, Path]



class CertGen:
    """
    Certificate generator supporting multiple key types.

    Supported extensions (refer to cert_extensions.py):
        RootCA - A basic RootCA that works as a root for Client(TOE) as well as server. Self Signed
        IntCA  - A basic IntCA, 'Signed using RootCA'
        CN     - A basic CN that works for Client as well as Server Auth 'Signed with either RootCA or IntCA'

    Supported key types:
        ed25519 - Curve25519 (default, recommended)
        ed448   - Curve448
        ecdsa   - ECDSA with SECP256R1 curve
        rsa     - RSA (legacy)
        dsa     - DSA (legacy)
    """

    # Below value is 0 indexed. Version = 2; means cert is Version 3
    Version: int = 2
    serialNumber: int = 0
    HUMAN_FORMAT: str = '%Y-%m-%d %H:%M:%S'
    MACHINE_FORMAT: str = '%Y%m%d%H%M%S%Z'

    def __init__(self) -> None:
        self.emailAddress: str = "test@example.com"
        self.countryName: str = "US"
        self.localityName: str = "Palo Alto"
        self.stateOrProvinceName: str = "CA"
        self.organizationName: str = "Meow Inc."
        self.organizationUnitName: str = "Cert Dept."
        self.validityStartInSeconds: int = 0
        self.validityEndInSeconds: int = 10 * 365 * 24 * 60 * 60
        self.rootca: dict[str, x509.Certificate | PrivateKeyTypes] = {}
        self.intca: dict[str, x509.Certificate | PrivateKeyTypes] = {}

    def __allocate_serial_number(self) -> int:
        """Increment and return a new serial number."""
        self.serialNumber += 1
        return self.serialNumber

    def create_cert_chain(
        self,
        root_path: PathLike,
        cn_path: PathLike | None = None,
        int_path: PathLike | None = None
    ) -> str:
        """
        Create a certificate chain from 2 or 3 certificates.

        Args:
            root_path: Path to root CA certificate
            cn_path: Path to leaf/CN certificate (optional)
            int_path: Path to intermediate CA certificate (optional)

        Returns:
            PEM-formatted certificate chain as string
        """
        cert_chain: list[str] = []
        if cn_path or int_path:
            if cn_path:
                with open(cn_path) as f:
                    for line in f:
                        cert_chain.append(line)
            # If present add IntCA to the chain
            if int_path:
                with open(int_path) as f:
                    for line in f:
                        cert_chain.append(line)
        else:
            raise ValueError('The paths to intCA, CN cannot both be empty')
        with open(root_path) as f:
            for line in f:
                cert_chain.append(line)
        return "".join(cert_chain)

    def get_api_compatible(self, content: PathLike | str) -> str:
        """
        Transform certificate/key content for API consumption.

        Args:
            content: Path to file or PEM content string

        Returns:
            Restructured PEM string suitable for API calls
        """
        if isinstance(content, Path) or '\n' not in content:
            with open(content) as f:
                content = f.read()
        restructured_content: list[str] = []
        lines = content.split('\n')
        for line in lines:
            if line in ["-----BEGIN CERTIFICATE-----",
                        "-----BEGIN PRIVATE KEY-----",
                        "-----BEGIN CERTIFICATE REQUEST-----"]:
                restructured_content.append(line)
                restructured_content.append('\n')
            elif line in ["-----END CERTIFICATE-----",
                          "-----END PRIVATE KEY-----",
                          "-----END CERTIFICATE REQUEST-----"]:
                restructured_content.append('\n')
                restructured_content.append(line)
                restructured_content.append('\n')
            else:
                if line:
                    restructured_content.append(line)
        return "".join(restructured_content[0:-1])

    def dump_cert_chain(
        self,
        cert_path: PathLike,
        cert_chain: str,
        basedir: PathLike = "/tmp/"
    ) -> Path:
        """
        Write certificate chain to file.

        Args:
            cert_path: Output file name
            cert_chain: PEM certificate chain content
            basedir: Base directory for output

        Returns:
            Path to the created file
        """
        if isinstance(basedir, str):
            basedir = Path(basedir)
        file_path = basedir / cert_path
        with open(file_path, "wt") as f:
            f.write(cert_chain)
        return file_path

    def default_self_signed(self) -> tuple[Path, Path]:
        """
        Generate a simple self-signed certificate using the local hostname.

        Returns:
            Tuple of (certificate_path, key_path)
        """
        cn = socket.gethostbyname(socket.gethostname() + '.local')
        return self.cert_gen(cn, cert_category="RootCA")

    def obj2pem(
        self,
        crypto_obj: x509.Certificate | PrivateKeyTypes | x509.CertificateRevocationList,
        pem_file: PathLike,
        form: FormType,
        basedir: PathLike = "/tmp/"
    ) -> Path:
        """
        Convert a certificate, private key, or CRL object to PEM file.

        Args:
            crypto_obj: Certificate, private key, or CRL object
            pem_file: Output file name
            form: Type of object ('cert', 'key', or 'crl')
            basedir: Base directory for output

        Returns:
            Path to the created PEM file
        """
        if isinstance(basedir, str):
            basedir = Path(basedir)
        if isinstance(pem_file, str):
            pem_file = Path(pem_file)

        output_path = basedir / pem_file
        with open(output_path, "wb") as f:
            if form.lower() == 'cert':
                f.write(crypto_obj.public_bytes(serialization.Encoding.PEM))
            elif form.lower() == 'key':
                # EdDSA keys (Ed25519/Ed448) don't support TraditionalOpenSSL format
                # Use PKCS8 for all key types for consistency
                f.write(crypto_obj.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            elif form.lower() == 'crl':
                f.write(crypto_obj.public_bytes(serialization.Encoding.PEM))
            else:
                raise ValueError('For argument "form": Acceptable inputs are "cert" | "key" | "crl"')
        return output_path

    def cert_gen(
        self,
        commonName: str,
        crl_uri: str | None = None,
        key_length: int = 4096,
        signing_algo: HashAlgo = "sha512",
        validityEndInSeconds: int | None = None,
        key_type: KeyType = "ed25519",
        cert_category: CertCategory = "RootCA",
        basedir: PathLike = "/tmp/"
    ) -> tuple[Path, Path]:
        """
        Generate a certificate with the given common name.

        Args:
            commonName: Common name for the certificate
            crl_uri: CRL URI (optional)
            key_length: Key length for RSA/DSA (ignored for EdDSA curves)
            signing_algo: Hash algorithm (sha1|sha224|sha256|sha384|sha512)
                         Note: Ignored for Ed25519/Ed448 (EdDSA has built-in hash)
            validityEndInSeconds: Validity period override
            key_type: Key type (ed25519|ed448|ecdsa|rsa|dsa). Default: ed25519
            cert_category: Certificate category (RootCA|IntCA|CN)
            basedir: Output directory for certificates

        Returns:
            Tuple of (certificate_path, key_path)
        """
        if key_length not in [1024, 2048, 3074, 4096]:
            raise ValueError('Parameter error: key length must be 1024|2048|3072|4096')
        
        # Map string algo to hashes class
        hash_algo_map = {
            'sha1': hashes.SHA1(),
            'sha224': hashes.SHA224(),
            'sha256': hashes.SHA256(),
            'sha384': hashes.SHA384(),
            'sha512': hashes.SHA512()
        }
        if signing_algo not in hash_algo_map:
            raise ValueError('Parameter error: signature algorithms must be sha1|sha224|sha256|sha384|sha512')
        
        hash_algorithm = hash_algo_map[signing_algo]

        if key_type not in ('rsa', 'dsa', 'ed25519', 'ecdsa', 'ed448'):
            raise ValueError('Parameter error: key type must be rsa|dsa|ed25519|ecdsa|ed448')
            
        cert_path = Path(commonName + str(".crt"))
        key_path = Path(commonName + str(".pem"))

        # Generate Key
        match key_type.lower():
            case 'ed25519':
                # Ed25519 uses Curve25519, fixed key size
                key = ed25519.Ed25519PrivateKey.generate()
            case 'ed448':
                # Ed448 uses Curve448, fixed key size
                key = ed448.Ed448PrivateKey.generate()
            case 'ecdsa':
                # ECDSA with SECP256R1 (prime256v1) curve as default
                key = ec.generate_private_key(ec.SECP256R1())
            case 'rsa':
                key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=key_length
                )
            case 'dsa':
                key = dsa.generate_private_key(
                    key_size=key_length
                )
            case _:
                raise ValueError('Parameter error: key type must be rsa|dsa|ed25519|ecdsa|ed448')

        # Create Builder
        builder = x509.CertificateBuilder()
        builder = builder.serial_number(self.__allocate_serial_number()) # Or x509.random_serial_number()
        
        # Subject
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, self.countryName),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.stateOrProvinceName),
            x509.NameAttribute(NameOID.LOCALITY_NAME, self.localityName),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.organizationName),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, self.organizationUnitName),
            x509.NameAttribute(NameOID.COMMON_NAME, commonName),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, self.emailAddress),
        ])
        builder = builder.subject_name(subject)
        builder = builder.public_key(key.public_key())

        # Validity
        now = datetime.now(timezone.utc)
        builder = builder.not_valid_before(now)
        
        # Calculate NotAfter
        if validityEndInSeconds:
             builder = builder.not_valid_after(now + timedelta(seconds=validityEndInSeconds))
        else:
             if EXTENSIONS[cert_category]['type'] == "Intermediate":
                 builder = builder.not_valid_after(now + timedelta(seconds=int(self.validityEndInSeconds / 2)))
             elif EXTENSIONS[cert_category]['type'] == "Leaf":
                 builder = builder.not_valid_after(now + timedelta(days=825))
             else:
                 builder = builder.not_valid_after(now + timedelta(seconds=self.validityEndInSeconds))

        # Add Extensions
        for ext_config in EXTENSIONS[cert_category]['parameters']:
            builder = builder.add_extension(
                ext_config['extension'], critical=ext_config['critical']
            )

        # Signing Logic
        if EXTENSIONS[cert_category]['type'] == "Root":
            builder = builder.issuer_name(subject)
            if self.rootca:
                raise ValueError("RootCA already present")

            # Root signs itself
            # Ed25519/Ed448 use None as algorithm (EdDSA is built-in)
            sign_algo = None if key_type.lower() in ('ed25519', 'ed448') else hash_algorithm
            cert = builder.sign(
                private_key=key, algorithm=sign_algo
            )
            self.rootca['pkey'] = key
            self.rootca['cert'] = cert

        elif EXTENSIONS[cert_category]['type'] == "Intermediate":
            if not self.rootca:
                 raise ValueError("RootCA must be present to sign Intermediate")

            builder = builder.issuer_name(self.rootca['cert'].subject)
            if self.intca:
                raise ValueError("IntCA already present")

            # Determine signing algorithm based on the signing key type
            sign_algo = None if isinstance(self.rootca['pkey'], (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)) else hash_algorithm
            cert = builder.sign(
                private_key=self.rootca['pkey'], algorithm=sign_algo
            )
            self.intca['pkey'] = key
            self.intca['cert'] = cert

        elif EXTENSIONS[cert_category]['type'] == "Leaf":
            if self.intca:
                builder = builder.issuer_name(self.intca['cert'].subject)
                signing_key = self.intca['pkey']
            elif self.rootca:
                builder = builder.issuer_name(self.rootca['cert'].subject)
                signing_key = self.rootca['pkey']
            else:
                raise ValueError('Leaf cannot be self signed')

            # Determine signing algorithm based on the signing key type
            sign_algo = None if isinstance(signing_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)) else hash_algorithm
            cert = builder.sign(
                private_key=signing_key, algorithm=sign_algo
            )
        else:
            raise ValueError(f"Unknown cert category: {cert_category}")

        self.obj2pem(cert, cert_path, "cert", basedir=basedir)
        self.obj2pem(key, key_path, "key", basedir=basedir)
        return basedir / cert_path, basedir / key_path

    def csr_signing(
        self,
        CACertFile: PathLike,
        CAKeyFile: PathLike,
        csr: str | bytes,
        notBefore: str,
        validityDays: int,
        signedCertFile: PathLike,
        digest: HashAlgo
    ) -> str:
        """
        Sign a CSR with the CA's private key.

        Args:
            CACertFile: Path to the CA certificate
            CAKeyFile: Path to the CA private key
            csr: CSR in PEM format (string or bytes)
            notBefore: Start date in format 'YYYY-MM-DD HH:MM:SS'
            validityDays: Validity period in days
            signedCertFile: Output path for signed certificate
            digest: Hash algorithm (sha1|sha224|sha256|sha384|sha512)
                   Note: Ignored for EdDSA keys

        Returns:
            Signed certificate in PEM format
        """
        notBeforeObj = datetime.strptime(notBefore, self.HUMAN_FORMAT).replace(tzinfo=timezone.utc)
        notAfterObj = notBeforeObj + timedelta(days=validityDays)

        # Load CA Key
        with open(CAKeyFile, 'rb') as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)

        # Load CA Cert
        with open(CACertFile, 'rb') as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())

        # Load CSR
        csr_bytes = csr.encode('utf-8') if isinstance(csr, str) else csr
        csr_obj = x509.load_pem_x509_csr(csr_bytes)

        # Build Cert
        builder = (x509.CertificateBuilder()
                   .subject_name(csr_obj.subject)
                   .issuer_name(ca_cert.subject)
                   .public_key(csr_obj.public_key())
                   .serial_number(random.randint(0, 4294967295))
                   .not_valid_before(notBeforeObj)
                   .not_valid_after(notAfterObj))

        # Hash algo - None for EdDSA keys
        hash_algo_map: dict[str, hashes.HashAlgorithm] = {
            'sha1': hashes.SHA1(),
            'sha224': hashes.SHA224(),
            'sha256': hashes.SHA256(),
            'sha384': hashes.SHA384(),
            'sha512': hashes.SHA512()
        }
        hash_algorithm: hashes.HashAlgorithm | None = hash_algo_map.get(digest, hashes.SHA512())

        # EdDSA keys use None as algorithm
        if isinstance(ca_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
            hash_algorithm = None

        cert = builder.sign(private_key=ca_key, algorithm=hash_algorithm)

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        with open(signedCertFile, 'wb') as h:
            h.write(cert_pem)

        return cert_pem.decode('utf-8')

    def crl_gen(
        self,
        authCert: PathLike,
        authKey: PathLike,
        serial: int,
        lastUpdate: str,
        nextUpdate: str,
        revokedFile: PathLike | None,
        digest: HashAlgo,
        base_dir: PathLike = '/tmp/'
    ) -> str:
        """
        Generate a Certificate Revocation List (CRL).

        Args:
            authCert: Path to the CA certificate
            authKey: Path to the CA private key
            serial: Serial number (unused, kept for compatibility)
            lastUpdate: Last update date in format 'YYYY-MM-DD HH:MM:SS'
            nextUpdate: Next update date in format 'YYYY-MM-DD HH:MM:SS'
            revokedFile: Path to certificate to revoke (optional)
            digest: Hash algorithm (sha1|sha224|sha256|sha384|sha512)
                   Note: Ignored for EdDSA keys
            base_dir: Output directory

        Returns:
            Path to the generated CRL file
        """
        lastUpdateObj = datetime.strptime(lastUpdate, self.HUMAN_FORMAT).replace(tzinfo=timezone.utc)
        nextUpdateObj = datetime.strptime(nextUpdate, self.HUMAN_FORMAT).replace(tzinfo=timezone.utc)

        # Load Auth Cert and Key
        with open(authCert, 'rb') as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        with open(authKey, 'rb') as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)

        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(ca_cert.subject)
        builder = builder.last_update(lastUpdateObj)
        builder = builder.next_update(nextUpdateObj)

        if revokedFile:
            with open(revokedFile, 'rb') as f:
                revoked_cert = x509.load_pem_x509_certificate(f.read())

            revoked_builder = x509.RevokedCertificateBuilder()
            revoked_builder = revoked_builder.serial_number(revoked_cert.serial_number)
            revoked_builder = revoked_builder.revocation_date(datetime.now(timezone.utc))
            builder = builder.add_revoked_certificate(revoked_builder.build())

        hash_algo_map: dict[str, hashes.HashAlgorithm] = {
            'sha1': hashes.SHA1(),
            'sha224': hashes.SHA224(),
            'sha256': hashes.SHA256(),
            'sha384': hashes.SHA384(),
            'sha512': hashes.SHA512()
        }
        hash_algorithm: hashes.HashAlgorithm | None = hash_algo_map.get(digest, hashes.SHA512())

        # EdDSA keys use None as algorithm
        if isinstance(ca_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
            hash_algorithm = None

        crl = builder.sign(private_key=ca_key, algorithm=hash_algorithm)

        # File naming logic
        auth_path = Path(authCert) if isinstance(authCert, str) else authCert
        stem = auth_path.stem.replace('.crt', '')
        if stem.endswith('.crt'):
            stem = stem[:-4]

        crlFile = Path(base_dir) / f"{stem}.crl"

        self.obj2pem(crl, crlFile, 'crl', basedir="")
        return str(crlFile)


if __name__ == "__main__":
    # Examples of what can be done
    certificate = CertGen()
    # Currently supports only one IntCA
    root_cert_path, root_key_path = certificate.cert_gen("RootCA", cert_category="RootCA")
    int_cert_path, int_key_path = certificate.cert_gen("IntCA", cert_category="IntCA")
    cn_cert_path, cn_key_path = certificate.cert_gen("10.40.71.224", cert_category="CN")

    cert_chain = certificate.create_cert_chain(root_cert_path,
                                               cn_path=cn_cert_path,
                                               int_path=int_cert_path)

    certificate.dump_cert_chain(Path("cert_chain.crt"), cert_chain)
    # repr() Not required in API call.
    print(repr(certificate.get_api_compatible(cert_chain)))
