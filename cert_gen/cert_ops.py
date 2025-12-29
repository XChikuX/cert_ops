from pathlib import Path
from datetime import datetime, timedelta, timezone
import random

import socket

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dsa
from cryptography.x509.oid import NameOID



from cert_gen.cert_extensions import EXTENSIONS  # noqa



class CertGen():
    """
    Currently Supported extensions are(refer to cert_extensions.py):
    RootCA - A basic RootCA that works as a root for
             Client(TOE) as well as server. Self Signed
    IntCA  - A basic IntCA, 'Signed using RootCA'
    CN     - A basic CN that works for Client as well as Server Auth
             'Signed with either RootCA or IntCA'
    """
    # Below value is 0 indexed. Version = 2; means cert is Version 3
    Version = 2
    serialNumber = 0
    HUMAN_FORMAT = '%Y-%m-%d %H:%M:%S'
    MACHINE_FORMAT = '%Y%m%d%H%M%S%Z'

    def __init__(self):
        self.emailAddress = "netfvt@vmware.com"
        self.countryName = "US"
        self.localityName = "Palo Alto"
        self.stateOrProvinceName = "CA"
        self.organizationName = "VMware Inc."
        self.organizationUnitName = "NSBU"
        self.validityStartInSeconds = 0
        self.validityEndInSeconds = 10 * 365 * 24 * 60 * 60
        self.rootca = {}
        self.intca = {}

    def __allocate_serial_number(self):
        """
        Function that increments and returns a new serial number
        """
        self.serialNumber += 1
        return self.serialNumber

    def create_cert_chain(self, root_path,
                          cn_path=None, int_path=None):
        """
        Function that takes 2 or 3 certificates to
        generate a valid certificate chain.
        Note: Providing CN to server chain is optional.
        """
        cert_chain = []
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
        # Return the generated cert_chain
        return "{}".format("".join(cert_chain))

    def get_api_compatible(self, content):
        """
        Function that takes a path or certificate/pk content
        to generate a valid certificate for API consumption
        """
        if isinstance(content, Path) or '\n' not in content:
            with open(content) as f:
                content = f.read()
        restructured_content = []
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
                # Ensure line is not ''
                if line:
                    restructured_content.append(line)
        # Returns a string capable of being sent over API call.
        return "{}".format("".join(restructured_content[0:-1]))

    def dump_cert_chain(self, cert_path, cert_chain, basedir="/tmp/"):
        """ Dump cert chain to desired path """
        file_path = basedir / cert_path
        with open(file_path, "wt") as f:
            f.write(cert_chain)
        return file_path

    def default_self_signed(self):
        """ A simple, valid self-signed certificate is returned """
        cn = socket.gethostbyname(socket.gethostname() + '.local')
        return self.cert_gen(cn, cert_category="RootCA")

    def obj2pem(self, crypto_obj, pem_file, form, basedir="/tmp/"):
        """
        convert a certificate or private key object to PEM file
        """
        if isinstance(basedir, str):
            basedir = Path(basedir)
        with open(basedir / pem_file, "wb") as f:
            if form.lower() == 'cert':
                f.write(crypto_obj.public_bytes(serialization.Encoding.PEM))
            elif form.lower() == 'key':
                f.write(crypto_obj.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            elif form.lower() == 'crl':
                f.write(crypto_obj.public_bytes(serialization.Encoding.PEM))
            else:
                raise ValueError('For argument "form": \
                                 Acceptable inputs are "cert" | "key" | "crl"')
        return pem_file

    def cert_gen(self, commonName, crl_uri=None,
                 key_length=4096, signing_algo="sha512",
                 validityEndInSeconds=None, key_type="rsa",
                 cert_category="RootCA", basedir="/tmp/"):
        """
        Generates a certificate based on the given common name
        and certains defaults.
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

        if key_type not in ('rsa', 'dsa'):
            raise ValueError('Parameter error: key type must be rsa|dsa')
            
        cert_path = Path(commonName + str(".crt"))
        key_path = Path(commonName + str(".pem"))

        # Generate Key
        if key_type.lower() == 'rsa':
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_length
            )
        elif key_type.lower() == 'dsa':
            key = dsa.generate_private_key(
                key_size=key_length
            )

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
            cert = builder.sign(
                private_key=key, algorithm=hash_algorithm
            )
            self.rootca['pkey'] = key
            self.rootca['cert'] = cert

        elif EXTENSIONS[cert_category]['type'] == "Intermediate":
            if not self.rootca:
                 raise ValueError("RootCA must be present to sign Intermediate")
            
            builder = builder.issuer_name(self.rootca['cert'].subject)
            if self.intca:
                raise ValueError("IntCA already present")
                
            cert = builder.sign(
                private_key=self.rootca['pkey'], algorithm=hash_algorithm
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
            
            cert = builder.sign(
                private_key=signing_key, algorithm=hash_algorithm
            )
        else:
            raise ValueError(f"Unknown cert category: {cert_category}")

        self.obj2pem(cert, cert_path, "cert", basedir=basedir)
        self.obj2pem(key, key_path, "key", basedir=basedir)
        return basedir / cert_path, basedir / key_path

    def csr_signing(self, CACertFile, CAKeyFile, csr, notBefore, validityDays,
                    signedCertFile, digest):
        """
        Function which signs a CSR with the private key of the root and digest
        CACertFile: the file path of the CA cert
        CAKeyFile:  the file path of the CA private key
        csr:        signing request in pem format string
        notBefore:  a date in the format of YYYY-MM-DD HH:MM:SS
        days:       integer. the validity of the cert in terms of days
        digest:     signature algorithm sha1|sha224|sha256|sha384|sha512
        Return:     the signed cert in PEM string
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
        
        # Hash algo
        hash_algo_map = {
            'sha1': hashes.SHA1(),
            'sha224': hashes.SHA224(),
            'sha256': hashes.SHA256(),
            'sha384': hashes.SHA384(),
            'sha512': hashes.SHA512()
        }
        hash_algorithm = hash_algo_map.get(digest, hashes.SHA512())

        cert = builder.sign(private_key=ca_key, algorithm=hash_algorithm)
        
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        with open(signedCertFile, 'wb') as h:
            h.write(cert_pem)
            
        return cert_pem.decode('utf-8')

    def crl_gen(self, authCert, authKey, serial, lastUpdate, nextUpdate,
                revokedFile, digest, base_dir='/tmp/'):
        """
        Revoke a certificate and generate a new certificate revocation list (CRL)
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
            
            # Create RevokedCertificateBuilder
            revoked_builder = x509.RevokedCertificateBuilder()
            revoked_builder = revoked_builder.serial_number(revoked_cert.serial_number)
            revoked_builder = revoked_builder.revocation_date(datetime.now(timezone.utc))
            builder = builder.add_revoked_certificate(revoked_builder.build())
        
        hash_algo_map = {
            'sha1': hashes.SHA1(),
            'sha224': hashes.SHA224(),
            'sha256': hashes.SHA256(),
            'sha384': hashes.SHA384(),
            'sha512': hashes.SHA512()
        }
        hash_algorithm = hash_algo_map.get(digest, hashes.SHA512())

        crl = builder.sign(private_key=ca_key, algorithm=hash_algorithm)
        
        # File naming logic preserved but using Path
        auth_path = Path(authCert)
        stem = auth_path.stem.replace('.crt', '') # handle double extensions if needed or just simple
        if stem.endswith('.crt'): stem = stem[:-4]
        
        crlFile = Path(base_dir) / f"{stem}.crl"
        
        # obj2pem handles saving
        # We pass basedir="" because we constructed the full path in crlFile (assuming base_dir was absolute)
        # If base_dir is relative, it still works.
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
