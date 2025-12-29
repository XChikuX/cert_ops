from pathlib import Path
from datetime import datetime, timedelta
import random
import re
import socket

from OpenSSL import crypto

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
        with open(basedir / pem_file, "wt") as f:
            if form.lower() == 'cert':
                f.write(crypto.dump_certificate(
                        crypto.FILETYPE_PEM, crypto_obj).decode('utf-8'))
            elif form.lower() == 'key':
                f.write(crypto.dump_privatekey(
                        crypto.FILETYPE_PEM, crypto_obj).decode('utf-8'))
            elif form.lower() == 'crl':
                f.write(crypto.dump_crl(
                        crypto.FILETYPE_PEM, crypto_obj).decode('utf-8'))
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
        It should be enough to change these defaults by changing the extension.

        countryName - The country of the entity.
        C - Alias for countryName.
        stateOrProvinceName - The state or province of the entity.
        ST - Alias for stateOrProvinceName.
        localityName - The locality of the entity.
        L - Alias for localityName.
        organizationName - The organization name of the entity.
        O - Alias for organizationName.
        organizationalUnitName - The organizational unit of the entity.
        OU - Alias for organizationalUnitName
        commonName - The common name of the entity.
        CN - Alias for commonName.
        emailAddress - The e-mail address of the entity.
        """
        if key_length not in [1024, 2048, 3074, 4096]:
            raise ValueError('Parameter error: key length must be 1024|2048|\
                             3072|4096')
        if signing_algo not in ['sha1', 'sha224', 'sha256', 'sha384', 'sha512']:
            raise ValueError('Parameter error: signature algorithms must be \
                             sha1|sha224|sha256|sha384|sha512')
        if key_type not in ('rsa', 'dsa'):
            raise ValueError('Parameter error: key type must be rsa|dsa')
        cert_path = Path(commonName + str(".crt"))
        key_path = Path(commonName + str(".pem"))
        # can look at generated file using openssl:
        # openssl x509 -inform pem -in selfsigned.crt -noout -text
        # create a key pair
        key = crypto.PKey()
        if key_type.lower() == 'rsa':
            key.generate_key(crypto.TYPE_RSA, key_length)
        elif key_type.lower() == 'dsa':
            key.generate_key(crypto.TYPE_DSA, key_length)
        else:
            raise ValueError('Invalid key type, must be either "rsa" or "dsa"')
        # create a self-signed cert
        cert = crypto.X509()
        cert.set_version(self.Version)
        cert.get_subject().C = self.countryName
        cert.get_subject().ST = self.stateOrProvinceName
        cert.get_subject().L = self.localityName
        cert.get_subject().organizationName = self.organizationName
        cert.get_subject().OU = self.organizationUnitName
        cert.get_subject().CN = commonName  # Should be TOI/server IP in case of leaf
        cert.get_subject().emailAddress = self.emailAddress
        cert.set_serial_number(self.__allocate_serial_number())

        # Set the pub key
        cert.set_pubkey(key)

        # TODO(@gsrikanth) Allow for expired certs to be generated
        if EXTENSIONS[cert_category]['type'] == "Root":
            if validityEndInSeconds:
                # In case of expired this value will need to be changed
                cert.gmtime_adj_notBefore(0)
                cert.gmtime_adj_notAfter(validityEndInSeconds)
            else:
                cert.gmtime_adj_notBefore(0)
                cert.gmtime_adj_notAfter(self.validityEndInSeconds)
            cert.add_extensions(EXTENSIONS[cert_category]['parameters'])
            cert.set_issuer(cert.get_subject())
            if self.rootca:
                raise ValueError("RootCA already present")
            cert.sign(key, signing_algo)
            self.rootca['pkey'] = key
            self.rootca['cert'] = cert

        elif EXTENSIONS[cert_category]['type'] == "Intermediate":
            if validityEndInSeconds:
                cert.gmtime_adj_notBefore(0)
                cert.gmtime_adj_notAfter(validityEndInSeconds)
            else:
                cert.gmtime_adj_notBefore(0)
                # Intermediate Validity is x0.5 of Root
                cert.gmtime_adj_notAfter(int(self.validityEndInSeconds / 2))
            cert.add_extensions(EXTENSIONS[cert_category]['parameters'])
            cert.set_issuer(self.rootca['cert'].get_subject())
            if self.intca:
                raise ValueError("IntCA already present")
            cert.sign(self.rootca['pkey'], signing_algo)
            self.intca['pkey'] = key
            self.intca['cert'] = cert

        elif EXTENSIONS[cert_category]['type'] == "Leaf":
            if validityEndInSeconds:
                cert.gmtime_adj_notBefore(0)
                cert.gmtime_adj_notAfter(validityEndInSeconds)
            else:
                cert.gmtime_adj_notBefore(0)
                # Leaf Validity is 825 days
                cert.gmtime_adj_notAfter(825 * 24 * 60 * 60)
            cert.add_extensions(EXTENSIONS[cert_category]['parameters'])
            if self.intca:
                cert.set_issuer(self.intca['cert'].get_subject())
                cert.sign(self.intca['pkey'], signing_algo)
            elif self.rootca:
                cert.set_issuer(self.rootca['cert'].get_subject())
                cert.sign(self.rootca['pkey'], signing_algo)
            else:
                raise ValueError('Leaf cannot be self signed')

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
        notBeforeObj = datetime.strptime(notBefore, self.HUMAN_FORMAT)
        notAfterObj = timedelta(days=validityDays) + notBeforeObj
        notBefore = notBeforeObj.strftime(self.MACHINE_FORMAT)
        notAfter = notAfterObj.strftime(self.MACHINE_FORMAT)

        with open(CAKeyFile, 'r') as f:
            CAKey = f.read()
        with open(CACertFile, 'rb') as g:
            CACert = g.read()
        reqObj = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr)
        keyObj = crypto.load_privatekey(crypto.FILETYPE_PEM, CAKey)
        crtObj = crypto.load_certificate(crypto.FILETYPE_PEM, CACert)
        cert = crypto.X509()
        cert.set_serial_number(random.randint(0, 4294967295))
        cert.set_notBefore(bytes(notBefore, encoding='utf-8'))
        cert.set_notAfter(bytes(notAfter, encoding='utf-8'))
        cert.set_issuer(crtObj.get_subject())
        cert.set_subject(reqObj.get_subject())
        cert.set_pubkey(reqObj.get_pubkey())
        cert.sign(keyObj, digest)
        certStr = (crypto.dump_certificate(crypto.FILETYPE_PEM, cert).
                   decode('utf-8'))
        with open(signedCertFile, 'w') as h:
            h.write(certStr)
        return certStr

    def crl_gen(self, authCert, authKey, serial, lastUpdate, nextUpdate,
                revokedFile, digest, base_dir='/tmp/'):
        """
        Revoke a certificate and generate a new certificate revocation
        list (CRL)
        If 'revokeFile' is None, revoke nothing but updating the CRL
        Arguments: issuerCert  - Authority cert's location
                                 e.g. '/tmp/RootCA.crt'
                   issuerKey   - Authority key's location
                                 e.g. '/tmp/RootCA.pem'
                   serial      - Serial number for the crl
                   lastUpdate  - Last crl update in format YYYY-MM-DD hh:mm:ss
                   nextUpdate  - Next crl update in format YYYY-MM-DD hh:mm:ss
                   revokedFile - certificate to be revoked
                                 e.g. '/tmp/leaf.crt'.
                   digest      - Digest method to use for signing
        Returns:   A crl in pem format, signed by authCert
        """
        lastUpdateObj = datetime.strptime(lastUpdate, self.HUMAN_FORMAT)
        nextUpdateObj = datetime.strptime(nextUpdate, self.HUMAN_FORMAT)
        lastU = bytes(lastUpdateObj.strftime(self.MACHINE_FORMAT), encoding='utf-8')
        nextU = bytes(nextUpdateObj.strftime(self.MACHINE_FORMAT), encoding='utf-8')
        now = datetime.now()

        revoked = crypto.Revoked()
        if revokedFile is None:
            revoked.set_serial(b'0')
            revoked.set_reason(None)
        else:
            revokedCert = self.pem2obj(revokedFile)
            revoked.set_serial(bytes(hex(revokedCert.get_serial_number())[2:],
                               encoding='utf-8'))
            revoked.set_reason(b'keyCompromise')
        revoked.set_rev_date(bytes(now.strftime(self.MACHINE_FORMAT),
                             encoding='utf-8'))

        parentCert = self.pem2obj(authCert)
        parentKey = self.pem2obj(authKey)
        crl = crypto.CRL()
        crl.set_lastUpdate(lastU)
        crl.set_nextUpdate(nextU)
        crl.add_revoked(revoked)
        crl.sign(parentCert, parentKey, bytes(digest, encoding='utf-8'))
        crl.set_version(1)
        authFile = re.sub(r'/tmp/', '', authCert)
        authFile = re.sub(r'\.crt', '', authFile)
        crlFile = base_dir + authFile + '.crl'
        self.obj2pem(crl, crlFile, 'crl')
        return crlFile


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
