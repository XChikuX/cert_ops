from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

# To create your extension:
# Add a type: Root, Intermediate, Leaf
# followed by the parameters as a list of dictionaries with 'extension' (x509 object) and 'critical' (bool).

EXTENSIONS = {
    "RootCA":
    {
        "type": "Root",
        "parameters":
            [
                {
                    "extension": x509.BasicConstraints(ca=True, path_length=None),
                    "critical": True
                },
                {
                    "extension": x509.KeyUsage(
                        digital_signature=True,
                        content_commitment=False,
                        key_encipherment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=True,
                        crl_sign=True,
                        encipher_only=False,
                        decipher_only=False
                    ),
                    "critical": True
                },
            ]
    },
    "IntCA":
    {
        "type": "Intermediate",
        "parameters":
            [
                {
                    "extension": x509.BasicConstraints(ca=True, path_length=None),
                    "critical": True
                },
                {
                    "extension": x509.KeyUsage(
                        digital_signature=True,
                        content_commitment=False,
                        key_encipherment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=True,
                        crl_sign=True,
                        encipher_only=False,
                        decipher_only=False
                    ),
                    "critical": True
                },
            ]
    },
    "CN":
    {
        "type": "Leaf",
        "parameters":
            [
                {
                    "extension": x509.BasicConstraints(ca=False, path_length=None),
                    "critical": False
                },
                {
                    "extension": x509.KeyUsage(
                        digital_signature=True,
                        content_commitment=True,  # nonRepudiation
                        key_encipherment=True,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=False,
                        crl_sign=False,
                        encipher_only=False,
                        decipher_only=False
                    ),
                    "critical": True
                },
                {
                    "extension": x509.ExtendedKeyUsage([
                        ExtendedKeyUsageOID.SERVER_AUTH,
                        ExtendedKeyUsageOID.CLIENT_AUTH,
                        ExtendedKeyUsageOID.EMAIL_PROTECTION
                    ]),
                    "critical": False
                }
            ]
    },
    # New extensions here...
}