from OpenSSL import crypto

# To create your extension:
# Add a type: Root, Intermediate, Leaf
# followed by the parameters as a list.
# Which are the cert extensions

EXTENSIONS = {
    "RootCA":
    {
        "type": "Root",
        "parameters":
            [
                crypto.X509Extension(b'basicConstraints', True, b'CA:TRUE'),
                crypto.X509Extension(b'keyUsage', True, b'digitalSignature, keyCertSign, cRLSign'),
                # crypto.X509Extension(b'subjectAltName', False, b'DNS:www.ex.com,IP:1.2.3.4')
            ]
    },
    "IntCA":
    {
        "type": "Intermediate",
        "parameters":
            [
                crypto.X509Extension(b'basicConstraints', True, b'CA:TRUE'),
                crypto.X509Extension(b'keyUsage', True, b'digitalSignature, keyCertSign, cRLSign'),
                # crypto.X509Extension(b'subjectAltName', False, b'DNS:www.ex.com,IP:1.2.3.4')
            ]
    },
    "CN":
    {
        "type": "Leaf",
        "parameters":
            [
                crypto.X509Extension(b'basicConstraints', False, b'CA:FALSE'),
                crypto.X509Extension(b'keyUsage', True, b'digitalSignature, nonRepudiation, keyEncipherment'),
                crypto.X509Extension(b'extendedKeyUsage', False, b'serverAuth, clientAuth, emailProtection')
            ]
    },
    # New extensions here...\
}
