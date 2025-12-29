"""Tests for CSR signing and CRL generation."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.x509.oid import NameOID

from cert_gen.cert_ops import CertGen


def generate_csr(common_name: str, key_type: str = "rsa") -> tuple[str, bytes]:
    """Generate a CSR for testing.

    Returns:
        Tuple of (CSR PEM string, private key bytes)
    """
    if key_type == "rsa":
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    else:
        key = ed25519.Ed25519PrivateKey.generate()

    csr_builder = x509.CertificateSigningRequestBuilder()
    csr_builder = csr_builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ]))

    if key_type == "rsa":
        csr = csr_builder.sign(key, hashes.SHA256())
    else:
        csr = csr_builder.sign(key, None)

    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    key_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    return csr_pem, key_bytes


class TestCSRSigning:
    """Tests for CSR signing functionality."""

    def test_sign_csr_basic(self, cert_gen_with_root: tuple[CertGen, Path, Path], temp_dir: Path) -> None:
        """Test basic CSR signing."""
        cg, ca_cert, ca_key = cert_gen_with_root
        csr_pem, _ = generate_csr("test.example.com")

        signed_cert_path = temp_dir / "signed.crt"
        result = cg.csr_signing(
            CACertFile=ca_cert,
            CAKeyFile=ca_key,
            csr=csr_pem,
            notBefore="2025-01-01 00:00:00",
            validityDays=365,
            signedCertFile=signed_cert_path,
            digest="sha256"
        )

        assert "-----BEGIN CERTIFICATE-----" in result
        assert "-----END CERTIFICATE-----" in result
        assert signed_cert_path.exists()

    def test_sign_csr_preserves_subject(
        self, cert_gen_with_root: tuple[CertGen, Path, Path], temp_dir: Path
    ) -> None:
        """Test that CSR signing preserves the subject from CSR."""
        cg, ca_cert, ca_key = cert_gen_with_root
        csr_pem, _ = generate_csr("myserver.example.com")

        signed_cert_path = temp_dir / "signed.crt"
        result = cg.csr_signing(
            CACertFile=ca_cert,
            CAKeyFile=ca_key,
            csr=csr_pem,
            notBefore="2025-01-01 00:00:00",
            validityDays=365,
            signedCertFile=signed_cert_path,
            digest="sha256"
        )

        cert = x509.load_pem_x509_certificate(result.encode())
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "myserver.example.com"

    def test_sign_csr_sets_issuer(
        self, cert_gen_with_root: tuple[CertGen, Path, Path], temp_dir: Path
    ) -> None:
        """Test that signed certificate has correct issuer."""
        cg, ca_cert, ca_key = cert_gen_with_root
        csr_pem, _ = generate_csr("test.example.com")

        # Load CA cert to get subject
        with open(ca_cert, "rb") as f:
            ca = x509.load_pem_x509_certificate(f.read())

        signed_cert_path = temp_dir / "signed.crt"
        result = cg.csr_signing(
            CACertFile=ca_cert,
            CAKeyFile=ca_key,
            csr=csr_pem,
            notBefore="2025-01-01 00:00:00",
            validityDays=365,
            signedCertFile=signed_cert_path,
            digest="sha256"
        )

        cert = x509.load_pem_x509_certificate(result.encode())
        assert cert.issuer == ca.subject

    def test_sign_csr_validity_period(
        self, cert_gen_with_root: tuple[CertGen, Path, Path], temp_dir: Path
    ) -> None:
        """Test that signed certificate has correct validity period."""
        cg, ca_cert, ca_key = cert_gen_with_root
        csr_pem, _ = generate_csr("test.example.com")

        signed_cert_path = temp_dir / "signed.crt"
        result = cg.csr_signing(
            CACertFile=ca_cert,
            CAKeyFile=ca_key,
            csr=csr_pem,
            notBefore="2025-06-15 12:00:00",
            validityDays=90,
            signedCertFile=signed_cert_path,
            digest="sha256"
        )

        cert = x509.load_pem_x509_certificate(result.encode())

        # Verify not_valid_before
        assert cert.not_valid_before_utc.year == 2025
        assert cert.not_valid_before_utc.month == 6
        assert cert.not_valid_before_utc.day == 15

        # Verify validity period is ~90 days
        delta = cert.not_valid_after_utc - cert.not_valid_before_utc
        assert delta.days == 90

    def test_sign_csr_with_bytes(
        self, cert_gen_with_root: tuple[CertGen, Path, Path], temp_dir: Path
    ) -> None:
        """Test signing CSR provided as bytes."""
        cg, ca_cert, ca_key = cert_gen_with_root
        csr_pem, _ = generate_csr("test.example.com")
        csr_bytes = csr_pem.encode('utf-8')

        signed_cert_path = temp_dir / "signed.crt"
        result = cg.csr_signing(
            CACertFile=ca_cert,
            CAKeyFile=ca_key,
            csr=csr_bytes,
            notBefore="2025-01-01 00:00:00",
            validityDays=365,
            signedCertFile=signed_cert_path,
            digest="sha256"
        )

        assert "-----BEGIN CERTIFICATE-----" in result

    @pytest.mark.parametrize("digest", ["sha224", "sha256", "sha384", "sha512"])
    def test_sign_csr_different_digests(
        self, temp_dir: Path, digest: str
    ) -> None:
        """Test CSR signing with different digest algorithms.

        Note: SHA1 is excluded as it's no longer supported for signatures
        in modern versions of the cryptography library.
        """
        # Use RSA CA for digest algorithm testing
        cg = CertGen()
        ca_cert, ca_key = cg.cert_gen("TestCA", key_type="rsa", key_length=2048, cert_category="RootCA", basedir=temp_dir)

        csr_pem, _ = generate_csr("test.example.com")

        signed_cert_path = temp_dir / f"signed_{digest}.crt"
        result = cg.csr_signing(
            CACertFile=ca_cert,
            CAKeyFile=ca_key,
            csr=csr_pem,
            notBefore="2025-01-01 00:00:00",
            validityDays=365,
            signedCertFile=signed_cert_path,
            digest=digest
        )

        assert "-----BEGIN CERTIFICATE-----" in result

    def test_sign_csr_with_ed25519_ca(self, temp_dir: Path) -> None:
        """Test CSR signing with Ed25519 CA (ignores digest parameter)."""
        cg = CertGen()
        ca_cert, ca_key = cg.cert_gen("Ed25519CA", key_type="ed25519", cert_category="RootCA", basedir=temp_dir)

        csr_pem, _ = generate_csr("test.example.com")

        signed_cert_path = temp_dir / "signed.crt"
        result = cg.csr_signing(
            CACertFile=ca_cert,
            CAKeyFile=ca_key,
            csr=csr_pem,
            notBefore="2025-01-01 00:00:00",
            validityDays=365,
            signedCertFile=signed_cert_path,
            digest="sha256"  # Should be ignored for Ed25519
        )

        assert "-----BEGIN CERTIFICATE-----" in result


class TestCRLGeneration:
    """Tests for CRL generation functionality."""

    def test_generate_empty_crl(self, cert_gen_with_root: tuple[CertGen, Path, Path]) -> None:
        """Test generating CRL without any revoked certificates."""
        cg, ca_cert, ca_key = cert_gen_with_root

        crl_path = cg.crl_gen(
            authCert=ca_cert,
            authKey=ca_key,
            serial=1,
            lastUpdate="2025-01-01 00:00:00",
            nextUpdate="2025-02-01 00:00:00",
            revokedFile=None,
            digest="sha256"
        )

        assert Path(crl_path).exists()

        with open(crl_path, "rb") as f:
            crl = x509.load_pem_x509_crl(f.read())

        assert crl is not None
        assert len(list(crl)) == 0  # No revoked certs

    def test_generate_crl_with_revoked_cert(
        self, cert_gen_with_chain: tuple[CertGen, dict[str, tuple[Path, Path]]]
    ) -> None:
        """Test generating CRL with a revoked certificate."""
        cg, certs = cert_gen_with_chain

        crl_path = cg.crl_gen(
            authCert=certs["root"][0],
            authKey=certs["root"][1],
            serial=1,
            lastUpdate="2025-01-01 00:00:00",
            nextUpdate="2025-02-01 00:00:00",
            revokedFile=certs["leaf"][0],  # Revoke the leaf cert
            digest="sha256"
        )

        with open(crl_path, "rb") as f:
            crl = x509.load_pem_x509_crl(f.read())

        # Should have one revoked certificate
        revoked_list = list(crl)
        assert len(revoked_list) == 1

    def test_crl_contains_correct_serial(
        self, cert_gen_with_chain: tuple[CertGen, dict[str, tuple[Path, Path]]]
    ) -> None:
        """Test that CRL contains the correct serial number of revoked cert."""
        cg, certs = cert_gen_with_chain

        # Get the serial number of the leaf cert
        with open(certs["leaf"][0], "rb") as f:
            leaf_cert = x509.load_pem_x509_certificate(f.read())
        leaf_serial = leaf_cert.serial_number

        crl_path = cg.crl_gen(
            authCert=certs["root"][0],
            authKey=certs["root"][1],
            serial=1,
            lastUpdate="2025-01-01 00:00:00",
            nextUpdate="2025-02-01 00:00:00",
            revokedFile=certs["leaf"][0],
            digest="sha256"
        )

        with open(crl_path, "rb") as f:
            crl = x509.load_pem_x509_crl(f.read())

        revoked = crl.get_revoked_certificate_by_serial_number(leaf_serial)
        assert revoked is not None
        assert revoked.serial_number == leaf_serial

    def test_crl_issuer_matches_ca(
        self, cert_gen_with_root: tuple[CertGen, Path, Path]
    ) -> None:
        """Test that CRL issuer matches CA subject."""
        cg, ca_cert, ca_key = cert_gen_with_root

        with open(ca_cert, "rb") as f:
            ca = x509.load_pem_x509_certificate(f.read())

        crl_path = cg.crl_gen(
            authCert=ca_cert,
            authKey=ca_key,
            serial=1,
            lastUpdate="2025-01-01 00:00:00",
            nextUpdate="2025-02-01 00:00:00",
            revokedFile=None,
            digest="sha256"
        )

        with open(crl_path, "rb") as f:
            crl = x509.load_pem_x509_crl(f.read())

        assert crl.issuer == ca.subject

    def test_crl_update_times(
        self, cert_gen_with_root: tuple[CertGen, Path, Path]
    ) -> None:
        """Test that CRL has correct last/next update times."""
        cg, ca_cert, ca_key = cert_gen_with_root

        crl_path = cg.crl_gen(
            authCert=ca_cert,
            authKey=ca_key,
            serial=1,
            lastUpdate="2025-03-15 10:30:00",
            nextUpdate="2025-04-15 10:30:00",
            revokedFile=None,
            digest="sha256"
        )

        with open(crl_path, "rb") as f:
            crl = x509.load_pem_x509_crl(f.read())

        assert crl.last_update_utc.year == 2025
        assert crl.last_update_utc.month == 3
        assert crl.last_update_utc.day == 15

        assert crl.next_update_utc.year == 2025
        assert crl.next_update_utc.month == 4
        assert crl.next_update_utc.day == 15

    def test_crl_with_ed25519_ca(self, temp_dir: Path) -> None:
        """Test CRL generation with Ed25519 CA."""
        cg = CertGen()
        ca_cert, ca_key = cg.cert_gen("Ed25519CA", key_type="ed25519", cert_category="RootCA", basedir=temp_dir)

        crl_path = cg.crl_gen(
            authCert=ca_cert,
            authKey=ca_key,
            serial=1,
            lastUpdate="2025-01-01 00:00:00",
            nextUpdate="2025-02-01 00:00:00",
            revokedFile=None,
            digest="sha256"  # Should be ignored
        )

        assert Path(crl_path).exists()

        with open(crl_path, "rb") as f:
            crl = x509.load_pem_x509_crl(f.read())

        assert crl is not None

    def test_crl_file_naming(
        self, cert_gen_with_root: tuple[CertGen, Path, Path]
    ) -> None:
        """Test that CRL file is named based on CA cert."""
        cg, ca_cert, ca_key = cert_gen_with_root

        crl_path = cg.crl_gen(
            authCert=ca_cert,
            authKey=ca_key,
            serial=1,
            lastUpdate="2025-01-01 00:00:00",
            nextUpdate="2025-02-01 00:00:00",
            revokedFile=None,
            digest="sha256"
        )

        # CRL should be named after CA cert with .crl extension
        assert crl_path.endswith(".crl")
        assert "TestRootCA" in crl_path
