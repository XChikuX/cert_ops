"""Tests for core certificate operations."""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from cert_gen.cert_ops import CertGen


class TestCertGenInit:
    """Tests for CertGen initialization."""

    def test_default_init(self, cert_gen: CertGen) -> None:
        """Test default initialization values."""
        assert cert_gen.emailAddress == "test@example.com"
        assert cert_gen.countryName == "US"
        assert cert_gen.localityName == "Palo Alto"
        assert cert_gen.stateOrProvinceName == "CA"
        assert cert_gen.organizationName == "Meow Inc."
        assert cert_gen.organizationUnitName == "Cert Dept."
        assert cert_gen.validityStartInSeconds == 0
        assert cert_gen.validityEndInSeconds == 10 * 365 * 24 * 60 * 60
        assert cert_gen.rootca == {}
        assert cert_gen.intca == {}

    def test_serial_number_starts_at_zero(self, cert_gen: CertGen) -> None:
        """Test that serial number counter starts at 0."""
        assert cert_gen.serialNumber == 0


class TestCertGenBasic:
    """Basic certificate generation tests."""

    def test_generate_root_ca(self, cert_gen: CertGen, temp_dir: Path) -> None:
        """Test generating a Root CA certificate."""
        cert_path, key_path = cert_gen.cert_gen(
            "TestRootCA",
            cert_category="RootCA",
            basedir=temp_dir
        )

        assert cert_path.exists()
        assert key_path.exists()
        assert cert_path.suffix == ".crt"
        assert key_path.suffix == ".pem"

        # Verify certificate can be loaded
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        assert cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == "TestRootCA"

    def test_generate_intermediate_ca(self, cert_gen: CertGen, temp_dir: Path) -> None:
        """Test generating an Intermediate CA certificate."""
        # First create Root CA
        cert_gen.cert_gen("TestRootCA", cert_category="RootCA", basedir=temp_dir)

        # Then create Intermediate CA
        cert_path, key_path = cert_gen.cert_gen(
            "TestIntCA",
            cert_category="IntCA",
            basedir=temp_dir
        )

        assert cert_path.exists()
        assert key_path.exists()

        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        assert cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == "TestIntCA"

    def test_generate_leaf_certificate(self, cert_gen: CertGen, temp_dir: Path) -> None:
        """Test generating a leaf (CN) certificate."""
        # Create chain first
        cert_gen.cert_gen("TestRootCA", cert_category="RootCA", basedir=temp_dir)

        # Create leaf certificate
        cert_path, key_path = cert_gen.cert_gen(
            "test.example.com",
            cert_category="CN",
            basedir=temp_dir
        )

        assert cert_path.exists()
        assert key_path.exists()

        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        assert cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == "test.example.com"

    def test_serial_numbers_increment(self, cert_gen: CertGen, temp_dir: Path) -> None:
        """Test that serial numbers increment within a CertGen instance."""
        # Generate root first
        cert_gen.cert_gen("Root", cert_category="RootCA", basedir=temp_dir)
        assert cert_gen.serialNumber == 1

        # Generate intermediate
        cert_gen.cert_gen("Int", cert_category="IntCA", basedir=temp_dir)
        assert cert_gen.serialNumber == 2

        # Generate leaf
        cert_gen.cert_gen("Leaf", cert_category="CN", basedir=temp_dir)
        assert cert_gen.serialNumber == 3


class TestCertGenValidation:
    """Tests for input validation."""

    def test_invalid_key_length(self, cert_gen: CertGen, temp_dir: Path) -> None:
        """Test that invalid key lengths raise ValueError."""
        with pytest.raises(ValueError, match="key length must be"):
            cert_gen.cert_gen(
                "TestCert",
                key_length=512,
                cert_category="RootCA",
                basedir=temp_dir
            )

    def test_invalid_signing_algo(self, cert_gen: CertGen, temp_dir: Path) -> None:
        """Test that invalid signing algorithms raise ValueError."""
        with pytest.raises(ValueError, match="signature algorithms must be"):
            cert_gen.cert_gen(
                "TestCert",
                signing_algo="md5",
                cert_category="RootCA",
                basedir=temp_dir
            )

    def test_invalid_key_type(self, cert_gen: CertGen, temp_dir: Path) -> None:
        """Test that invalid key types raise ValueError."""
        with pytest.raises(ValueError, match="key type must be"):
            cert_gen.cert_gen(
                "TestCert",
                key_type="invalid",
                cert_category="RootCA",
                basedir=temp_dir
            )

    def test_duplicate_root_ca(self, cert_gen: CertGen, temp_dir: Path) -> None:
        """Test that creating a second Root CA raises ValueError."""
        cert_gen.cert_gen("Root1", cert_category="RootCA", basedir=temp_dir)

        with pytest.raises(ValueError, match="RootCA already present"):
            cert_gen.cert_gen("Root2", cert_category="RootCA", basedir=temp_dir)

    def test_duplicate_intermediate_ca(self, cert_gen: CertGen, temp_dir: Path) -> None:
        """Test that creating a second Intermediate CA raises ValueError."""
        cert_gen.cert_gen("Root", cert_category="RootCA", basedir=temp_dir)
        cert_gen.cert_gen("Int1", cert_category="IntCA", basedir=temp_dir)

        with pytest.raises(ValueError, match="IntCA already present"):
            cert_gen.cert_gen("Int2", cert_category="IntCA", basedir=temp_dir)

    def test_intermediate_without_root(self, cert_gen: CertGen, temp_dir: Path) -> None:
        """Test that creating Intermediate CA without Root CA raises ValueError."""
        with pytest.raises(ValueError, match="RootCA must be present"):
            cert_gen.cert_gen("IntCA", cert_category="IntCA", basedir=temp_dir)

    def test_leaf_without_ca(self, cert_gen: CertGen, temp_dir: Path) -> None:
        """Test that creating leaf certificate without CA raises ValueError."""
        with pytest.raises(ValueError, match="Leaf cannot be self signed"):
            cert_gen.cert_gen("Leaf", cert_category="CN", basedir=temp_dir)


class TestCertGenValidity:
    """Tests for certificate validity periods."""

    def test_custom_validity_period(self, cert_gen: CertGen, temp_dir: Path) -> None:
        """Test custom validity period."""
        validity_seconds = 365 * 24 * 60 * 60  # 1 year

        cert_path, _ = cert_gen.cert_gen(
            "TestCert",
            validityEndInSeconds=validity_seconds,
            cert_category="RootCA",
            basedir=temp_dir
        )

        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())

        # Verify validity period is approximately 1 year
        delta = cert.not_valid_after_utc - cert.not_valid_before_utc
        assert abs(delta.total_seconds() - validity_seconds) < 2  # Allow 2 second tolerance

    def test_root_ca_default_validity(self, cert_gen: CertGen, temp_dir: Path) -> None:
        """Test Root CA default validity (10 years)."""
        cert_path, _ = cert_gen.cert_gen(
            "TestRoot",
            cert_category="RootCA",
            basedir=temp_dir
        )

        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())

        delta = cert.not_valid_after_utc - cert.not_valid_before_utc
        expected_seconds = 10 * 365 * 24 * 60 * 60
        assert abs(delta.total_seconds() - expected_seconds) < 2

    def test_intermediate_ca_default_validity(self, cert_gen: CertGen, temp_dir: Path) -> None:
        """Test Intermediate CA default validity (5 years)."""
        cert_gen.cert_gen("Root", cert_category="RootCA", basedir=temp_dir)
        cert_path, _ = cert_gen.cert_gen(
            "TestInt",
            cert_category="IntCA",
            basedir=temp_dir
        )

        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())

        delta = cert.not_valid_after_utc - cert.not_valid_before_utc
        expected_seconds = 5 * 365 * 24 * 60 * 60
        assert abs(delta.total_seconds() - expected_seconds) < 2

    def test_leaf_default_validity(self, cert_gen: CertGen, temp_dir: Path) -> None:
        """Test leaf certificate default validity (825 days)."""
        cert_gen.cert_gen("Root", cert_category="RootCA", basedir=temp_dir)
        cert_path, _ = cert_gen.cert_gen(
            "TestLeaf",
            cert_category="CN",
            basedir=temp_dir
        )

        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())

        delta = cert.not_valid_after_utc - cert.not_valid_before_utc
        expected_days = 825
        assert abs(delta.days - expected_days) <= 1


class TestObj2Pem:
    """Tests for object to PEM conversion."""

    def test_cert_to_pem(self, cert_gen_with_root: tuple[CertGen, Path, Path]) -> None:
        """Test certificate to PEM conversion."""
        _, cert_path, _ = cert_gen_with_root

        with open(cert_path, "rb") as f:
            content = f.read()

        assert b"-----BEGIN CERTIFICATE-----" in content
        assert b"-----END CERTIFICATE-----" in content

    def test_key_to_pem(self, cert_gen_with_root: tuple[CertGen, Path, Path]) -> None:
        """Test private key to PEM conversion."""
        _, _, key_path = cert_gen_with_root

        with open(key_path, "rb") as f:
            content = f.read()

        assert b"-----BEGIN PRIVATE KEY-----" in content
        assert b"-----END PRIVATE KEY-----" in content

    def test_key_is_loadable(self, cert_gen_with_root: tuple[CertGen, Path, Path]) -> None:
        """Test that generated private key can be loaded."""
        _, _, key_path = cert_gen_with_root

        with open(key_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)

        assert key is not None


class TestGetApiCompatible:
    """Tests for API-compatible formatting."""

    def test_format_from_file(self, cert_gen_with_root: tuple[CertGen, Path, Path]) -> None:
        """Test formatting from file path."""
        cg, cert_path, _ = cert_gen_with_root

        result = cg.get_api_compatible(cert_path)

        assert "-----BEGIN CERTIFICATE-----" in result
        assert "-----END CERTIFICATE-----" in result
        assert "\n" in result

    def test_format_from_string(self, cert_gen_with_root: tuple[CertGen, Path, Path]) -> None:
        """Test formatting from PEM string."""
        cg, cert_path, _ = cert_gen_with_root

        with open(cert_path) as f:
            content = f.read()

        result = cg.get_api_compatible(content)

        assert "-----BEGIN CERTIFICATE-----" in result
        assert "-----END CERTIFICATE-----" in result
