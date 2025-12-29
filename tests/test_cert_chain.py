"""Tests for certificate chain operations."""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography import x509

from cert_gen.cert_ops import CertGen


class TestCreateCertChain:
    """Tests for creating certificate chains."""

    def test_create_chain_with_all_certs(
        self, cert_gen_with_chain: tuple[CertGen, dict[str, tuple[Path, Path]]]
    ) -> None:
        """Test creating chain with root, intermediate, and leaf certificates."""
        cg, certs = cert_gen_with_chain

        chain = cg.create_cert_chain(
            root_path=certs["root"][0],
            cn_path=certs["leaf"][0],
            int_path=certs["int"][0]
        )

        # Verify chain contains all three certificates
        assert chain.count("-----BEGIN CERTIFICATE-----") == 3
        assert chain.count("-----END CERTIFICATE-----") == 3

    def test_create_chain_without_intermediate(self, temp_dir: Path) -> None:
        """Test creating chain with just root and leaf."""
        cg = CertGen()
        root_cert, _ = cg.cert_gen("Root", cert_category="RootCA", basedir=temp_dir)
        leaf_cert, _ = cg.cert_gen("Leaf", cert_category="CN", basedir=temp_dir)

        chain = cg.create_cert_chain(
            root_path=root_cert,
            cn_path=leaf_cert
        )

        # Verify chain contains two certificates
        assert chain.count("-----BEGIN CERTIFICATE-----") == 2
        assert chain.count("-----END CERTIFICATE-----") == 2

    def test_create_chain_with_only_intermediate(self, temp_dir: Path) -> None:
        """Test creating chain with root and intermediate (no leaf)."""
        cg = CertGen()
        root_cert, _ = cg.cert_gen("Root", cert_category="RootCA", basedir=temp_dir)
        int_cert, _ = cg.cert_gen("Int", cert_category="IntCA", basedir=temp_dir)

        chain = cg.create_cert_chain(
            root_path=root_cert,
            int_path=int_cert
        )

        assert chain.count("-----BEGIN CERTIFICATE-----") == 2
        assert chain.count("-----END CERTIFICATE-----") == 2

    def test_create_chain_empty_paths_raises(self, temp_dir: Path) -> None:
        """Test that empty paths raise ValueError."""
        cg = CertGen()
        root_cert, _ = cg.cert_gen("Root", cert_category="RootCA", basedir=temp_dir)

        with pytest.raises(ValueError, match="cannot both be empty"):
            cg.create_cert_chain(root_path=root_cert)

    def test_chain_order_is_correct(
        self, cert_gen_with_chain: tuple[CertGen, dict[str, tuple[Path, Path]]]
    ) -> None:
        """Test that certificates in chain are in correct order (leaf -> int -> root)."""
        cg, certs = cert_gen_with_chain

        chain = cg.create_cert_chain(
            root_path=certs["root"][0],
            cn_path=certs["leaf"][0],
            int_path=certs["int"][0]
        )

        # Split chain into individual certs
        cert_boundaries = chain.split("-----END CERTIFICATE-----")
        cert_pems = [
            c + "-----END CERTIFICATE-----"
            for c in cert_boundaries
            if "-----BEGIN CERTIFICATE-----" in c
        ]

        assert len(cert_pems) == 3

        # Load and verify order
        certs_loaded = [x509.load_pem_x509_certificate(c.encode()) for c in cert_pems]

        # First should be leaf (CN=TestLeaf)
        assert certs_loaded[0].subject.get_attributes_for_oid(
            x509.oid.NameOID.COMMON_NAME
        )[0].value == "TestLeaf"

        # Second should be intermediate (CN=TestIntCA)
        assert certs_loaded[1].subject.get_attributes_for_oid(
            x509.oid.NameOID.COMMON_NAME
        )[0].value == "TestIntCA"

        # Third should be root (CN=TestRootCA)
        assert certs_loaded[2].subject.get_attributes_for_oid(
            x509.oid.NameOID.COMMON_NAME
        )[0].value == "TestRootCA"


class TestDumpCertChain:
    """Tests for dumping certificate chains to file."""

    def test_dump_chain_creates_file(
        self, cert_gen_with_chain: tuple[CertGen, dict[str, tuple[Path, Path]]], temp_dir: Path
    ) -> None:
        """Test that dumping chain creates a file."""
        cg, certs = cert_gen_with_chain

        chain = cg.create_cert_chain(
            root_path=certs["root"][0],
            cn_path=certs["leaf"][0],
            int_path=certs["int"][0]
        )

        chain_path = cg.dump_cert_chain(
            Path("chain.crt"),
            chain,
            basedir=temp_dir
        )

        assert chain_path.exists()
        assert chain_path.name == "chain.crt"

    def test_dump_chain_content_matches(
        self, cert_gen_with_chain: tuple[CertGen, dict[str, tuple[Path, Path]]], temp_dir: Path
    ) -> None:
        """Test that dumped chain content matches original."""
        cg, certs = cert_gen_with_chain

        chain = cg.create_cert_chain(
            root_path=certs["root"][0],
            cn_path=certs["leaf"][0],
            int_path=certs["int"][0]
        )

        chain_path = cg.dump_cert_chain(
            Path("chain.crt"),
            chain,
            basedir=temp_dir
        )

        with open(chain_path) as f:
            content = f.read()

        assert content == chain


class TestCertificateHierarchy:
    """Tests for certificate hierarchy and issuer relationships."""

    def test_root_is_self_signed(self, cert_gen_with_root: tuple[CertGen, Path, Path]) -> None:
        """Test that Root CA is self-signed (issuer == subject)."""
        _, cert_path, _ = cert_gen_with_root

        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())

        assert cert.issuer == cert.subject

    def test_intermediate_issued_by_root(
        self, cert_gen_with_chain: tuple[CertGen, dict[str, tuple[Path, Path]]]
    ) -> None:
        """Test that Intermediate CA is issued by Root CA."""
        _, certs = cert_gen_with_chain

        with open(certs["root"][0], "rb") as f:
            root_cert = x509.load_pem_x509_certificate(f.read())

        with open(certs["int"][0], "rb") as f:
            int_cert = x509.load_pem_x509_certificate(f.read())

        assert int_cert.issuer == root_cert.subject

    def test_leaf_issued_by_intermediate(
        self, cert_gen_with_chain: tuple[CertGen, dict[str, tuple[Path, Path]]]
    ) -> None:
        """Test that leaf certificate is issued by Intermediate CA."""
        _, certs = cert_gen_with_chain

        with open(certs["int"][0], "rb") as f:
            int_cert = x509.load_pem_x509_certificate(f.read())

        with open(certs["leaf"][0], "rb") as f:
            leaf_cert = x509.load_pem_x509_certificate(f.read())

        assert leaf_cert.issuer == int_cert.subject

    def test_leaf_issued_by_root_when_no_intermediate(self, temp_dir: Path) -> None:
        """Test that leaf is issued by Root CA when no Intermediate exists."""
        cg = CertGen()
        root_cert, _ = cg.cert_gen("Root", cert_category="RootCA", basedir=temp_dir)
        leaf_cert, _ = cg.cert_gen("Leaf", cert_category="CN", basedir=temp_dir)

        with open(root_cert, "rb") as f:
            root = x509.load_pem_x509_certificate(f.read())

        with open(leaf_cert, "rb") as f:
            leaf = x509.load_pem_x509_certificate(f.read())

        assert leaf.issuer == root.subject


class TestCertificateExtensions:
    """Tests for certificate extensions in chains."""

    def test_root_has_ca_true(self, cert_gen_with_root: tuple[CertGen, Path, Path]) -> None:
        """Test that Root CA has BasicConstraints with CA=True."""
        _, cert_path, _ = cert_gen_with_root

        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())

        basic_constraints = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        )
        assert basic_constraints.value.ca is True

    def test_intermediate_has_ca_true(
        self, cert_gen_with_chain: tuple[CertGen, dict[str, tuple[Path, Path]]]
    ) -> None:
        """Test that Intermediate CA has BasicConstraints with CA=True."""
        _, certs = cert_gen_with_chain

        with open(certs["int"][0], "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())

        basic_constraints = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        )
        assert basic_constraints.value.ca is True

    def test_leaf_has_ca_false(
        self, cert_gen_with_chain: tuple[CertGen, dict[str, tuple[Path, Path]]]
    ) -> None:
        """Test that leaf certificate has BasicConstraints with CA=False."""
        _, certs = cert_gen_with_chain

        with open(certs["leaf"][0], "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())

        basic_constraints = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        )
        assert basic_constraints.value.ca is False

    def test_leaf_has_extended_key_usage(
        self, cert_gen_with_chain: tuple[CertGen, dict[str, tuple[Path, Path]]]
    ) -> None:
        """Test that leaf certificate has ExtendedKeyUsage extension."""
        _, certs = cert_gen_with_chain

        with open(certs["leaf"][0], "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())

        eku = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.EXTENDED_KEY_USAGE
        )

        # Verify expected usages
        assert x509.oid.ExtendedKeyUsageOID.SERVER_AUTH in eku.value
        assert x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH in eku.value
        assert x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION in eku.value
