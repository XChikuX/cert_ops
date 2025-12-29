"""Tests for certificate extension configurations."""

from __future__ import annotations

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from cert_gen.cert_extensions import EXTENSIONS, ExtensionConfig, CertTypeConfig


class TestExtensionsStructure:
    """Tests for the EXTENSIONS dictionary structure."""

    def test_extensions_has_required_categories(self) -> None:
        """Test that EXTENSIONS contains all required certificate categories."""
        assert "RootCA" in EXTENSIONS
        assert "IntCA" in EXTENSIONS
        assert "CN" in EXTENSIONS

    def test_each_category_has_type(self) -> None:
        """Test that each category has a 'type' field."""
        for category, config in EXTENSIONS.items():
            assert "type" in config, f"{category} missing 'type' field"

    def test_each_category_has_parameters(self) -> None:
        """Test that each category has a 'parameters' field."""
        for category, config in EXTENSIONS.items():
            assert "parameters" in config, f"{category} missing 'parameters' field"
            assert isinstance(config["parameters"], list)

    def test_parameter_structure(self) -> None:
        """Test that each parameter has 'extension' and 'critical' fields."""
        for category, config in EXTENSIONS.items():
            for i, param in enumerate(config["parameters"]):
                assert "extension" in param, f"{category} param {i} missing 'extension'"
                assert "critical" in param, f"{category} param {i} missing 'critical'"
                assert isinstance(param["critical"], bool)


class TestRootCAExtensions:
    """Tests for RootCA extension configuration."""

    def test_root_type_is_root(self) -> None:
        """Test that RootCA type is 'Root'."""
        assert EXTENSIONS["RootCA"]["type"] == "Root"

    def test_root_has_basic_constraints(self) -> None:
        """Test that RootCA has BasicConstraints extension."""
        params = EXTENSIONS["RootCA"]["parameters"]
        basic_constraints = [p for p in params if isinstance(p["extension"], x509.BasicConstraints)]
        assert len(basic_constraints) == 1

    def test_root_basic_constraints_ca_true(self) -> None:
        """Test that RootCA BasicConstraints has CA=True."""
        params = EXTENSIONS["RootCA"]["parameters"]
        bc = next(p for p in params if isinstance(p["extension"], x509.BasicConstraints))
        assert bc["extension"].ca is True
        assert bc["critical"] is True

    def test_root_has_key_usage(self) -> None:
        """Test that RootCA has KeyUsage extension."""
        params = EXTENSIONS["RootCA"]["parameters"]
        key_usage = [p for p in params if isinstance(p["extension"], x509.KeyUsage)]
        assert len(key_usage) == 1

    def test_root_key_usage_allows_cert_signing(self) -> None:
        """Test that RootCA KeyUsage allows certificate signing."""
        params = EXTENSIONS["RootCA"]["parameters"]
        ku = next(p for p in params if isinstance(p["extension"], x509.KeyUsage))
        assert ku["extension"].key_cert_sign is True
        assert ku["extension"].crl_sign is True
        assert ku["extension"].digital_signature is True


class TestIntCAExtensions:
    """Tests for IntCA (Intermediate CA) extension configuration."""

    def test_int_type_is_intermediate(self) -> None:
        """Test that IntCA type is 'Intermediate'."""
        assert EXTENSIONS["IntCA"]["type"] == "Intermediate"

    def test_int_has_basic_constraints(self) -> None:
        """Test that IntCA has BasicConstraints extension."""
        params = EXTENSIONS["IntCA"]["parameters"]
        basic_constraints = [p for p in params if isinstance(p["extension"], x509.BasicConstraints)]
        assert len(basic_constraints) == 1

    def test_int_basic_constraints_ca_true(self) -> None:
        """Test that IntCA BasicConstraints has CA=True."""
        params = EXTENSIONS["IntCA"]["parameters"]
        bc = next(p for p in params if isinstance(p["extension"], x509.BasicConstraints))
        assert bc["extension"].ca is True
        assert bc["critical"] is True

    def test_int_has_key_usage(self) -> None:
        """Test that IntCA has KeyUsage extension."""
        params = EXTENSIONS["IntCA"]["parameters"]
        key_usage = [p for p in params if isinstance(p["extension"], x509.KeyUsage)]
        assert len(key_usage) == 1

    def test_int_key_usage_allows_cert_signing(self) -> None:
        """Test that IntCA KeyUsage allows certificate signing."""
        params = EXTENSIONS["IntCA"]["parameters"]
        ku = next(p for p in params if isinstance(p["extension"], x509.KeyUsage))
        assert ku["extension"].key_cert_sign is True
        assert ku["extension"].crl_sign is True


class TestCNExtensions:
    """Tests for CN (leaf certificate) extension configuration."""

    def test_cn_type_is_leaf(self) -> None:
        """Test that CN type is 'Leaf'."""
        assert EXTENSIONS["CN"]["type"] == "Leaf"

    def test_cn_has_basic_constraints(self) -> None:
        """Test that CN has BasicConstraints extension."""
        params = EXTENSIONS["CN"]["parameters"]
        basic_constraints = [p for p in params if isinstance(p["extension"], x509.BasicConstraints)]
        assert len(basic_constraints) == 1

    def test_cn_basic_constraints_ca_false(self) -> None:
        """Test that CN BasicConstraints has CA=False."""
        params = EXTENSIONS["CN"]["parameters"]
        bc = next(p for p in params if isinstance(p["extension"], x509.BasicConstraints))
        assert bc["extension"].ca is False
        assert bc["critical"] is False  # Leaf cert BC is not critical

    def test_cn_has_key_usage(self) -> None:
        """Test that CN has KeyUsage extension."""
        params = EXTENSIONS["CN"]["parameters"]
        key_usage = [p for p in params if isinstance(p["extension"], x509.KeyUsage)]
        assert len(key_usage) == 1

    def test_cn_key_usage_for_end_entity(self) -> None:
        """Test that CN KeyUsage is appropriate for end-entity certificates."""
        params = EXTENSIONS["CN"]["parameters"]
        ku = next(p for p in params if isinstance(p["extension"], x509.KeyUsage))
        assert ku["extension"].digital_signature is True
        assert ku["extension"].key_encipherment is True
        assert ku["extension"].key_cert_sign is False  # Cannot sign certs
        assert ku["extension"].crl_sign is False  # Cannot sign CRLs

    def test_cn_has_extended_key_usage(self) -> None:
        """Test that CN has ExtendedKeyUsage extension."""
        params = EXTENSIONS["CN"]["parameters"]
        eku = [p for p in params if isinstance(p["extension"], x509.ExtendedKeyUsage)]
        assert len(eku) == 1

    def test_cn_extended_key_usage_values(self) -> None:
        """Test that CN ExtendedKeyUsage has correct OIDs."""
        params = EXTENSIONS["CN"]["parameters"]
        eku = next(p for p in params if isinstance(p["extension"], x509.ExtendedKeyUsage))

        oids = list(eku["extension"])
        assert ExtendedKeyUsageOID.SERVER_AUTH in oids
        assert ExtendedKeyUsageOID.CLIENT_AUTH in oids
        assert ExtendedKeyUsageOID.EMAIL_PROTECTION in oids


class TestExtensionConsistency:
    """Tests for consistency across extension configurations."""

    def test_all_categories_have_basic_constraints(self) -> None:
        """Test that all certificate categories have BasicConstraints."""
        for category in ["RootCA", "IntCA", "CN"]:
            params = EXTENSIONS[category]["parameters"]
            bc = [p for p in params if isinstance(p["extension"], x509.BasicConstraints)]
            assert len(bc) >= 1, f"{category} missing BasicConstraints"

    def test_all_categories_have_key_usage(self) -> None:
        """Test that all certificate categories have KeyUsage."""
        for category in ["RootCA", "IntCA", "CN"]:
            params = EXTENSIONS[category]["parameters"]
            ku = [p for p in params if isinstance(p["extension"], x509.KeyUsage)]
            assert len(ku) >= 1, f"{category} missing KeyUsage"

    def test_ca_types_have_critical_basic_constraints(self) -> None:
        """Test that CA certificate types have critical BasicConstraints."""
        for category in ["RootCA", "IntCA"]:
            params = EXTENSIONS[category]["parameters"]
            bc = next(p for p in params if isinstance(p["extension"], x509.BasicConstraints))
            assert bc["critical"] is True, f"{category} BasicConstraints should be critical"

    def test_only_leaf_has_extended_key_usage(self) -> None:
        """Test that only leaf certificates have ExtendedKeyUsage."""
        for category in ["RootCA", "IntCA"]:
            params = EXTENSIONS[category]["parameters"]
            eku = [p for p in params if isinstance(p["extension"], x509.ExtendedKeyUsage)]
            assert len(eku) == 0, f"{category} should not have ExtendedKeyUsage"

        cn_params = EXTENSIONS["CN"]["parameters"]
        eku = [p for p in cn_params if isinstance(p["extension"], x509.ExtendedKeyUsage)]
        assert len(eku) == 1, "CN should have ExtendedKeyUsage"


class TestTypeAliases:
    """Tests for TypedDict type aliases."""

    def test_extension_config_structure(self) -> None:
        """Test that ExtensionConfig TypedDict works correctly."""
        # This is a compile-time check, but we can verify the structure
        sample: ExtensionConfig = {
            "extension": x509.BasicConstraints(ca=True, path_length=None),
            "critical": True
        }
        assert "extension" in sample
        assert "critical" in sample

    def test_cert_type_config_structure(self) -> None:
        """Test that CertTypeConfig TypedDict works correctly."""
        sample: CertTypeConfig = {
            "type": "Root",
            "parameters": []
        }
        assert "type" in sample
        assert "parameters" in sample
