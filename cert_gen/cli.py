"""Command-line interface for certificate generation."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree
from cryptography import x509

from cert_gen.cert_ops import CertGen

app = typer.Typer(
    name="certgen",
    help="Generate X.509 certificates with modern elliptic curve cryptography.",
    rich_markup_mode="rich",
    no_args_is_help=True,
)
console = Console()

# Shared state for certificate chain operations
_cert_gen: CertGen | None = None


def get_cert_gen() -> CertGen:
    """Get or create a CertGen instance."""
    global _cert_gen
    if _cert_gen is None:
        _cert_gen = CertGen()
    return _cert_gen


def reset_cert_gen() -> None:
    """Reset the CertGen instance."""
    global _cert_gen
    _cert_gen = None


@app.command()
def generate(
    common_name: Annotated[str, typer.Argument(help="Common name for the certificate")],
    category: Annotated[
        str,
        typer.Option("--category", "-c", help="Certificate category: RootCA, IntCA, or CN")
    ] = "RootCA",
    key_type: Annotated[
        str,
        typer.Option("--key-type", "-k", help="Key type: ed25519, ed448, ecdsa, rsa, dsa")
    ] = "ed25519",
    key_length: Annotated[
        int,
        typer.Option("--key-length", "-l", help="Key length for RSA/DSA (ignored for EdDSA)")
    ] = 4096,
    hash_algo: Annotated[
        str,
        typer.Option("--hash", "-h", help="Hash algorithm: sha256, sha384, sha512")
    ] = "sha512",
    validity_days: Annotated[
        Optional[int],
        typer.Option("--validity", "-v", help="Validity period in days")
    ] = None,
    output_dir: Annotated[
        Path,
        typer.Option("--output", "-o", help="Output directory for certificates")
    ] = Path("/tmp"),
) -> None:
    """
    Generate a certificate with the specified parameters.

    [bold]Examples:[/bold]

        Generate a Root CA with Ed25519:
        $ certgen generate MyRootCA

        Generate an Intermediate CA:
        $ certgen generate MyIntCA --category IntCA

        Generate a leaf certificate:
        $ certgen generate server.example.com --category CN

        Generate with RSA key:
        $ certgen generate MyCA --key-type rsa --key-length 4096
    """
    # Validate inputs
    if category not in ("RootCA", "IntCA", "CN"):
        console.print(f"[red]Error:[/red] Invalid category '{category}'. Must be RootCA, IntCA, or CN.")
        raise typer.Exit(1)

    if key_type not in ("ed25519", "ed448", "ecdsa", "rsa", "dsa"):
        console.print(f"[red]Error:[/red] Invalid key type '{key_type}'.")
        raise typer.Exit(1)

    cg = get_cert_gen()

    validity_seconds = validity_days * 24 * 60 * 60 if validity_days else None

    try:
        with console.status(f"[bold green]Generating {category} certificate...[/bold green]"):
            cert_path, key_path = cg.cert_gen(
                commonName=common_name,
                key_type=key_type,
                key_length=key_length,
                signing_algo=hash_algo,
                validityEndInSeconds=validity_seconds,
                cert_category=category,
                basedir=output_dir,
            )

        # Display results
        console.print()
        console.print(Panel.fit(
            f"[bold green]✓[/bold green] Certificate generated successfully!\n\n"
            f"[bold]Certificate:[/bold] {cert_path}\n"
            f"[bold]Private Key:[/bold] {key_path}",
            title=f"[bold]{category}: {common_name}[/bold]",
            border_style="green",
        ))

        # Show certificate details
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())

        table = Table(title="Certificate Details", show_header=False)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="white")

        table.add_row("Subject", str(cert.subject.rfc4514_string()))
        table.add_row("Issuer", str(cert.issuer.rfc4514_string()))
        table.add_row("Serial Number", str(cert.serial_number))
        table.add_row("Not Before", str(cert.not_valid_before_utc))
        table.add_row("Not After", str(cert.not_valid_after_utc))
        table.add_row("Key Type", key_type.upper())
        table.add_row("Signature Algorithm", cert.signature_algorithm_oid._name)

        console.print(table)

    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


@app.command()
def chain(
    root_cert: Annotated[Path, typer.Argument(help="Path to Root CA certificate")],
    output: Annotated[Path, typer.Argument(help="Output path for certificate chain")],
    leaf_cert: Annotated[
        Optional[Path],
        typer.Option("--leaf", "-l", help="Path to leaf certificate")
    ] = None,
    int_cert: Annotated[
        Optional[Path],
        typer.Option("--intermediate", "-i", help="Path to intermediate CA certificate")
    ] = None,
) -> None:
    """
    Create a certificate chain from individual certificates.

    The chain is assembled in order: Leaf -> Intermediate -> Root

    [bold]Examples:[/bold]

        Create chain with all certificates:
        $ certgen chain root.crt chain.pem --leaf server.crt --intermediate int.crt

        Create chain without intermediate:
        $ certgen chain root.crt chain.pem --leaf server.crt
    """
    if not leaf_cert and not int_cert:
        console.print("[red]Error:[/red] At least one of --leaf or --intermediate must be provided.")
        raise typer.Exit(1)

    cg = CertGen()

    try:
        with console.status("[bold green]Creating certificate chain...[/bold green]"):
            chain_content = cg.create_cert_chain(
                root_path=root_cert,
                cn_path=leaf_cert,
                int_path=int_cert,
            )

            output.parent.mkdir(parents=True, exist_ok=True)
            with open(output, "w") as f:
                f.write(chain_content)

        # Count certificates in chain
        cert_count = chain_content.count("-----BEGIN CERTIFICATE-----")

        console.print()
        console.print(Panel.fit(
            f"[bold green]✓[/bold green] Certificate chain created!\n\n"
            f"[bold]Output:[/bold] {output}\n"
            f"[bold]Certificates:[/bold] {cert_count}",
            title="[bold]Certificate Chain[/bold]",
            border_style="green",
        ))

    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


@app.command()
def sign_csr(
    ca_cert: Annotated[Path, typer.Argument(help="Path to CA certificate")],
    ca_key: Annotated[Path, typer.Argument(help="Path to CA private key")],
    csr: Annotated[Path, typer.Argument(help="Path to CSR file")],
    output: Annotated[Path, typer.Argument(help="Output path for signed certificate")],
    validity_days: Annotated[
        int,
        typer.Option("--validity", "-v", help="Validity period in days")
    ] = 365,
    hash_algo: Annotated[
        str,
        typer.Option("--hash", "-h", help="Hash algorithm: sha256, sha384, sha512")
    ] = "sha256",
    not_before: Annotated[
        Optional[str],
        typer.Option("--not-before", help="Not before date (YYYY-MM-DD HH:MM:SS)")
    ] = None,
) -> None:
    """
    Sign a Certificate Signing Request (CSR) with a CA.

    [bold]Examples:[/bold]

        Sign a CSR:
        $ certgen sign-csr ca.crt ca.pem server.csr server.crt

        Sign with custom validity:
        $ certgen sign-csr ca.crt ca.pem server.csr server.crt --validity 90
    """
    from datetime import datetime, timezone

    if not_before is None:
        not_before = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    with open(csr, "r") as f:
        csr_content = f.read()

    cg = CertGen()

    try:
        with console.status("[bold green]Signing CSR...[/bold green]"):
            result = cg.csr_signing(
                CACertFile=ca_cert,
                CAKeyFile=ca_key,
                csr=csr_content,
                notBefore=not_before,
                validityDays=validity_days,
                signedCertFile=output,
                digest=hash_algo,
            )

        console.print()
        console.print(Panel.fit(
            f"[bold green]✓[/bold green] CSR signed successfully!\n\n"
            f"[bold]Output:[/bold] {output}\n"
            f"[bold]Validity:[/bold] {validity_days} days",
            title="[bold]Signed Certificate[/bold]",
            border_style="green",
        ))

    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


@app.command()
def crl(
    ca_cert: Annotated[Path, typer.Argument(help="Path to CA certificate")],
    ca_key: Annotated[Path, typer.Argument(help="Path to CA private key")],
    output_dir: Annotated[
        Path,
        typer.Option("--output", "-o", help="Output directory for CRL")
    ] = Path("/tmp"),
    revoke: Annotated[
        Optional[Path],
        typer.Option("--revoke", "-r", help="Path to certificate to revoke")
    ] = None,
    next_update_days: Annotated[
        int,
        typer.Option("--next-update", "-n", help="Days until next update")
    ] = 30,
    hash_algo: Annotated[
        str,
        typer.Option("--hash", "-h", help="Hash algorithm: sha256, sha384, sha512")
    ] = "sha256",
) -> None:
    """
    Generate a Certificate Revocation List (CRL).

    [bold]Examples:[/bold]

        Generate empty CRL:
        $ certgen crl ca.crt ca.pem

        Generate CRL with revoked certificate:
        $ certgen crl ca.crt ca.pem --revoke compromised.crt
    """
    from datetime import datetime, timezone, timedelta

    now = datetime.now(timezone.utc)
    last_update = now.strftime("%Y-%m-%d %H:%M:%S")
    next_update = (now + timedelta(days=next_update_days)).strftime("%Y-%m-%d %H:%M:%S")

    cg = CertGen()

    try:
        with console.status("[bold green]Generating CRL...[/bold green]"):
            crl_path = cg.crl_gen(
                authCert=ca_cert,
                authKey=ca_key,
                serial=1,
                lastUpdate=last_update,
                nextUpdate=next_update,
                revokedFile=revoke,
                digest=hash_algo,
                base_dir=output_dir,
            )

        console.print()
        console.print(Panel.fit(
            f"[bold green]✓[/bold green] CRL generated!\n\n"
            f"[bold]Output:[/bold] {crl_path}\n"
            f"[bold]Next Update:[/bold] {next_update}",
            title="[bold]Certificate Revocation List[/bold]",
            border_style="green",
        ))

    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


@app.command()
def info(
    cert_path: Annotated[Path, typer.Argument(help="Path to certificate file")],
    show_extensions: Annotated[
        bool,
        typer.Option("--extensions", "-e", help="Show certificate extensions")
    ] = False,
    show_pem: Annotated[
        bool,
        typer.Option("--pem", "-p", help="Show PEM content")
    ] = False,
) -> None:
    """
    Display information about a certificate.

    [bold]Examples:[/bold]

        Show certificate info:
        $ certgen info server.crt

        Show with extensions:
        $ certgen info server.crt --extensions
    """
    try:
        with open(cert_path, "rb") as f:
            cert_data = f.read()
            cert = x509.load_pem_x509_certificate(cert_data)

        console.print()

        # Basic info table
        table = Table(title=f"Certificate: {cert_path.name}", show_header=False)
        table.add_column("Property", style="cyan", width=20)
        table.add_column("Value", style="white")

        table.add_row("Subject", cert.subject.rfc4514_string())
        table.add_row("Issuer", cert.issuer.rfc4514_string())
        table.add_row("Serial Number", str(cert.serial_number))
        table.add_row("Version", f"v{cert.version.value + 1}")
        table.add_row("Not Before", str(cert.not_valid_before_utc))
        table.add_row("Not After", str(cert.not_valid_after_utc))
        table.add_row("Signature Algorithm", cert.signature_algorithm_oid._name)

        # Check if self-signed
        is_self_signed = cert.issuer == cert.subject
        table.add_row("Self-Signed", "Yes" if is_self_signed else "No")

        console.print(table)

        if show_extensions:
            console.print()
            ext_table = Table(title="Extensions", show_header=True)
            ext_table.add_column("Extension", style="cyan")
            ext_table.add_column("Critical", style="yellow")
            ext_table.add_column("Value", style="white")

            for ext in cert.extensions:
                ext_table.add_row(
                    ext.oid._name,
                    "Yes" if ext.critical else "No",
                    str(ext.value)[:80] + "..." if len(str(ext.value)) > 80 else str(ext.value)
                )

            console.print(ext_table)

        if show_pem:
            console.print()
            console.print(Panel(
                cert_data.decode(),
                title="PEM Content",
                border_style="dim",
            ))

    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


@app.command()
def verify(
    cert_path: Annotated[Path, typer.Argument(help="Path to certificate to verify")],
    ca_cert: Annotated[
        Optional[Path],
        typer.Option("--ca", help="Path to CA certificate for verification")
    ] = None,
) -> None:
    """
    Verify a certificate.

    [bold]Examples:[/bold]

        Verify certificate is valid:
        $ certgen verify server.crt

        Verify against CA:
        $ certgen verify server.crt --ca ca.crt
    """
    from datetime import datetime, timezone

    try:
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())

        now = datetime.now(timezone.utc)
        issues = []
        warnings = []

        # Check validity period
        if now < cert.not_valid_before_utc:
            issues.append("Certificate is not yet valid")
        elif now > cert.not_valid_after_utc:
            issues.append("Certificate has expired")
        else:
            days_remaining = (cert.not_valid_after_utc - now).days
            if days_remaining < 30:
                warnings.append(f"Certificate expires in {days_remaining} days")

        # Check if CA cert provided
        if ca_cert:
            with open(ca_cert, "rb") as f:
                ca = x509.load_pem_x509_certificate(f.read())

            if cert.issuer != ca.subject:
                issues.append("Certificate issuer does not match CA subject")

        console.print()

        if issues:
            console.print(Panel.fit(
                "[bold red]✗[/bold red] Certificate verification failed!\n\n" +
                "\n".join(f"• {issue}" for issue in issues),
                title="[bold red]Verification Failed[/bold red]",
                border_style="red",
            ))
            raise typer.Exit(1)
        else:
            msg = "[bold green]✓[/bold green] Certificate is valid!"
            if warnings:
                msg += "\n\n[yellow]Warnings:[/yellow]\n" + "\n".join(f"• {w}" for w in warnings)
            console.print(Panel.fit(
                msg,
                title="[bold green]Verification Passed[/bold green]",
                border_style="green",
            ))

    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


@app.command()
def wizard() -> None:
    """
    Interactive wizard for generating a complete certificate chain.

    This wizard will guide you through creating:
    1. Root CA
    2. Intermediate CA (optional)
    3. Leaf certificate
    """
    from rich.prompt import Prompt, Confirm

    console.print()
    console.print(Panel.fit(
        "[bold]Certificate Chain Wizard[/bold]\n\n"
        "This wizard will help you create a complete certificate chain.",
        border_style="blue",
    ))
    console.print()

    # Reset state
    reset_cert_gen()
    cg = get_cert_gen()

    output_dir = Path(Prompt.ask(
        "[cyan]Output directory[/cyan]",
        default="/tmp/certs"
    ))
    output_dir.mkdir(parents=True, exist_ok=True)

    key_type = Prompt.ask(
        "[cyan]Key type[/cyan]",
        choices=["ed25519", "ed448", "ecdsa", "rsa"],
        default="ed25519"
    )

    # Root CA
    console.print("\n[bold]Step 1: Root CA[/bold]")
    root_cn = Prompt.ask("[cyan]Root CA common name[/cyan]", default="MyRootCA")

    with console.status("[bold green]Generating Root CA...[/bold green]"):
        root_cert, root_key = cg.cert_gen(
            commonName=root_cn,
            key_type=key_type,
            cert_category="RootCA",
            basedir=output_dir,
        )
    console.print(f"  [green]✓[/green] Root CA: {root_cert}")

    # Intermediate CA
    create_int = Confirm.ask("\n[cyan]Create Intermediate CA?[/cyan]", default=True)
    int_cert = None
    if create_int:
        console.print("\n[bold]Step 2: Intermediate CA[/bold]")
        int_cn = Prompt.ask("[cyan]Intermediate CA common name[/cyan]", default="MyIntCA")

        with console.status("[bold green]Generating Intermediate CA...[/bold green]"):
            int_cert, int_key = cg.cert_gen(
                commonName=int_cn,
                key_type=key_type,
                cert_category="IntCA",
                basedir=output_dir,
            )
        console.print(f"  [green]✓[/green] Intermediate CA: {int_cert}")

    # Leaf certificate
    console.print("\n[bold]Step 3: Leaf Certificate[/bold]")
    leaf_cn = Prompt.ask("[cyan]Leaf certificate common name[/cyan]", default="server.example.com")

    with console.status("[bold green]Generating leaf certificate...[/bold green]"):
        leaf_cert, leaf_key = cg.cert_gen(
            commonName=leaf_cn,
            key_type=key_type,
            cert_category="CN",
            basedir=output_dir,
        )
    console.print(f"  [green]✓[/green] Leaf certificate: {leaf_cert}")

    # Create chain
    console.print("\n[bold]Step 4: Certificate Chain[/bold]")
    with console.status("[bold green]Creating certificate chain...[/bold green]"):
        chain_content = cg.create_cert_chain(
            root_path=root_cert,
            cn_path=leaf_cert,
            int_path=int_cert,
        )
        chain_path = output_dir / "chain.pem"
        with open(chain_path, "w") as f:
            f.write(chain_content)
    console.print(f"  [green]✓[/green] Certificate chain: {chain_path}")

    # Summary
    console.print()
    tree = Tree("[bold]Generated Files[/bold]")
    tree.add(f"[cyan]{root_cert}[/cyan] (Root CA)")
    tree.add(f"[cyan]{root_key}[/cyan] (Root CA Key)")
    if int_cert:
        tree.add(f"[cyan]{int_cert}[/cyan] (Intermediate CA)")
        tree.add(f"[cyan]{int_key}[/cyan] (Intermediate CA Key)")
    tree.add(f"[cyan]{leaf_cert}[/cyan] (Leaf Certificate)")
    tree.add(f"[cyan]{leaf_key}[/cyan] (Leaf Key)")
    tree.add(f"[cyan]{chain_path}[/cyan] (Full Chain)")

    console.print(tree)
    console.print()
    console.print("[bold green]✓ Certificate chain generation complete![/bold green]")


@app.command()
def version() -> None:
    """Show version information."""
    console.print()
    console.print(Panel.fit(
        "[bold]Certificate Generator[/bold]\n\n"
        "Version: 0.1.0\n"
        "Python: 3.12+\n"
        "License: Apache 2.0",
        title="[bold]certgen[/bold]",
        border_style="blue",
    ))


def main() -> None:
    """Entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()
