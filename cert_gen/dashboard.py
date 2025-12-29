"""FastHTML dashboard for certificate generation and management."""

from __future__ import annotations

import tempfile
from pathlib import Path
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field

from fasthtml.common import *
from lucide_fasthtml import Lucide
from cryptography import x509

from cert_gen.cert_ops import CertGen

# Tailwind CSS via CDN.
# Note: if we set a tailwind.config object, it must be defined BEFORE loading the CDN script.
tailwind_config = Script("""
tailwind.config = {
    theme: {
        extend: {
            fontFamily: {
                sans: ['Inter', 'system-ui', 'sans-serif'],
            },
            colors: {
                primary: {
                    50: '#eef2ff',
                    100: '#e0e7ff',
                    500: '#6366f1',
                    600: '#4f46e5',
                    700: '#4338ca',
                },
                secondary: '#7c3aed',
                accent: '#0891b2',
                success: '#16a34a',
                warning: '#d97706',
                error: '#dc2626',
                gray: {
                    50: '#f8fafc',
                    100: '#f1f5f9',
                    200: '#e2e8f0',
                    300: '#cbd5e1',
                    400: '#94a3b8',
                    500: '#64748b',
                    600: '#475569',
                    700: '#334155',
                    800: '#1e293b',
                    900: '#0f172a',
                }
            }
        }
    }
}
""")

app, rt = fast_app(
    hdrs=(
        tailwind_config,
        Script(src="https://cdn.tailwindcss.com"),
        Link(rel="preconnect", href="https://fonts.googleapis.com"),
        Link(rel="stylesheet", href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap"),
        Style("""
            body { 
                font-family: 'Inter', sans-serif; 
                background-color: #f8fafc;
                color: #0f172a;
            }
            .glass {
                background: rgba(255, 255, 255, 0.7);
                backdrop-filter: blur(10px);
                -webkit-backdrop-filter: blur(10px);
            }
            /* Smooth transitions */
            .transition-all-custom {
                transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
            }
        """),
    ),
    pico=False,
)


@dataclass
class AppState:
    cert_gen: CertGen | None = None
    output_dir: Path = field(default_factory=lambda: Path(tempfile.mkdtemp()))
    certificates: dict[str, tuple[Path, Path]] = field(default_factory=dict)

    def reset(self):
        self.cert_gen = CertGen()
        self.certificates = {}

    def get_cert_gen(self) -> CertGen:
        if self.cert_gen is None:
            self.cert_gen = CertGen()
        return self.cert_gen


state = AppState()


def icon(name: str, cls: str = "w-5 h-5") -> Lucide:
    return Lucide(name, cls=cls)


def navbar():
    return Nav(cls="glass border-b border-gray-200/60 sticky top-0 z-50 transition-all duration-300")(
        Div(cls="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8")(
            Div(cls="flex justify-between h-16")(
                Div(cls="flex items-center")(
                    A(href="/", cls="flex items-center space-x-3 group")(
                        Div(cls="w-10 h-10 bg-primary-600 rounded-xl shadow-lg shadow-primary-500/30 flex items-center justify-center transform group-hover:scale-105 transition-all duration-300")(
                            icon("shield-check", "w-6 h-6 text-white")
                        ),
                        Span("CertGen", cls="text-xl font-bold text-gray-900 tracking-tight"),
                    ),
                ),
                Div(cls="flex items-center space-x-2")(
                    *[
                        A(
                            text, 
                            href=href, 
                            cls="px-4 py-2 text-sm font-medium text-gray-600 hover:text-primary-600 hover:bg-primary-50 rounded-lg transition-colors duration-200"
                        )
                        for text, href in [
                            ("Dashboard", "/"),
                            ("Generate", "/generate"),
                            ("Certificates", "/certificates"),
                            ("Chain", "/chain")
                        ]
                    ]
                ),
            ),
        ),
    )


def page(*children, title: str = "CertGen"):
    return Html(
        Head(
            Title(title),
            Meta(charset="utf-8"),
            Meta(name="viewport", content="width=device-width, initial-scale=1"),
        ),
        Body(cls="bg-gray-50 min-h-screen text-gray-900 antialiased")(
            navbar(),
            Main(cls="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 animate-fade-in")(*children),
            Script("document.body.classList.add('opacity-100');") # Simple hack to ensure load
        ),
    )


def card(*children, title: str = None, cls: str = ""):
    return Div(cls=f"bg-white rounded-2xl shadow-sm border border-gray-100/60 hover:shadow-md transition-all-custom duration-300 overflow-hidden {cls}")(
        Div(cls="p-6")(
            H3(title, cls="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2") if title else None,
            *children,
        ),
    )


def stat_card(title: str, value: str, subtitle: str, icon_name: str, color: str = "primary"):
    # Map colors to classes manually to ensure they exist
    colors = {
        "primary": ("bg-indigo-50", "text-indigo-600", "text-indigo-600"),
        "success": ("bg-green-50", "text-green-600", "text-green-600"),
        "warning": ("bg-amber-50", "text-amber-600", "text-amber-600"),
        "accent": ("bg-cyan-50", "text-cyan-600", "text-cyan-600"),
    }
    bg_cls, icon_cls, text_cls = colors.get(color, colors["primary"])

    return Div(cls="bg-white rounded-2xl shadow-sm border border-gray-100 hover:shadow-md transition-all duration-300 p-6 group")(
        Div(cls="flex items-center justify-between")(
            Div()(
                P(title, cls="text-sm font-medium text-gray-500"),
                P(value, cls="text-3xl font-bold text-gray-900 mt-2 tracking-tight"),
                P(subtitle, cls="text-xs text-gray-400 mt-1 font-medium"),
            ),
            Div(cls=f"w-12 h-12 rounded-xl flex items-center justify-center {bg_cls} group-hover:scale-110 transition-transform duration-300")(
                icon(icon_name, f"w-6 h-6 {icon_cls}"),
            ),
        ),
    )


def alert(message: str, type: str = "info"):
    styles = {
        "info": "bg-blue-50 border-blue-200 text-blue-800",
        "success": "bg-green-50 border-green-200 text-green-800",
        "warning": "bg-amber-50 border-amber-200 text-amber-800",
        "error": "bg-red-50 border-red-200 text-red-800",
    }
    icons = {"info": "info", "success": "check-circle", "warning": "alert-triangle", "error": "x-circle"}

    return Div(cls=f"rounded-lg border p-4 flex items-center space-x-3 {styles.get(type, styles['info'])}")(
        icon(icons.get(type, "info"), "w-5 h-5 flex-shrink-0"),
        P(message, cls="text-sm font-medium"),
    )


def button(text: str, icon_name: str = None, variant: str = "primary", type: str = "button", cls: str = "", **kwargs):
    variants = {
        "primary": "bg-primary-600 hover:bg-primary-700 text-white shadow-md shadow-primary-500/20",
        "secondary": "bg-white hover:bg-gray-50 text-gray-700 border border-gray-200",
        "outline": "bg-transparent hover:bg-gray-50 text-gray-700 border border-gray-300",
        "danger": "bg-red-600 hover:bg-red-700 text-white shadow-md shadow-red-500/20",
    }

    return Button(
        type=type,
        cls=(
            f"inline-flex items-center justify-center px-4 py-2.5 rounded-lg text-sm font-semibold "
            f"transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 "
            f"active:scale-95 "
            f"{variants.get(variant, variants['primary'])} {cls}"
        ),
        **kwargs
    )(
        icon(icon_name, "w-4 h-4 mr-2") if icon_name else None,
        text,
    )


def input_field(label: str, name: str, type: str = "text", placeholder: str = "", value: str = "", required: bool = False, **kwargs):
    return Div(cls="space-y-1.5")(
        Label(label, cls="block text-sm font-medium text-gray-700", **{"for": name}),
        Input(
            type=type,
            name=name,
            id=name,
            placeholder=placeholder,
            value=value,
            required=required,
            cls="w-full px-4 py-2.5 bg-white border border-gray-300 rounded-lg shadow-sm focus:ring-2 focus:ring-primary-500/20 focus:border-primary-500 text-sm transition-all duration-200 hover:border-gray-400",
            **kwargs,
        ),
    )


def select_field(label: str, name: str, options: list[tuple[str, str]], selected: str = None, disabled_options: list[str] = None):
    disabled_options = disabled_options or []
    return Div(cls="space-y-1.5")(
        Label(label, cls="block text-sm font-medium text-gray-700", **{"for": name}),
        Div(cls="relative")(
            Select(
                name=name,
                id=name,
                cls="w-full px-4 py-2.5 bg-white border border-gray-300 rounded-lg shadow-sm focus:ring-2 focus:ring-primary-500/20 focus:border-primary-500 text-sm appearance-none transition-all duration-200 hover:border-gray-400 cursor-pointer",
            )(
                *[Option(text, value=val, selected=(val == selected), disabled=(val in disabled_options)) for text, val in options]
            ),
            Div(cls="absolute inset-y-0 right-0 flex items-center px-2 pointer-events-none text-gray-500")(
                icon("chevron-down", "w-4 h-4")
            )
        )
    )


@rt("/")
def home():
    cert_count = len(state.certificates)
    has_root = "root" in state.certificates
    has_int = "int" in state.certificates

    return page(
        # Hero
        Div(cls="text-center mb-16 pt-8")(
            Div(cls="inline-flex items-center justify-center w-20 h-20 bg-primary-600 rounded-2xl shadow-xl shadow-primary-500/20 mb-6 transform hover:scale-105 transition-transform duration-300")(
                icon("shield-check", "w-10 h-10 text-white"),
            ),
            H1("Certificate Generator", cls="text-4xl font-extrabold text-gray-900 mb-3 tracking-tight"),
            P("Generate and manage X.509 certificates with modern elliptic curve cryptography", cls="text-lg text-gray-500 max-w-lg mx-auto leading-relaxed"),
        ),

        # Stats
        Div(cls="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-12")(
            stat_card("Certificates", str(cert_count), "Generated this session", "file-key", "primary"),
            stat_card("Root CA", "Active" if has_root else "None", "Self-signed root", "shield", "success" if has_root else "warning"),
            stat_card("Intermediate", "Active" if has_int else "None", "Signed by Root", "layers", "success" if has_int else "warning"),
            stat_card("Default Key", "Ed25519", "Curve25519", "key", "accent"),
        ),

        # Quick Actions
        Div(cls="mb-12")(
            Div(cls="flex items-center justify-between mb-6")(
                H2("Quick Actions", cls="text-2xl font-bold text-gray-900"),
            ),
            Div(cls="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6")(
                A(href="/generate", cls="group block")(
                    Div(cls="bg-white rounded-2xl shadow-sm border border-gray-100 p-6 hover:shadow-lg hover:border-primary-100 transition-all duration-300 h-full")(
                        Div(cls="w-12 h-12 bg-primary-50 rounded-xl flex items-center justify-center mb-4 group-hover:bg-primary-600 transition-colors duration-300")(
                            icon("plus-circle", "w-6 h-6 text-primary-600 group-hover:text-white transition-colors duration-300"),
                        ),
                        H3("Generate Certificate", cls="font-semibold text-gray-900 mb-2"),
                        P("Create Root CA, Intermediate CA, or leaf certificates", cls="text-sm text-gray-500 leading-relaxed"),
                    ),
                ),
                A(href="/chain", cls="group block")(
                    Div(cls="bg-white rounded-2xl shadow-sm border border-gray-100 p-6 hover:shadow-lg hover:border-cyan-100 transition-all duration-300 h-full")(
                        Div(cls="w-12 h-12 bg-cyan-50 rounded-xl flex items-center justify-center mb-4 group-hover:bg-cyan-600 transition-colors duration-300")(
                            icon("link", "w-6 h-6 text-cyan-600 group-hover:text-white transition-colors duration-300"),
                        ),
                        H3("Build Chain", cls="font-semibold text-gray-900 mb-2"),
                        P("Assemble certificates into a complete chain", cls="text-sm text-gray-500 leading-relaxed"),
                    ),
                ),
                A(href="/certificates", cls="group block")(
                    Div(cls="bg-white rounded-2xl shadow-sm border border-gray-100 p-6 hover:shadow-lg hover:border-violet-100 transition-all duration-300 h-full")(
                        Div(cls="w-12 h-12 bg-violet-50 rounded-xl flex items-center justify-center mb-4 group-hover:bg-violet-600 transition-colors duration-300")(
                            icon("file-search", "w-6 h-6 text-violet-600 group-hover:text-white transition-colors duration-300"),
                        ),
                        H3("View Certificates", cls="font-semibold text-gray-900 mb-2"),
                        P("Inspect generated certificates and keys", cls="text-sm text-gray-500 leading-relaxed"),
                    ),
                ),
                A(href="/reset", cls="group block")(
                    Div(cls="bg-white rounded-2xl shadow-sm border border-gray-100 p-6 hover:shadow-lg hover:border-gray-300 transition-all duration-300 h-full")(
                        Div(cls="w-12 h-12 bg-gray-100 rounded-xl flex items-center justify-center mb-4 group-hover:bg-gray-800 transition-colors duration-300")(
                            icon("rotate-ccw", "w-6 h-6 text-gray-600 group-hover:text-white transition-colors duration-300"),
                        ),
                        H3("Reset Session", cls="font-semibold text-gray-900 mb-2"),
                        P("Clear all generated certificates", cls="text-sm text-gray-500 leading-relaxed"),
                    ),
                ),
            ),
        ),

        # Supported Key Types
        Div(cls="mb-8")(
            H2("Supported Key Types", cls="text-2xl font-bold text-gray-900 mb-6"),
            Div(cls="bg-white rounded-2xl shadow-sm border border-gray-200 overflow-hidden")(
                Div(cls="grid grid-cols-2 md:grid-cols-5 divide-x divide-gray-200")(
                    Div(cls="p-6 text-center hover:bg-gray-50 transition-colors")(
                        Span("Ed25519", cls="inline-block px-3 py-1 bg-primary-50 text-primary-700 rounded-full text-sm font-semibold mb-2"),
                        P("Curve25519 · Default", cls="text-xs text-gray-500"),
                    ),
                    Div(cls="p-6 text-center hover:bg-gray-50 transition-colors")(
                        Span("Ed448", cls="inline-block px-3 py-1 bg-violet-50 text-violet-700 rounded-full text-sm font-semibold mb-2"),
                        P("Curve448 · High security", cls="text-xs text-gray-500"),
                    ),
                    Div(cls="p-6 text-center hover:bg-gray-50 transition-colors")(
                        Span("ECDSA", cls="inline-block px-3 py-1 bg-cyan-50 text-cyan-700 rounded-full text-sm font-semibold mb-2"),
                        P("SECP256R1 · Compatible", cls="text-xs text-gray-500"),
                    ),
                    Div(cls="p-6 text-center hover:bg-gray-50 transition-colors")(
                        Span("RSA", cls="inline-block px-3 py-1 bg-amber-50 text-amber-700 rounded-full text-sm font-semibold mb-2"),
                        P("1024-4096 bit · Legacy", cls="text-xs text-gray-500"),
                    ),
                    Div(cls="p-6 text-center hover:bg-gray-50 transition-colors")(
                        Span("DSA", cls="inline-block px-3 py-1 bg-gray-100 text-gray-700 rounded-full text-sm font-semibold mb-2"),
                        P("1024-4096 bit · Legacy", cls="text-xs text-gray-500"),
                    ),
                ),
            ),
        ),
        title="CertGen Dashboard",
    )


@rt("/generate")
def generate_page():
    has_root = "root" in state.certificates
    has_int = "int" in state.certificates

    disabled_cats = []
    if has_root:
        disabled_cats.append("RootCA")
    if not has_root:
        disabled_cats.extend(["IntCA", "CN"])
    if has_int:
        disabled_cats.append("IntCA")

    return page(
        Div(cls="max-w-2xl mx-auto")(
            # Header
            Div(cls="mb-8")(
                A(href="/", cls="inline-flex items-center text-sm text-gray-500 hover:text-gray-700 mb-4")(
                    icon("arrow-left", "w-4 h-4 mr-1"),
                    "Back to Dashboard",
                ),
                H1("Generate Certificate", cls="text-2xl font-bold text-gray-900"),
                P("Create a new certificate with your preferred settings", cls="text-gray-500 mt-1"),
            ),

            # Status
            Div(cls="grid grid-cols-2 gap-4 mb-6")(
                Div(cls=f"rounded-lg p-4 flex items-center space-x-3 {'bg-green-50 border border-green-200' if has_root else 'bg-amber-50 border border-amber-200'}")(
                    icon("shield-check" if has_root else "shield-alert", f"w-5 h-5 {'text-green-600' if has_root else 'text-amber-600'}"),
                    Div()(
                        P("Root CA", cls="text-sm font-medium text-gray-900"),
                        P("Active" if has_root else "Not created", cls="text-xs text-gray-500"),
                    ),
                ),
                Div(cls=f"rounded-lg p-4 flex items-center space-x-3 {'bg-green-50 border border-green-200' if has_int else 'bg-gray-50 border border-gray-200'}")(
                    icon("layers", f"w-5 h-5 {'text-green-600' if has_int else 'text-gray-400'}"),
                    Div()(
                        P("Intermediate CA", cls="text-sm font-medium text-gray-900"),
                        P("Active" if has_int else "Optional", cls="text-xs text-gray-500"),
                    ),
                ),
            ),

            # Form
            card(
                Form(action="/generate", method="post", cls="space-y-5")(
                    input_field("Common Name", "common_name", placeholder="e.g., MyRootCA or server.example.com", required=True),

                    select_field("Certificate Category", "category", [
                        ("Root CA (Self-signed)", "RootCA"),
                        ("Intermediate CA (Signed by Root)", "IntCA"),
                        ("Leaf Certificate (End entity)", "CN"),
                    ], selected="RootCA" if not has_root else ("IntCA" if not has_int else "CN"), disabled_options=disabled_cats),

                    select_field("Key Type", "key_type", [
                        ("Ed25519 - Recommended", "ed25519"),
                        ("Ed448 - High Security", "ed448"),
                        ("ECDSA - Wide Compatibility", "ecdsa"),
                        ("RSA - Legacy", "rsa"),
                        ("DSA - Legacy", "dsa"),
                    ], selected="ed25519"),

                    Div(cls="grid grid-cols-2 gap-4")(
                        select_field("Key Length (RSA/DSA)", "key_length", [
                            ("2048 bits", "2048"),
                            ("4096 bits", "4096"),
                        ], selected="4096"),
                        input_field("Validity (days)", "validity_days", type="number", value="365"),
                    ),

                    Div(cls="pt-4")(
                        button("Generate Certificate", icon_name="plus-circle", type="submit", cls="w-full"),
                    ),
                ),
            ),
        ),
        title="Generate Certificate",
    )


@rt("/generate", methods=["POST"])
def generate_cert(common_name: str, category: str, key_type: str, key_length: int, validity_days: int):
    cg = state.get_cert_gen()

    try:
        validity_seconds = int(validity_days) * 24 * 60 * 60

        cert_path, key_path = cg.cert_gen(
            commonName=common_name,
            key_type=key_type,
            key_length=int(key_length),
            validityEndInSeconds=validity_seconds,
            cert_category=category,
            basedir=state.output_dir,
        )

        key = {"RootCA": "root", "IntCA": "int", "CN": f"leaf_{len([k for k in state.certificates if k.startswith('leaf')])}"}[category]
        state.certificates[key] = (cert_path, key_path)

        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())

        return page(
            Div(cls="max-w-2xl mx-auto")(
                alert(f"Certificate '{common_name}' generated successfully!", "success"),

                card(
                    Div(cls="space-y-4")(
                        Div(cls="flex items-center justify-between py-2 border-b border-gray-100")(
                            Span("Subject", cls="text-sm text-gray-500"),
                            Span(cert.subject.rfc4514_string(), cls="text-sm font-medium text-gray-900"),
                        ),
                        Div(cls="flex items-center justify-between py-2 border-b border-gray-100")(
                            Span("Issuer", cls="text-sm text-gray-500"),
                            Span(cert.issuer.rfc4514_string(), cls="text-sm font-medium text-gray-900"),
                        ),
                        Div(cls="flex items-center justify-between py-2 border-b border-gray-100")(
                            Span("Valid Until", cls="text-sm text-gray-500"),
                            Span(str(cert.not_valid_after_utc.date()), cls="text-sm font-medium text-gray-900"),
                        ),
                        Div(cls="flex items-center justify-between py-2 border-b border-gray-100")(
                            Span("Key Type", cls="text-sm text-gray-500"),
                            Span(key_type.upper(), cls="text-sm font-medium text-gray-900"),
                        ),
                        Div(cls="flex items-center justify-between py-2")(
                            Span("Certificate Path", cls="text-sm text-gray-500"),
                            Span(str(cert_path), cls="text-xs font-mono text-gray-600"),
                        ),
                    ),
                    title="Certificate Details",
                    cls="mt-6",
                ),

                Div(cls="flex space-x-3 mt-6")(
                    A(href="/generate")(button("Generate Another", icon_name="plus", variant="primary")),
                    A(href="/certificates")(button("View All", icon_name="list", variant="outline")),
                ),
            ),
            title="Certificate Generated",
        )

    except ValueError as e:
        return page(
            Div(cls="max-w-2xl mx-auto")(
                alert(str(e), "error"),
                A(href="/generate", cls="mt-4 inline-block")(button("Try Again", icon_name="arrow-left", variant="outline")),
            ),
            title="Error",
        )


@rt("/certificates")
def certificates_page():
    if not state.certificates:
        return page(
            Div(cls="text-center py-16")(
                Div(cls="w-16 h-16 bg-gray-100 rounded-full flex items-center justify-center mx-auto mb-4")(
                    icon("inbox", "w-8 h-8 text-gray-400"),
                ),
                H2("No certificates yet", cls="text-xl font-semibold text-gray-900 mb-2"),
                P("Generate your first certificate to get started", cls="text-gray-500 mb-6"),
                A(href="/generate")(button("Generate Certificate", icon_name="plus-circle")),
            ),
            title="Certificates",
        )

    cert_cards = []
    for name, (cert_path, key_path) in state.certificates.items():
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())

        cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
        category = "Root CA" if name == "root" else "Intermediate CA" if name == "int" else "Leaf"
        badge_cls = "bg-indigo-100 text-indigo-700" if name == "root" else "bg-violet-100 text-violet-700" if name == "int" else "bg-cyan-100 text-cyan-700"

        cert_cards.append(
            Div(cls="bg-white rounded-xl shadow-sm border border-gray-200 p-6")(
                Div(cls="flex items-start justify-between mb-4")(
                    Div()(
                        Span(category, cls=f"inline-block px-2 py-1 rounded-full text-xs font-medium {badge_cls}"),
                    ),
                    icon("file-key", "w-5 h-5 text-gray-400"),
                ),
                H3(cn, cls="font-semibold text-gray-900 mb-1 truncate"),
                P(f"Valid until {cert.not_valid_after_utc.strftime('%Y-%m-%d')}", cls="text-sm text-gray-500 mb-4"),
                Div(cls="flex space-x-2")(
                    A(href=f"/certificate/{name}")(button("Details", variant="outline", cls="text-xs px-3 py-1")),
                ),
            )
        )

    return page(
        Div(cls="mb-6")(
            H1("Certificates", cls="text-2xl font-bold text-gray-900"),
            P(f"{len(state.certificates)} certificate(s) generated", cls="text-gray-500"),
        ),
        Div(cls="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4")(*cert_cards),
        title="Certificates",
    )


@rt("/certificate/{name}")
def certificate_detail(name: str):
    if name not in state.certificates:
        return page(alert("Certificate not found", "error"), title="Error")

    cert_path, key_path = state.certificates[name]
    with open(cert_path, "rb") as f:
        cert_data = f.read()
        cert = x509.load_pem_x509_certificate(cert_data)

    cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value

    return page(
        Div(cls="mb-6")(
            A(href="/certificates", cls="inline-flex items-center text-sm text-gray-500 hover:text-gray-700 mb-4")(
                icon("arrow-left", "w-4 h-4 mr-1"), "Back to Certificates"
            ),
            H1(cn, cls="text-2xl font-bold text-gray-900"),
        ),

        Div(cls="grid grid-cols-1 lg:grid-cols-2 gap-6")(
            card(
                Div(cls="space-y-3")(
                    *[Div(cls="flex justify-between py-2 border-b border-gray-100")(
                        Span(k, cls="text-sm text-gray-500"), Span(v, cls="text-sm font-medium text-gray-900 text-right")
                    ) for k, v in [
                        ("Subject", cert.subject.rfc4514_string()),
                        ("Issuer", cert.issuer.rfc4514_string()),
                        ("Serial", str(cert.serial_number)),
                        ("Not Before", str(cert.not_valid_before_utc)),
                        ("Not After", str(cert.not_valid_after_utc)),
                        ("Algorithm", cert.signature_algorithm_oid._name),
                    ]],
                ),
                title="Certificate Info",
            ),
            card(
                Div(cls="space-y-2")(
                    *[Div(cls="flex items-center justify-between py-2 border-b border-gray-100")(
                        Span(ext.oid._name, cls="text-sm text-gray-700"),
                        Span("Critical", cls="text-xs px-2 py-1 bg-amber-100 text-amber-700 rounded") if ext.critical else None,
                    ) for ext in cert.extensions]
                ),
                title="Extensions",
            ),
        ),

        card(
            Pre(cert_data.decode(), cls="text-xs font-mono text-gray-600 overflow-x-auto whitespace-pre-wrap"),
            title="PEM Content",
            cls="mt-6",
        ),
        title=f"Certificate: {cn}",
    )


@rt("/chain")
def chain_page():
    has_root = "root" in state.certificates
    has_int = "int" in state.certificates
    has_leaf = any(k.startswith("leaf") for k in state.certificates)

    if not has_root:
        return page(
            Div(cls="text-center py-16")(
                icon("link", "w-12 h-12 text-gray-300 mx-auto mb-4"),
                H2("No Root CA", cls="text-xl font-semibold text-gray-900 mb-2"),
                P("Generate a Root CA first to build a chain", cls="text-gray-500 mb-6"),
                A(href="/generate")(button("Generate Root CA", icon_name="plus-circle")),
            ),
            title="Chain Builder",
        )

    return page(
        Div(cls="max-w-2xl mx-auto")(
            H1("Chain Builder", cls="text-2xl font-bold text-gray-900 mb-2"),
            P("Combine certificates into a full chain", cls="text-gray-500 mb-8"),

            card(
                Div(cls="space-y-4 mb-6")(
                    *[Div(cls="flex items-center space-x-3 p-3 bg-gray-50 rounded-lg")(
                        icon("check-circle", "w-5 h-5 text-green-500"),
                        Span(name.replace("_", " ").title(), cls="text-sm font-medium text-gray-700"),
                    ) for name in state.certificates]
                ),
                Form(action="/chain/build", method="post", cls="space-y-4")(
                    Div(cls="flex items-center justify-between p-3 border border-gray-200 rounded-lg")(
                        Label("Include Leaf Certificate", cls="text-sm font-medium text-gray-700"),
                        Input(type="checkbox", name="include_leaf", checked=has_leaf, disabled=not has_leaf, cls="w-4 h-4 text-indigo-600 rounded"),
                    ),
                    Div(cls="flex items-center justify-between p-3 border border-gray-200 rounded-lg")(
                        Label("Include Intermediate CA", cls="text-sm font-medium text-gray-700"),
                        Input(type="checkbox", name="include_int", checked=has_int, disabled=not has_int, cls="w-4 h-4 text-indigo-600 rounded"),
                    ),
                    button("Build Chain", icon_name="link", type="submit", cls="w-full"),
                ),
                title="Available Certificates",
            ),
        ),
        title="Chain Builder",
    )


@rt("/chain/build", methods=["POST"])
def build_chain(include_leaf: bool = False, include_int: bool = False):
    cg = CertGen()
    root_path = state.certificates["root"][0]
    int_path = state.certificates.get("int", (None,))[0] if include_int else None
    leaf_keys = [k for k in state.certificates if k.startswith("leaf")]
    leaf_path = state.certificates[leaf_keys[0]][0] if include_leaf and leaf_keys else None

    if not leaf_path and not int_path:
        return page(alert("Select at least one certificate", "error"), A(href="/chain")(button("Back", variant="outline")), title="Error")

    chain_content = cg.create_cert_chain(root_path=root_path, cn_path=leaf_path, int_path=int_path)
    chain_path = state.output_dir / "chain.pem"
    chain_path.write_text(chain_content)

    return page(
        Div(cls="max-w-2xl mx-auto")(
            alert(f"Chain created with {chain_content.count('BEGIN CERTIFICATE')} certificates!", "success"),
            card(Pre(chain_content, cls="text-xs font-mono text-gray-600 overflow-x-auto max-h-96"), title="Chain Content", cls="mt-6"),
            A(href="/chain", cls="mt-6 inline-block")(button("Back", icon_name="arrow-left", variant="outline")),
        ),
        title="Chain Created",
    )


@rt("/reset")
def reset_session():
    state.reset()
    return page(
        Div(cls="text-center py-16")(
            icon("check-circle", "w-16 h-16 text-green-500 mx-auto mb-4"),
            H2("Session Reset", cls="text-xl font-semibold text-gray-900 mb-2"),
            P("All certificates have been cleared", cls="text-gray-500 mb-6"),
            A(href="/")(button("Back to Dashboard", icon_name="home")),
        ),
        title="Reset Complete",
    )


def main():
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)


if __name__ == "__main__":
    main()
