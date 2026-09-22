from __future__ import annotations

import argparse
import ipaddress
import json
import platform
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from http.client import HTTPResponse
from pathlib import Path
from typing import Any, Iterable

MIN_PORT = 1
MAX_PORT = 65535

SECURITY_HEADERS: dict[str, str] = {
    "strict-transport-security": "Protects HTTPS sites from downgrade attacks.",
    "content-security-policy": "Reduces cross-site scripting and injection risk.",
    "x-content-type-options": "Prevents MIME sniffing when set to nosniff.",
    "x-frame-options": "Reduces clickjacking risk.",
    "referrer-policy": "Controls referrer data leakage.",
    "permissions-policy": "Limits access to powerful browser features.",
}


class Colors:
    """ANSI color helper with opt-out support."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    CYAN = "\033[36m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    DIM = "\033[2m"

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled

    def paint(self, text: object, color: str) -> str:
        rendered = str(text)
        if not self.enabled:
            return rendered
        return f"{color}{rendered}{self.RESET}"

    def bold(self, text: object) -> str:
        return self.paint(text, self.BOLD)

    def cyan(self, text: object) -> str:
        return self.paint(text, self.CYAN)

    def green(self, text: object) -> str:
        return self.paint(text, self.GREEN)

    def yellow(self, text: object) -> str:
        return self.paint(text, self.YELLOW)

    def red(self, text: object) -> str:
        return self.paint(text, self.RED)

    def dim(self, text: object) -> str:
        return self.paint(text, self.DIM)


class CliLogger:
    """Minimal CLI logger supporting verbose and quiet modes."""

    def __init__(self, colors: Colors, verbose: bool = False, quiet: bool = False) -> None:
        self.colors = colors
        self.verbose = verbose
        self.quiet = quiet

    def raw(self, message: object) -> None:
        print(message)

    def section(self, title: str) -> None:
        if not self.quiet:
            print(self.colors.bold(self.colors.cyan(title)))

    def item(self, key: str, value: Any | None = None) -> None:
        if self.quiet:
            return
        label = self.colors.green(key.replace("_", " ").title())
        print(f"{label}: {value}" if value is not None else f"{label}:")

    def success(self, message: object) -> None:
        if not self.quiet:
            print(self.colors.green(message))

    def error(self, message: object) -> None:
        if not self.quiet:
            print(self.colors.red(f"Error: {message}"))


def validate_host(host: str) -> str:
    """Validate a hostname or IP-like target string."""
    cleaned = host.strip()
    if not cleaned:
        raise ValueError("Target host cannot be empty.")
    if any(ch.isspace() for ch in cleaned):
        raise ValueError("Target host cannot contain whitespace.")
    return cleaned


def validate_port(port: int) -> int:
    """Validate a TCP port number."""
    if not MIN_PORT <= int(port) <= MAX_PORT:
        raise ValueError(f"Port must be between {MIN_PORT} and {MAX_PORT}.")
    return int(port)


def validate_timeout(timeout: float) -> float:
    """Validate a positive timeout value."""
    if timeout <= 0:
        raise ValueError("Timeout must be greater than zero.")
    return float(timeout)


def parse_ports(port_expression: str) -> list[int]:
    """Parse ports such as ``22``, ``22,80,443``, or ``1-1024``."""
    if not port_expression or not port_expression.strip():
        raise ValueError("Ports cannot be empty.")

    ports: set[int] = set()
    for part in port_expression.split(","):
        token = part.strip()
        if not token:
            raise ValueError("Port expression contains an empty item.")
        if "-" in token:
            start_text, end_text = token.split("-", 1)
            if not start_text.isdigit() or not end_text.isdigit():
                raise ValueError(f"Invalid port range: {token}")
            start = validate_port(int(start_text))
            end = validate_port(int(end_text))
            if start > end:
                raise ValueError(f"Port range start is greater than end: {token}")
            ports.update(range(start, end + 1))
        else:
            if not token.isdigit():
                raise ValueError(f"Invalid port: {token}")
            ports.add(validate_port(int(token)))
    return sorted(ports)


def banner_grab(host: str, port: int, timeout: float = 2.0) -> dict[str, object]:
    """Attempt to retrieve a service banner from a TCP endpoint."""
    target = validate_host(host)
    tcp_port = validate_port(port)
    bounded_timeout = validate_timeout(timeout)
    result: dict[str, object] = {
        "type": "banner_grab",
        "target": target,
        "port": tcp_port,
        "banner": None,
        "status": "unknown",
    }

    try:
        with socket.create_connection((target, tcp_port), timeout=bounded_timeout) as sock:
            sock.settimeout(bounded_timeout)
            try:
                sock.sendall(b"\r\n")
            except OSError:
                pass
            data = sock.recv(1024)
        result["banner"] = data.decode("utf-8", errors="replace").strip() or None
        result["status"] = "open"
    except (TimeoutError, socket.timeout):
        result["status"] = "timeout"
    except OSError as exc:
        result["status"] = "closed_or_filtered"
        result["error"] = str(exc)
    return result


def _scan_one(host: str, port: int, timeout: float, grab_banners: bool) -> dict[str, object]:
    """Scan one TCP port."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
        entry: dict[str, object] = {"port": port, "state": "open"}
        if grab_banners:
            entry["banner"] = banner_grab(host, port, timeout=timeout).get("banner")
        return entry
    except (TimeoutError, socket.timeout):
        return {"port": port, "state": "filtered"}
    except OSError:
        return {"port": port, "state": "closed"}


def scan_tcp_ports(
    host: str,
    ports: Iterable[int],
    timeout: float = 1.0,
    grab_banners: bool = True,
    verbose: bool = False,
) -> dict[str, object]:
    """Scan a target host for open TCP ports."""
    target = validate_host(host)
    bounded_timeout = validate_timeout(timeout)
    validated_ports = [validate_port(port) for port in ports]
    if not validated_ports:
        raise ValueError("At least one port is required.")

    open_ports: list[dict[str, object]] = []
    closed_count = 0
    filtered_count = 0
    workers = max(1, min(100, len(validated_ports), 256))

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_scan_one, target, port, bounded_timeout, grab_banners): port
            for port in validated_ports
        }
        for future in as_completed(futures):
            entry = future.result()
            if entry["state"] == "open":
                open_ports.append(entry)
            elif entry["state"] == "filtered":
                filtered_count += 1
            else:
                closed_count += 1

    result: dict[str, object] = {
        "type": "tcp_port_scan",
        "target": target,
        "ports_scanned": len(validated_ports),
        "open_ports": sorted(open_ports, key=lambda item: int(item["port"])),
    }
    if verbose:
        result["closed_ports"] = closed_count
        result["filtered_ports"] = filtered_count
    return result


def dns_lookup(hostname: str) -> dict[str, object]:
    """Resolve a hostname to available IP addresses."""
    target = validate_host(hostname)
    addresses: set[str] = set()
    errors: list[str] = []
    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(target, None):
            if family in (socket.AF_INET, socket.AF_INET6):
                addresses.add(str(sockaddr[0]))
    except socket.gaierror as exc:
        errors.append(str(exc))
    return {"type": "dns_lookup", "target": target, "addresses": sorted(addresses), "errors": errors}


def reverse_dns_lookup(address: str) -> dict[str, object]:
    """Resolve an IP address to a hostname when PTR records are available."""
    cleaned = address.strip()
    if not cleaned:
        raise ValueError("IP address cannot be empty.")
    try:
        ipaddress.ip_address(cleaned)
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {cleaned}") from exc

    result: dict[str, object] = {
        "type": "reverse_dns_lookup",
        "address": cleaned,
        "hostname": None,
        "aliases": [],
    }
    try:
        hostname, aliases, _ = socket.gethostbyaddr(cleaned)
        result["hostname"] = hostname
        result["aliases"] = aliases
    except (socket.herror, socket.gaierror) as exc:
        result["error"] = str(exc)
    return result


def normalize_url(url: str) -> str:
    """Validate and normalize an HTTP or HTTPS URL."""
    cleaned = url.strip()
    if not cleaned:
        raise ValueError("URL cannot be empty.")
    if "://" not in cleaned:
        cleaned = f"https://{cleaned}"
    parsed = urllib.parse.urlparse(cleaned)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")
    if not parsed.netloc:
        raise ValueError("URL must include a hostname.")
    return cleaned


def _request(url: str, timeout: float, method: str = "HEAD") -> HTTPResponse:
    """Issue an HTTP request with a browser-like User-Agent."""
    validate_timeout(timeout)
    request = urllib.request.Request(
        normalize_url(url),
        method=method,
        headers={"User-Agent": "NetScope/1.0"},
    )
    return urllib.request.urlopen(request, timeout=timeout)


def check_http_status(url: str, timeout: float = 5.0) -> dict[str, object]:
    """Return status information for an HTTP or HTTPS endpoint."""
    normalized = normalize_url(url)
    result: dict[str, object] = {
        "type": "http_status",
        "url": normalized,
        "status_code": None,
        "reason": None,
        "final_url": None,
    }
    try:
        with _request(normalized, timeout=timeout, method="HEAD") as response:
            result.update({"status_code": response.status, "reason": response.reason, "final_url": response.geturl()})
    except urllib.error.HTTPError as exc:
        result.update({"status_code": exc.code, "reason": exc.reason, "final_url": exc.url})
    except urllib.error.URLError:
        try:
            with _request(normalized, timeout=timeout, method="GET") as response:
                result.update(
                    {"status_code": response.status, "reason": response.reason, "final_url": response.geturl()}
                )
        except urllib.error.HTTPError as exc:
            result.update({"status_code": exc.code, "reason": exc.reason, "final_url": exc.url})
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            result["error"] = str(exc)
    except (TimeoutError, OSError) as exc:
        result["error"] = str(exc)
    return result


def analyze_security_headers(url: str, timeout: float = 5.0) -> dict[str, object]:
    """Analyze common defensive HTTP response headers."""
    normalized = normalize_url(url)
    headers: dict[str, str] = {}
    status_code: int | None = None
    error: str | None = None

    try:
        with _request(normalized, timeout=timeout, method="HEAD") as response:
            status_code = response.status
            headers = {key.lower(): value for key, value in response.headers.items()}
    except urllib.error.HTTPError as exc:
        status_code = exc.code
        headers = {key.lower(): value for key, value in exc.headers.items()}
    except urllib.error.URLError:
        try:
            with _request(normalized, timeout=timeout, method="GET") as response:
                status_code = response.status
                headers = {key.lower(): value for key, value in response.headers.items()}
        except urllib.error.HTTPError as exc:
            status_code = exc.code
            headers = {key.lower(): value for key, value in exc.headers.items()}
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            error = str(exc)
    except (TimeoutError, OSError) as exc:
        error = str(exc)

    present = {name: headers[name] for name in SECURITY_HEADERS if name in headers}
    missing = [name for name in SECURITY_HEADERS if name not in headers]
    result: dict[str, object] = {
        "type": "http_security_headers",
        "url": normalized,
        "status_code": status_code,
        "score": int((len(present) / len(SECURITY_HEADERS)) * 100),
        "present": present,
        "missing": missing,
        "recommendations": {name: SECURITY_HEADERS[name] for name in missing},
    }
    if error:
        result["error"] = error
    return result


def _parse_cert_time(value: str | None) -> str | None:
    """Parse OpenSSL certificate time strings into ISO 8601 when possible."""
    if not value:
        return None
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC).isoformat()
    except ValueError:
        return value


def _flatten_name(name_parts: tuple[tuple[tuple[str, str], ...], ...]) -> dict[str, str]:
    """Flatten certificate subject or issuer data."""
    flattened: dict[str, str] = {}
    for group in name_parts:
        for key, value in group:
            flattened[key] = value
    return flattened


def inspect_certificate(host: str, port: int = 443, timeout: float = 5.0) -> dict[str, object]:
    """Inspect the peer SSL/TLS certificate for a host."""
    target = validate_host(host)
    tls_port = validate_port(port)
    bounded_timeout = validate_timeout(timeout)
    context = ssl.create_default_context()
    result: dict[str, object] = {"type": "ssl_certificate", "target": target, "port": tls_port, "valid": False}

    try:
        with socket.create_connection((target, tls_port), timeout=bounded_timeout) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=target) as tls_sock:
                cert: dict[str, Any] = tls_sock.getpeercert()
                cipher = tls_sock.cipher()
                protocol = tls_sock.version()
    except (ssl.SSLError, OSError, TimeoutError, socket.timeout) as exc:
        result["error"] = str(exc)
        return result

    not_after = _parse_cert_time(cert.get("notAfter"))
    days_remaining = None
    if not_after:
        try:
            days_remaining = (datetime.fromisoformat(not_after) - datetime.now(UTC)).days
        except ValueError:
            pass

    result.update(
        {
            "valid": True,
            "subject": _flatten_name(cert.get("subject", ())),
            "issuer": _flatten_name(cert.get("issuer", ())),
            "serial_number": cert.get("serialNumber"),
            "not_before": _parse_cert_time(cert.get("notBefore")),
            "not_after": not_after,
            "days_remaining": days_remaining,
            "subject_alt_names": [value for key, value in cert.get("subjectAltName", []) if key == "DNS"],
            "protocol": protocol,
            "cipher": cipher[0] if cipher else None,
        }
    )
    return result


def _run_command(args: list[str], timeout: int) -> dict[str, object]:
    """Run a bounded platform command and return captured output."""
    if timeout <= 0:
        raise ValueError("Timeout must be greater than zero.")
    try:
        completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
        return {
            "command": " ".join(args),
            "exit_code": completed.returncode,
            "stdout": completed.stdout.strip(),
            "stderr": completed.stderr.strip(),
        }
    except FileNotFoundError as exc:
        return {"command": " ".join(args), "exit_code": None, "error": str(exc)}
    except subprocess.TimeoutExpired:
        return {"command": " ".join(args), "exit_code": None, "error": "Command timed out."}


def ping_host(host: str, count: int = 4, timeout: int = 4) -> dict[str, object]:
    """Ping a host using the platform ping utility."""
    target = validate_host(host)
    if not 1 <= count <= 20:
        raise ValueError("Ping count must be between 1 and 20.")
    if platform.system().lower() == "windows":
        command = ["ping", "-n", str(count), "-w", str(timeout * 1000), target]
    else:
        command = ["ping", "-c", str(count), "-W", str(timeout), target]
    result = _run_command(command, timeout=max(timeout * count + 2, 5))
    result.update({"type": "ping", "target": target})
    return result


def traceroute(host: str, timeout: int = 30) -> dict[str, object]:
    """Run traceroute or tracert depending on the operating system."""
    target = validate_host(host)
    command = ["tracert", target] if platform.system().lower() == "windows" else ["traceroute", target]
    result = _run_command(command, timeout=timeout)
    result.update({"type": "traceroute", "target": target})
    return result


def get_local_network_info() -> dict[str, object]:
    """Return basic local hostname and address information."""
    hostname = socket.gethostname()
    addresses: set[str] = set()
    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(hostname, None):
            if family in (socket.AF_INET, socket.AF_INET6):
                addresses.add(str(sockaddr[0]))
    except socket.gaierror:
        pass
    return {
        "type": "local_network_info",
        "hostname": hostname,
        "platform": platform.platform(),
        "addresses": sorted(addresses),
    }


def get_public_ip_info(timeout: float = 5.0) -> dict[str, object]:
    """Retrieve public IP information from a public diagnostic endpoint."""
    validate_timeout(timeout)
    url = "https://api64.ipify.org?format=json"
    request = urllib.request.Request(url, headers={"User-Agent": "NetScope/1.0"})
    result: dict[str, object] = {"type": "public_ip_info", "provider": url, "ip": None}
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
        result["ip"] = payload.get("ip")
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        result["error"] = str(exc)
    return result


def subnet_calculator(cidr: str) -> dict[str, object]:
    """Calculate common details for an IPv4 or IPv6 subnet."""
    cleaned = cidr.strip()
    if not cleaned:
        raise ValueError("CIDR value cannot be empty.")
    try:
        network = ipaddress.ip_network(cleaned, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid CIDR network: {cleaned}") from exc

    total = network.num_addresses
    usable = total
    first_host = str(network.network_address)
    last_host = str(network.broadcast_address)
    if network.version == 4 and network.prefixlen <= 30:
        usable = max(total - 2, 0)
        first_host = str(network.network_address + 1)
        last_host = str(network.broadcast_address - 1)

    return {
        "type": "subnet_calculation",
        "input": cleaned,
        "network": str(network.network_address),
        "cidr": str(network),
        "version": f"IPv{network.version}",
        "netmask": str(network.netmask),
        "broadcast": str(network.broadcast_address),
        "prefix_length": network.prefixlen,
        "total_addresses": total,
        "usable_hosts": usable,
        "first_host": first_host,
        "last_host": last_host,
        "is_private": network.is_private,
    }


def _to_text(data: Any, indent: int = 0) -> str:
    """Convert nested data into readable plain text."""
    prefix = " " * indent
    if isinstance(data, dict):
        lines: list[str] = []
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                lines.append(f"{prefix}{key}:")
                lines.append(_to_text(value, indent + 2))
            else:
                lines.append(f"{prefix}{key}: {value}")
        return "\n".join(lines)
    if isinstance(data, list):
        return "\n".join(f"{prefix}- {_to_text(item, indent + 2).lstrip()}" for item in data)
    return f"{prefix}{data}"


def export_results(data: dict[str, Any], output_path: Path, export_format: str = "json") -> Path:
    """Export command results as JSON or plain text."""
    destination = Path(output_path)
    if export_format not in {"json", "txt"}:
        raise ValueError("Export format must be 'json' or 'txt'.")
    if destination.exists() and destination.is_dir():
        raise ValueError("Output path points to a directory.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if export_format == "json":
        destination.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    else:
        destination.write_text(_to_text(data), encoding="utf-8")
    return destination


def add_global_options(parser: argparse.ArgumentParser, *, suppress_defaults: bool = False) -> None:
    """Add global CLI options to a parser or subparser."""
    flag_default = argparse.SUPPRESS if suppress_defaults else False
    value_default = argparse.SUPPRESS if suppress_defaults else None
    parser.add_argument("-v", "--verbose", action="store_true", default=flag_default, help="Show extra details.")
    parser.add_argument("-q", "--quiet", action="store_true", default=flag_default, help="Only print essential output.")
    parser.add_argument("--no-color", action="store_true", default=flag_default, help="Disable colored CLI output.")
    parser.add_argument("-o", "--output", type=Path, default=value_default, help="Export results to a file.")
    parser.add_argument(
        "--format",
        choices=("json", "txt"),
        default=argparse.SUPPRESS if suppress_defaults else "json",
        help="Export format when --output is used.",
    )


def build_parser() -> argparse.ArgumentParser:
    """Create and configure the CLI parser."""
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Network diagnostics and defensive security toolkit.",
    )
    add_global_options(parser)
    global_parent = argparse.ArgumentParser(add_help=False)
    add_global_options(global_parent, suppress_defaults=True)
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", parents=[global_parent], help="Scan TCP ports on a host.")
    scan.add_argument("target", help="Hostname or IP address to scan.")
    scan.add_argument(
        "-p",
        "--ports",
        default="21,22,25,53,80,110,143,443,465,587,993,995,3306,5432,6379,8080,8443",
        help="Ports to scan, for example: 22,80,443 or 1-1024.",
    )
    scan.add_argument("--timeout", type=float, default=1.0, help="Connection timeout in seconds.")
    scan.add_argument("--no-banners", action="store_true", help="Skip banner grabbing.")

    banner = subparsers.add_parser("banner", parents=[global_parent], help="Grab a TCP service banner.")
    banner.add_argument("target", help="Hostname or IP address.")
    banner.add_argument("port", type=int, help="TCP port.")
    banner.add_argument("--timeout", type=float, default=2.0, help="Connection timeout in seconds.")

    dns = subparsers.add_parser("dns", parents=[global_parent], help="Resolve DNS records for a hostname.")
    dns.add_argument("target", help="Hostname to resolve.")

    rdns = subparsers.add_parser("rdns", parents=[global_parent], help="Perform reverse DNS lookup.")
    rdns.add_argument("address", help="IP address to resolve.")

    http = subparsers.add_parser("http", parents=[global_parent], help="Check HTTP or HTTPS status.")
    http.add_argument("url", help="URL or hostname.")
    http.add_argument("--timeout", type=float, default=5.0, help="Request timeout in seconds.")

    headers = subparsers.add_parser("headers", parents=[global_parent], help="Analyze HTTP security headers.")
    headers.add_argument("url", help="URL or hostname.")
    headers.add_argument("--timeout", type=float, default=5.0, help="Request timeout in seconds.")

    ssl_parser = subparsers.add_parser("ssl", parents=[global_parent], help="Inspect an SSL/TLS certificate.")
    ssl_parser.add_argument("target", help="Hostname to inspect.")
    ssl_parser.add_argument("--port", type=int, default=443, help="TLS port.")
    ssl_parser.add_argument("--timeout", type=float, default=5.0, help="Connection timeout in seconds.")

    ping = subparsers.add_parser("ping", parents=[global_parent], help="Ping a host.")
    ping.add_argument("target", help="Hostname or IP address.")
    ping.add_argument("-c", "--count", type=int, default=4, help="Number of echo requests.")
    ping.add_argument("--timeout", type=int, default=4, help="Timeout in seconds.")

    trace = subparsers.add_parser("trace", parents=[global_parent], help="Run traceroute to a host.")
    trace.add_argument("target", help="Hostname or IP address.")
    trace.add_argument("--timeout", type=int, default=30, help="Overall timeout in seconds.")

    subparsers.add_parser("local", parents=[global_parent], help="Show local network information.")
    subparsers.add_parser("public-ip", parents=[global_parent], help="Show public IP information.")

    subnet = subparsers.add_parser("subnet", parents=[global_parent], help="Calculate subnet details.")
    subnet.add_argument("cidr", help="CIDR network, for example 192.168.1.0/24.")
    return parser


def print_result(result: dict[str, Any], logger: CliLogger) -> None:
    """Print command results in a readable way."""
    if logger.quiet:
        logger.raw(str(result.get("status", result.get("type", "ok"))))
        return
    logger.section(str(result.get("type", "result")).replace("_", " ").title())
    for key, value in result.items():
        if key == "type":
            continue
        if isinstance(value, list):
            logger.item(key)
            for entry in value or ["none"]:
                logger.raw(f"  - {entry}")
        elif isinstance(value, dict):
            logger.item(key)
            for subkey, subvalue in value.items():
                logger.raw(f"  - {subkey}: {subvalue}")
            if not value:
                logger.raw("  - none")
        else:
            logger.item(key, value)


def run_command(args: argparse.Namespace) -> dict[str, Any]:
    """Dispatch parsed arguments to the selected command implementation."""
    if args.command == "scan":
        return scan_tcp_ports(
            args.target,
            ports=parse_ports(args.ports),
            timeout=args.timeout,
            grab_banners=not args.no_banners,
            verbose=args.verbose,
        )
    if args.command == "banner":
        return banner_grab(args.target, args.port, timeout=args.timeout)
    if args.command == "dns":
        return dns_lookup(args.target)
    if args.command == "rdns":
        return reverse_dns_lookup(args.address)
    if args.command == "http":
        return check_http_status(args.url, timeout=args.timeout)
    if args.command == "headers":
        return analyze_security_headers(args.url, timeout=args.timeout)
    if args.command == "ssl":
        return inspect_certificate(args.target, port=args.port, timeout=args.timeout)
    if args.command == "ping":
        return ping_host(args.target, count=args.count, timeout=args.timeout)
    if args.command == "trace":
        return traceroute(args.target, timeout=args.timeout)
    if args.command == "local":
        return get_local_network_info()
    if args.command == "public-ip":
        return get_public_ip_info()
    if args.command == "subnet":
        return subnet_calculator(args.cidr)
    raise ValueError(f"Unsupported command: {args.command}")


def main(argv: list[str] | None = None) -> int:
    """Run the NetScope CLI."""
    parser = build_parser()
    if argv is None and len(sys.argv) == 1:
        parser.print_help()
        if platform.system().lower() == "windows":
            input("\nPress Enter to exit...")
        return 0

    args = parser.parse_args(argv)
    logger = CliLogger(Colors(enabled=not args.no_color), verbose=args.verbose, quiet=args.quiet)
    try:
        result = run_command(args)
        print_result(result, logger)
        if args.output:
            export_results(result, args.output, args.format)
            logger.success(f"Exported results to {args.output}")
        return 0
    except KeyboardInterrupt:
        logger.error("Interrupted by user.")
        return 130
    except Exception as exc:  
        logger.error(str(exc))
        if args.verbose:
            raise
        return 1


if __name__ == "__main__":
    sys.exit(main())
