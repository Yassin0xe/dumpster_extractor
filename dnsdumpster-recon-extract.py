#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dnsdumpster_recon_extract.py

Extract recon-style artifacts from a "Domain Profiler" XLS/XLSX workbook and
export one CSV (or TXT) file per artifact type, for example:

    ucd-ac-ma-subdomains.csv
    ucd-ac-ma-emails.csv
    ucd-ac-ma-ips.csv
    ucd-ac-ma-hosts.csv
    ...

The XLSX reader uses only the Python standard library (zipfile + ElementTree).
Legacy binary .xls files require the optional `xlrd` package.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import re
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple
import xml.etree.ElementTree as ET

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
NS_R = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"
NS_PKG = "{http://schemas.openxmlformats.org/package/2006/relationships}"

CATEGORIES: Tuple[str, ...] = (
    "subdomains",
    "emails",
    "ips",
    "hosts",
    "mx",
    "ns",
    "reverse-dns",
    "netblocks",
    "banners",
    "asns",
    "countries",
    "all-data",
)

DESCRIPTIONS: Dict[str, str] = {
    "subdomains": "Host names belonging to the target domain",
    "emails": "E-mail addresses found anywhere in the workbook",
    "ips": "Unique IP addresses from the DNS records",
    "hosts": "Full DNS host records (all columns)",
    "mx": "Mail exchanger (MX) records",
    "ns": "Name server (NS) records",
    "reverse-dns": "Records with a reverse DNS (PTR) name",
    "netblocks": "Network ranges from the summary sheet",
    "banners": "Top HTTP server banners",
    "asns": "Top autonomous systems",
    "countries": "Top countries",
    "all-data": "Every finding combined into a single flat file",
}

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
DOMAIN_RE = re.compile(
    r"(?<![\w.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}(?![\w.-])"
)
UUID_SUFFIX_RE = re.compile(
    r"-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

TXT_RENDERERS: Dict[str, Callable[[List[str]], str]] = {
    "hosts": lambda r: f"{r[0]}:{r[1]}",
    "mx": lambda r: f"{r[1]}:{r[2]}",
    "ns": lambda r: f"{r[0]}:{r[1]}",
    "reverse-dns": lambda r: f"{r[1]} -> {r[2]}",
    "banners": lambda r: f"{r[0]} ({r[1]})",
    "asns": lambda r: f"{r[0]} ({r[1]}) {r[2]}",
    "countries": lambda r: f"{r[0]} ({r[1]})",
    "all-data": lambda r: " | ".join(value for value in r if value),
}


class ReconError(Exception):
    """User-facing extraction error."""


@dataclass
class Finding:
    name: str
    description: str
    headers: List[str]
    rows: List[List[str]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

BANNER_FONT: Dict[str, List[str]] = {
    "X": ["#   #", " # # ", "  #  ", " # # ", "#   #"],
    "L": ["#    ", "#    ", "#    ", "#    ", "#####"],
    "S": ["#####", "#    ", "#### ", "    #", "#####"],
    "2": ["#### ", "#   #", "   # ", "  #  ", "#####"],
    "R": ["#### ", "#   #", "#### ", "#  # ", "#   #"],
    "E": ["#####", "#    ", "#### ", "#    ", "#####"],
    "C": [" ####", "#    ", "#    ", "#    ", " ####"],
    "O": [" ### ", "#   #", "#   #", "#   #", " ### "],
    "N": ["#   #", "##  #", "# # #", "#  ##", "#   #"],
    " ": ["     "] * 5,
}


def render_banner(text: str = "XLS2RECON") -> List[str]:
    glyphs = [BANNER_FONT.get(ch.upper(), BANNER_FONT[" "]) for ch in text]
    art = ["".join(g[row] + " " for g in glyphs).rstrip() for row in range(5)]
    pad = 2
    inner = max(len(line) for line in art) + pad * 2
    subtitle = f" Domain Profiler workbook  ->  recon artifacts  |  v{__version__} "
    subtitle = subtitle[:inner]

    lines = ["┌" + "─" * inner + "┐"]
    lines += ["│" + " " * pad + line + " " * (inner - pad - len(line)) + "│" for line in art]
    lines.append("├" + "─" * inner + "┤")
    lines.append("│" + subtitle.center(inner) + "│")
    lines.append("└" + "─" * inner + "┘")
    return lines


def print_banner(use_color: bool = False) -> None:
    lines = render_banner()
    if use_color:
        cyan = "\033[36m"
        reset = "\033[0m"
        print("\n".join(cyan + line + reset for line in lines))
    else:
        print("\n".join(lines))
    print()


# ---------------------------------------------------------------------------
# XLSX / XLS readers (standard library only for XLSX)
# ---------------------------------------------------------------------------


def column_index(cell_ref: str) -> int:
    match = re.match(r"([A-Za-z]+)", cell_ref or "")
    if not match:
        return 1
    index = 0
    for char in match.group(1).upper():
        index = index * 26 + (ord(char) - ord("A") + 1)
    return index


def normalize_target(target: str) -> str:
    parts: List[str] = []
    for part in target.replace("\\", "/").lstrip("/").split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
        else:
            parts.append(part)
    return "/".join(parts)


def parse_sheet(xml_data: bytes, shared_strings: Sequence[str]) -> List[List[str]]:
    root = ET.fromstring(xml_data)
    rows: List[List[str]] = []

    for xml_row in root.findall(".//" + NS + "row"):
        cells: Dict[int, str] = {}
        for cell in xml_row.findall(NS + "c"):
            ref = cell.get("r", "")
            idx = column_index(ref) - 1 if ref else len(cells)
            cell_type = cell.get("t", "")
            value = ""

            if cell_type == "inlineStr":
                inline = cell.find(NS + "is")
                if inline is not None:
                    value = "".join(node.text or "" for node in inline.iter(NS + "t"))
            else:
                value_node = cell.find(NS + "v")
                raw = value_node.text if value_node is not None and value_node.text else ""
                if cell_type == "s" and raw:
                    try:
                        value = shared_strings[int(raw)]
                    except (ValueError, IndexError):
                        value = raw
                elif cell_type == "b":
                    value = "TRUE" if raw == "1" else "FALSE"
                else:
                    value = raw

            cells[idx] = (value or "").strip()
        if cells:
            rows.append([cells.get(i, "") for i in range(max(cells) + 1)])
        else:
            rows.append([])

    return rows


def read_xlsx(path: Path) -> Dict[str, List[List[str]]]:
    with zipfile.ZipFile(path) as archive:
        available = set(archive.namelist())

        shared: List[str] = []
        if "xl/sharedStrings.xml" in available:
            root = ET.fromstring(archive.read("xl/sharedStrings.xml"))
            for item in root.findall(NS + "si"):
                shared.append("".join(node.text or "" for node in item.iter(NS + "t")))

        relationships: Dict[str, str] = {}
        if "xl/_rels/workbook.xml.rels" in available:
            rel_root = ET.fromstring(archive.read("xl/_rels/workbook.xml.rels"))
            for rel in rel_root.findall(NS_PKG + "Relationship"):
                relationships[rel.get("Id", "")] = rel.get("Target", "")

        if "xl/workbook.xml" not in available:
            raise ReconError(f"'{path.name}' is a ZIP file but has no xl/workbook.xml")

        workbook = ET.fromstring(archive.read("xl/workbook.xml"))
        sheets_element = workbook.find(NS + "sheets")
        if sheets_element is None:
            raise ReconError(f"No sheets found in '{path.name}'")

        sheets: Dict[str, List[List[str]]] = {}
        for sheet in sheets_element.findall(NS + "sheet"):
            name = sheet.get("name", "Sheet")
            target = normalize_target(relationships.get(sheet.get(NS_R + "id", ""), ""))
            if not target:
                continue
            member = target if target in available else "xl/" + target
            if member not in available:
                continue
            sheets[name] = parse_sheet(archive.read(member), shared)

    if not sheets:
        raise ReconError(f"Could not read any worksheets from '{path.name}'")
    return sheets


def read_xls(path: Path) -> Dict[str, List[List[str]]]:
    try:
        import xlrd  # type: ignore
    except ImportError as exc:
        raise ReconError(
            "Legacy .xls input needs the optional 'xlrd' package "
            "(pip install xlrd). For best results, save the file as .xlsx."
        ) from exc

    try:
        book = xlrd.open_workbook(str(path))
    except Exception as exc:  # pragma: no cover - depends on xlrd
        raise ReconError(f"Could not open '{path.name}': {exc}") from exc

    sheets: Dict[str, List[List[str]]] = {}
    for sheet in book.sheets():
        rows = []
        for row_index in range(sheet.nrows):
            rows.append([str(sheet.cell_value(row_index, col)).strip() for col in range(sheet.ncols)])
        sheets[sheet.name] = rows
    return sheets


def load_workbook(path: Path) -> Dict[str, List[List[str]]]:
    if not path.is_file():
        raise ReconError(f"Input file not found: {path}")
    with path.open("rb") as handle:
        signature = handle.read(4)
    if signature[:2] == b"PK":
        return read_xlsx(path)
    if path.suffix.lower() == ".xls":
        return read_xls(path)
    raise ReconError("Unsupported file format: expected .xlsx (or legacy .xls with xlrd)")


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


def clean_host(value: str) -> str:
    """Strip an MX priority prefix and a trailing dot from a host name."""
    return re.sub(r"^\d+\s+", "", (value or "").strip()).rstrip(".").strip()


def flatten_ws(value: str) -> str:
    """Make multi-line spreadsheet cells safe for one-line CSV/TXT records."""
    return re.sub(r"\s*[\r\n]+\s*", "; ", (value or "").strip())


def unique(values: Iterable[str], key: Optional[Callable[[str], str]] = None) -> List[str]:
    seen = set()
    result: List[str] = []
    for value in values:
        marker = key(value) if key else value
        if marker in seen:
            continue
        seen.add(marker)
        result.append(value)
    return result


def valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def detect_domain(sheets: Dict[str, List[List[str]]], path: Path) -> str:
    for rows in sheets.values():
        for row in rows:
            for cell in row:
                match = re.search(r"Domain Profiler(?: Summary)?\s+(?:for\s+)?([^\s]+)", cell, re.I)
                if match:
                    candidate = match.group(1).strip().rstrip(".,;:")
                    if DOMAIN_RE.fullmatch(candidate):
                        return candidate

    fallback = UUID_SUFFIX_RE.sub("", path.stem)
    match = DOMAIN_RE.search(fallback)
    if match:
        return match.group(0)
    return fallback.replace(" ", "-")


def find_dns_records(sheets: Dict[str, List[List[str]]]) -> List[Dict[str, str]]:
    """Locate the DNS table by its header row and return normalized records."""
    aliases = {
        "host": "host",
        "ip": "ip",
        "type": "type",
        "reverse dns": "reverse_dns",
        "netblock owner": "netblock_owner",
        "http services": "http_services",
        "remote services": "remote_services",
    }

    for rows in sheets.values():
        for row_index, row in enumerate(rows[:10]):
            lowered = [cell.strip().lower() for cell in row]
            if "host" not in lowered or "ip" not in lowered:
                continue

            columns = {aliases[name]: pos for pos, name in enumerate(lowered) if name in aliases}
            records: List[Dict[str, str]] = []
            for data in rows[row_index + 1 :]:
                def get(field_name: str) -> str:
                    pos = columns.get(field_name)
                    return data[pos].strip() if pos is not None and pos < len(data) else ""

                host = clean_host(get("host"))
                ip = get("ip")
                if not host and not ip:
                    continue
                priority_match = re.match(r"^(\d+)\s+", get("host"))
                records.append(
                    {
                        "host": host,
                        "ip": ip,
                        "type": get("type").upper(),
                        "priority": priority_match.group(1) if priority_match else "",
                        "reverse_dns": flatten_ws(get("reverse_dns")),
                        "netblock_owner": flatten_ws(get("netblock_owner")),
                        "http_services": flatten_ws(get("http_services")),
                        "remote_services": flatten_ws(get("remote_services")),
                    }
                )
            return records
    return []


def find_summary_sections(sheets: Dict[str, List[List[str]]]) -> Dict[str, List[Dict[str, str]]]:
    sections: Dict[str, List[Dict[str, str]]] = {"banners": [], "asns": [], "countries": []}

    def classify(title: str) -> Optional[str]:
        lowered = title.lower()
        if "banner" in lowered:
            return "banners"
        if "asn" in lowered:
            return "asns"
        if "countr" in lowered:
            return "countries"
        return None

    for rows in sheets.values():
        for row_index, row in enumerate(rows):
            for cell in row:
                match = re.match(r"Top\s+\d+\s+(.+)", (cell or "").strip(), re.I)
                if not match:
                    continue
                category = classify(match.group(1))
                if not category:
                    continue

                cursor = row_index + 1
                while cursor < len(rows) and not any(rows[cursor]):
                    cursor += 1
                if cursor >= len(rows):
                    continue

                header = [re.sub(r"\s+", "_", h.strip().lower()) for h in rows[cursor]]
                cursor += 1
                while cursor < len(rows):
                    data = rows[cursor]
                    if not any(data):
                        break
                    if re.match(r"Top\s+\d+", " ".join(data), re.I):
                        break
                    if data[: len(header)] == header:
                        cursor += 1
                        continue
                    record = {
                        name: (data[index].strip() if index < len(data) else "")
                        for index, name in enumerate(header)
                    }
                    if any(record.values()):
                        sections[category].append(record)
                    cursor += 1

    return sections


# ---------------------------------------------------------------------------
# Finding construction
# ---------------------------------------------------------------------------


def build_findings(
    sheets: Dict[str, List[List[str]]], domain: str
) -> Dict[str, Finding]:
    dns = find_dns_records(sheets)
    summary = find_summary_sections(sheets)
    output: Dict[str, Finding] = {}

    # Subdomains: only host names that live under the target domain.
    suffix = "." + domain.lower()
    subdomains = unique(
        (
            record["host"]
            for record in dns
            if record["host"]
            and "." in record["host"]
            and (record["host"].lower().endswith(suffix) or record["host"].lower() == domain.lower())
        ),
        key=str.lower,
    )
    output["subdomains"] = Finding(
        "subdomains", DESCRIPTIONS["subdomains"], ["subdomain"], [[value] for value in subdomains]
    )

    # Emails: regex scan over every cell of every sheet.
    emails = unique(
        (
            match.group(0).lower()
            for rows in sheets.values()
            for row in rows
            for cell in row
            for match in EMAIL_RE.finditer(cell)
        ),
        key=str.lower,
    )
    output["emails"] = Finding(
        "emails", DESCRIPTIONS["emails"], ["email"], [[value] for value in emails]
    )

    ips = unique(record["ip"] for record in dns if valid_ip(record["ip"]))
    output["ips"] = Finding("ips", DESCRIPTIONS["ips"], ["ip"], [[value] for value in ips])

    output["hosts"] = Finding(
        "hosts",
        DESCRIPTIONS["hosts"],
        ["host", "ip", "type", "reverse_dns", "netblock_owner", "http_services", "remote_services"],
        [
            [
                record["host"],
                record["ip"],
                record["type"],
                record["reverse_dns"],
                record["netblock_owner"],
                record["http_services"],
                record["remote_services"],
            ]
            for record in dns
        ],
    )

    mx = [record for record in dns if record["type"] == "MX"]
    output["mx"] = Finding(
        "mx",
        DESCRIPTIONS["mx"],
        ["priority", "host", "ip", "reverse_dns"],
        [[r["priority"], r["host"], r["ip"], r["reverse_dns"]] for r in mx],
    )

    ns = [record for record in dns if record["type"] == "NS"]
    output["ns"] = Finding(
        "ns",
        DESCRIPTIONS["ns"],
        ["host", "ip", "reverse_dns"],
        [[r["host"], r["ip"], r["reverse_dns"]] for r in ns],
    )

    ptr = [record for record in dns if record["reverse_dns"]]
    output["reverse-dns"] = Finding(
        "reverse-dns",
        DESCRIPTIONS["reverse-dns"],
        ["host", "ip", "reverse_dns"],
        [[r["host"], r["ip"], r["reverse_dns"]] for r in ptr],
    )

    netblocks = unique(
        r.get("network_range", "") for r in summary["asns"] if r.get("network_range", "")
    )
    output["netblocks"] = Finding(
        "netblocks", DESCRIPTIONS["netblocks"], ["network_range"], [[v] for v in netblocks]
    )

    output["banners"] = Finding(
        "banners",
        DESCRIPTIONS["banners"],
        ["name", "count"],
        [[r.get("name", ""), r.get("count", "")] for r in summary["banners"]],
    )
    output["asns"] = Finding(
        "asns",
        DESCRIPTIONS["asns"],
        ["asn", "asn_name", "network_range", "count"],
        [
            [r.get("asn", ""), r.get("asn_name", ""), r.get("network_range", ""), r.get("count", "")]
            for r in summary["asns"]
        ],
    )
    output["countries"] = Finding(
        "countries",
        DESCRIPTIONS["countries"],
        ["name", "count"],
        [[r.get("name", ""), r.get("count", "")] for r in summary["countries"]],
    )

    ordered = [output[name] for name in CATEGORIES if name in output]
    width = max((len(row) for item in ordered for row in item.rows), default=1)
    combined_headers = ["category"] + [f"value_{index}" for index in range(1, width + 1)]
    combined_rows = [
        [item.name] + row + [""] * (width - len(row))
        for item in ordered
        for row in item.rows
    ]
    output["all-data"] = Finding(
        "all-data", DESCRIPTIONS["all-data"], combined_headers, combined_rows
    )

    return output


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------


def txt_line(finding: Finding, row: List[str], separator: str) -> str:
    renderer = TXT_RENDERERS.get(finding.name)
    if renderer:
        return renderer(row)
    if len(row) == 1:
        return row[0]
    return separator.join(value for value in row if value)


def write_finding(
    finding: Finding,
    output_dir: Path,
    base_name: str,
    formats: Sequence[str],
    delimiter: str,
    txt_separator: str,
    include_header: bool,
    no_overwrite: bool,
    sort_rows: bool,
) -> List[Path]:
    written: List[Path] = []
    rows = sorted(finding.rows) if sort_rows else finding.rows

    for fmt in formats:
        destination = output_dir / f"{base_name}-{finding.name}.{fmt}"
        if destination.exists() and no_overwrite:
            print(f"    [=] skipped (exists): {destination.name}")
            continue

        with destination.open("w", newline="", encoding="utf-8") as handle:
            if fmt == "csv":
                writer = csv.writer(handle, delimiter=delimiter, lineterminator="\n")
                if include_header:
                    writer.writerow(finding.headers)
                writer.writerows(rows)
            else:
                if include_header:
                    handle.write(txt_line(finding, finding.headers, txt_separator) + "\n")
                for row in rows:
                    handle.write(txt_line(finding, row, txt_separator) + "\n")
        written.append(destination)

    return written


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xlsx_recon_extract.py",
        description=(
            "Extract subdomains, e-mails, IPs, MX/NS records, banners and more from a "
            "Domain Profiler XLSX workbook into separate CSV/TXT files."
        ),
        epilog=(
            "examples:\n"
            "  python3 xlsx_recon_extract.py report.xlsx\n"
            "  python3 xlsx_recon_extract.py report.xlsx -f both -o ./out\n"
            "  python3 xlsx_recon_extract.py report.xlsx -c subdomains emails ips\n"
            "  python3 xlsx_recon_extract.py report.xlsx -b mysite -c all --sort\n"
            "  python3 xlsx_recon_extract.py --list-categories\n\n"
            "If INPUT is omitted, the only spreadsheet in the current directory is used."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("input", nargs="?", help="path to the .xlsx (or .xls) workbook")
    parser.add_argument("-o", "--output-dir", default=".", metavar="DIR", help="output directory (default: .)")
    parser.add_argument(
        "-b", "--base-name", metavar="NAME",
        help="prefix for output files (default: detected domain with dashes, e.g. ucd-ac-ma)",
    )
    parser.add_argument("-f", "--format", choices=("csv", "txt", "both"), default="csv", help="output format (default: csv)")
    parser.add_argument(
        "-c", "--categories", nargs="+", metavar="NAME",
        help="categories to export (default: all); use --list-categories to see them",
    )
    parser.add_argument("--delimiter", default=",", metavar="CHAR", help="CSV field delimiter (default: ',')")
    parser.add_argument("--txt-separator", default=" | ", metavar="STR", help="separator for multi-column TXT rows (default: ' | ')")
    parser.add_argument("--sort", action="store_true", help="sort rows inside each output file")
    parser.add_argument("--no-header", action="store_true", help="omit the header row/column names")
    parser.add_argument("--no-overwrite", action="store_true", help="do not replace existing output files")
    parser.add_argument("--dry-run", action="store_true", help="analyze and show what would be written")
    parser.add_argument("--list-categories", action="store_true", help="list available categories and exit")
    parser.add_argument("--no-banner", action="store_true", help="do not print the banner")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colors in the banner")
    parser.add_argument("-v", "--verbose", action="store_true", help="show per-sheet parsing details")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def resolve_input(supplied: Optional[str]) -> Path:
    if supplied:
        return Path(supplied).expanduser()

    candidates = sorted(
        path
        for path in Path.cwd().iterdir()
        if path.is_file()
        and path.suffix.lower() in (".xlsx", ".xls", ".xlsm")
        and not path.name.startswith("~$")
    )
    if not candidates:
        raise ReconError("No spreadsheet found in the current directory. Provide INPUT explicitly.")
    if len(candidates) > 1:
        listing = "\n  ".join(path.name for path in candidates)
        raise ReconError(
            "Several spreadsheets found; choose one with INPUT:\n  " + listing
        )
    return candidates[0]


def normalize_category(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    use_color = sys.stdout.isatty() and not args.no_color and not args.no_banner
    if not args.no_banner:
        print_banner(use_color)

    if args.list_categories:
        print(f"{'CATEGORY':<14} DESCRIPTION")
        print("-" * 72)
        for name in CATEGORIES:
            print(f"{name:<14} {DESCRIPTIONS[name]}")
        print("\nUse '-c all' to export every category.")
        return 0

    if len(args.delimiter) != 1:
        parser.error("--delimiter must be exactly one character")

    try:
        path = resolve_input(args.input)
        print(f"[*] Workbook   : {path}")
        sheets = load_workbook(path)

        if args.verbose:
            for name, rows in sheets.items():
                print(f"[*] Sheet      : {name!r} ({len(rows)} rows)")

        domain = detect_domain(sheets, path)
        base_name = args.base_name or domain.replace(".", "-")
        print(f"[*] Domain     : {domain}")
        print(f"[*] Base name  : {base_name}")

        findings = build_findings(sheets, domain)

        if args.categories:
            requested: List[str] = []
            for token in args.categories:
                normalized = normalize_category(token)
                if normalized == "all":
                    requested.extend(CATEGORIES)
                elif normalized in CATEGORIES:
                    requested.append(normalized)
                else:
                    parser.error(f"unknown category '{token}' (see --list-categories)")
            selected = list(dict.fromkeys(requested))
        else:
            selected = list(CATEGORIES)

        formats = ("csv", "txt") if args.format == "both" else (args.format,)
        output_dir = Path(args.output_dir).expanduser()

        print(f"[*] Categories : {', '.join(selected)}")
        print(f"[*] Format     : {'+'.join(formats)}")
        print(f"[*] Output dir : {output_dir}\n")

        if not args.dry_run:
            output_dir.mkdir(parents=True, exist_ok=True)

        header = f"{'CATEGORY':<14} {'RECORDS':>7}  OUTPUT"
        print(header)
        print("-" * max(len(header), 60))

        total = 0
        for name in selected:
            finding = findings[name]
            files = ", ".join(f"{base_name}-{name}.{fmt}" for fmt in formats)
            print(f"{name:<14} {len(finding.rows):>7}  {files}")
            total += len(finding.rows)
            if not args.dry_run:
                write_finding(
                    finding,
                    output_dir,
                    base_name,
                    formats,
                    args.delimiter,
                    args.txt_separator,
                    not args.no_header,
                    args.no_overwrite,
                    args.sort,
                )

        print("-" * max(len(header), 60))
        print(f"[+] {total} record(s) across {len(selected)} categorie(s).")
        if args.dry_run:
            print("[+] Dry run complete - no files were written.")
        else:
            print(f"[+] Done. Files written to {output_dir.resolve()}")
        return 0

    except ReconError as exc:
        print(f"[-] Error: {exc}", file=sys.stderr)
        return 1
    except (OSError, zipfile.BadZipFile, ET.ParseError) as exc:
        print(f"[-] Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
