# XLS2RECON — DNS Dumpster Recon Extractor
`dnsdumpster-recon-extract.py` turns a **Domain Profiler** workbook (for example, one exported from
[DNSdumpster](https://dnsdumpster.com/)) into clean, ready-to-use recon artifacts.
It reads an `.xlsx` / `.xls` spreadsheet, pulls out DNS and summary data, and writes one CSV (or TXT)
file per artifact type — subdomains, e-mails, IPs, MX/NS records, reverse DNS, netblocks, banners,
ASNs, countries, and an all-in-one combined file.
Reading `.xlsx` files uses **only the Python standard library** (`zipfile` + `xml.etree`). No external
dependencies are required for the normal case. Legacy `.xls` input needs the optional `xlrd` package.
---
## Features
- 📦 Zero dependencies for `.xlsx` input (standard library only)
- 🔍 Automatically detects the target domain and the DNS table inside the workbook
- 🗂️ Exports 12 artifact categories, each to its own file
- 📄 CSV and/or TXT output, with configurable delimiters and headers
- 🧹 Deduplicates values, cleans MX priorities and trailing dots, flattens multi-line cells
- 🛡️ Safe options: `--dry-run`, `--no-overwrite`, `--sort`
- 🎨 Optional ASCII banner with color support
---
## Screenshots
**DNS Dumpster domain overview — the source of the Domain Profiler workbook:**
![DNS Dumpster domain overview](<dns dumpster.png>)
**Example scan / extracted output:**
![Example scan output](<scan example.png>)
---
## Installation
```bash
# Clone / download this folder, then just run the script with Python 3.8+
python3 --version
# Optional: only needed if you want to read legacy .xls files
pip install -r requirements.txt
```
No installation step is needed for `.xlsx` files — copy `dnsdumpster-recon-extract.py` anywhere and run it.
---
## Usage
```bash
# Simplest: analyze the only spreadsheet in the current directory
python3 dnsdumpster-recon-extract.py
# Explicit input and output folder
python3 dnsdumpster-recon-extract.py report.xlsx -o ./out
# Both CSV and TXT, sorted, with a custom file prefix
python3 dnsdumpster-recon-extract.py report.xlsx -f both -b mysite -c all --sort
# Only a few categories
python3 dnsdumpster-recon-extract.py report.xlsx -c subdomains emails ips
# Preview what would be written without creating files
python3 dnsdumpster-recon-extract.py report.xlsx --dry-run
# List all available categories
python3 dnsdumpster-recon-extract.py --list-categories
```
If `INPUT` is omitted, the script looks for a single `.xlsx`, `.xls`, or `.xlsm` file in the
current directory. If there are several, you must specify which one to use.
---
## Command-line options
| Option | Description |
| --- | --- |
| `INPUT` | Path to the `.xlsx` / `.xls` workbook (optional; see auto-detection above) |
| `-o, --output-dir DIR` | Output directory (default: `.`) |
| `-b, --base-name NAME` | Prefix for output files (default: detected domain with dashes, e.g. `ucd-ac-ma`) |
| `-f, --format {csv,txt,both}` | Output format (default: `csv`) |
| `-c, --categories NAME ...` | Categories to export (default: all). Use `all` for everything. |
| `--delimiter CHAR` | CSV field delimiter (default: `,`) |
| `--txt-separator STR` | Separator for multi-column TXT rows (default: ` \| `) |
| `--sort` | Sort rows inside each output file |
| `--no-header` | Omit the header row / column names |
| `--no-overwrite` | Skip files that already exist instead of replacing them |
| `--dry-run` | Analyze and report without writing files |
| `--list-categories` | List available categories and exit |
| `--no-banner` | Do not print the banner |
| `--no-color` | Disable ANSI colors in the banner |
| `-v, --verbose` | Show per-sheet parsing details |
| `--version` | Print the version and exit |
---
## Output categories
Use `--list-categories` to print these at any time.
| Category | Description |
| --- | --- |
| `subdomains` | Host names belonging to the target domain |
| `emails` | E-mail addresses found anywhere in the workbook |
| `ips` | Unique IP addresses from the DNS records |
| `hosts` | Full DNS host records (all columns) |
| `mx` | Mail exchanger (MX) records |
| `ns` | Name server (NS) records |
| `reverse-dns` | Records with a reverse DNS (PTR) name |
| `netblocks` | Network ranges from the summary sheet |
| `banners` | Top HTTP server banners |
| `asns` | Top autonomous systems |
| `countries` | Top countries |
| `all-data` | Every finding combined into a single flat file |
Output files are named `<base-name>-<category>.<ext>`, for example:
```
example-subdomains.csv
example-emails.csv
example-ips.csv
example-hosts.csv
example-all-data.csv
```
---
## Input format
The script expects a Domain Profiler workbook containing:
1. A **DNS records table** with a header row that includes `Host` and `IP` (other recognized columns:
   `Type`, `Reverse DNS`, `Netblock Owner`, `HTTP Services`, `Remote Services`).
2. Optionally, summary sections titled `Top N ...` (e.g. "Top 10 Banners", "Top 10 ASNs",
   "Top 10 Countries") used to build the `netblocks`, `banners`, `asns`, and `countries` categories.
E-mails are extracted by scanning every cell of every sheet with a regular expression, so they do not
depend on a specific layout.
> **Tip:** For best results, save legacy `.xls` files as `.xlsx` before processing.
---
## Requirements
- Python 3.8 or newer
- `xlrd` — **optional**, only for reading legacy binary `.xls` files (see `requirements.txt`)
---
## Authorized use
This tool is intended for **authorized security testing and defensive reconnaissance only**. Make sure
you have permission to analyze the target domain and to handle any data contained in the workbook.
---
## License
Provided as-is, without warranty. Use at your own risk.
