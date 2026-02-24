# 🌀 SSX — Shortscan Engine

> This directory contains the underlying scan engine. For full documentation and CLI reference, see the **[root README](../README.md)**.

## Quick Reference

```bash
# Basic scan
ssx http://target.com/

# Vulnerability check only (no enumeration)
ssx -V http://target.com/

# Bulk scan from URL list
ssx @targets.txt

# JSON output
ssx -o json -O results.json http://target.com/

# Custom headers + increased concurrency
ssx -c 50 -H "Authorization: Bearer TOKEN" http://target.com/
```

## Utility: `shortutil`

```bash
# Generate a checksum for a filename
shortutil checksum index.html

# Build a rainbow table from a wordlist
shortutil wordlist wordlist.txt > rainbow.txt

# Use the rainbow table with ssx
ssx -r rainbow.txt http://target.com/
```

## Credits

- [Soroush Dalili](https://soroush.secproject.com/) — original IIS tilde research
- [bitquark](https://github.com/bitquark) — original engine
- [Serdar715](https://github.com/Serdar715) — SSX v2 refactor
