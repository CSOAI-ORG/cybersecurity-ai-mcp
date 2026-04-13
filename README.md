# Cybersecurity AI MCP Server

**Security Intelligence Tools**

Built by [MEOK AI Labs](https://meok.ai)

---

An MCP server for security professionals. Classify vulnerabilities with OWASP mapping, look up CVE details, audit HTTP security headers, analyze password strength with entropy and crack-time estimates, and generate STRIDE-based threat models.

## Tools

| Tool | Description |
|------|-------------|
| `classify_vulnerability` | Classify vulnerabilities with OWASP category, CWE, and CVSS estimation |
| `lookup_cve` | Look up CVE details including affected versions and remediation |
| `check_security_headers` | Audit HTTP security headers against best practices with grading |
| `analyze_password_strength` | Password analysis with entropy, crack-time, and pattern detection |
| `generate_threat_model` | Generate STRIDE-based threat models with risk scoring |

## Quick Start

```bash
pip install cybersecurity-ai-mcp
```

### Claude Desktop

```json
{
  "mcpServers": {
    "cybersecurity-ai": {
      "command": "python",
      "args": ["-m", "server"],
      "cwd": "/path/to/cybersecurity-ai-mcp"
    }
  }
}
```

### Direct Usage

```bash
python server.py
```

## Rate Limits

| Tier | Requests/Hour |
|------|--------------|
| Free | 60 |
| Pro | 5,000 |

## License

MIT - see [LICENSE](LICENSE)

---

*Part of the MEOK AI Labs MCP Marketplace*
