<div align="center">

# Cybersecurity Ai MCP

**Cybersecurity AI MCP Server - Security Intelligence Tools**

[![PyPI](https://img.shields.io/pypi/v/meok-cybersecurity-ai-mcp)](https://pypi.org/project/meok-cybersecurity-ai-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-MCP_Server-purple)](https://meok.ai)

</div>

## Overview

Cybersecurity AI MCP Server - Security Intelligence Tools
Built by MEOK AI Labs | https://meok.ai

Vulnerability classification, CVE lookup, security header checking,
password strength analysis, and threat model generation.

## Tools

| Tool | Description |
|------|-------------|
| `classify_vulnerability` | Classify a vulnerability by type, severity, and OWASP category. |
| `lookup_cve` | Look up CVE details from the vulnerability database. |
| `check_security_headers` | Analyze HTTP security headers against best practices. |
| `analyze_password_strength` | Analyze password strength and provide improvement suggestions. |
| `generate_threat_model` | Generate a STRIDE-based threat model for a system. |

## Installation

```bash
pip install meok-cybersecurity-ai-mcp
```

## Usage with Claude Desktop

Add to your Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "cybersecurity-ai": {
      "command": "python",
      "args": ["-m", "meok_cybersecurity_ai_mcp.server"]
    }
  }
}
```

## Usage with FastMCP

```python
from mcp.server.fastmcp import FastMCP

# This server exposes 5 tool(s) via MCP
# See server.py for full implementation
```

## License

MIT © [MEOK AI Labs](https://meok.ai)
