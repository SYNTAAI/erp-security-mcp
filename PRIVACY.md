# Privacy Policy

**SyntaAI ERP Security MCP Server**
*Last updated: February 26, 2026*

## Overview

SyntaAI ERP Security ("the Service") is a Model Context Protocol (MCP) server that enables AI assistants to interact with SAP® ERP systems for security analysis and compliance reporting. This privacy policy describes how data is handled when using the Service.

## Data Collection

### What We Access
When you connect the MCP server to your SAP system, the Service accesses:
- SAP user account information (usernames, roles, profiles, login history)
- System security parameters and configuration
- Security audit log entries
- RFC connection configurations
- Transport request logs
- Authorization trace data

### What We Do NOT Collect
- **No personal data is stored** — All queries are pass-through to your SAP system
- **No credentials are stored** — OAuth 2.0 tokens are managed per-session
- **No analytics or tracking** — We do not use cookies, pixels, or tracking scripts
- **No data is shared with third parties** — Your SAP data is never transmitted to any party other than the authenticated AI assistant session

## Data Processing

The MCP server acts as a **stateless proxy** between the AI assistant (Claude) and your SAP system:

1. Claude sends a tool request to the MCP server
2. The MCP server authenticates with your SAP system via OAuth 2.0
3. The MCP server retrieves the requested data via SAP OData APIs
4. The data is returned to Claude for analysis
5. **No data is cached, logged, or persisted on the MCP server**

## Authentication

- Authentication uses **OAuth 2.0** with your SAP system's authorization server
- Access tokens are scoped to read-only operations by default
- Token refresh is handled automatically; tokens are not stored persistently
- You can revoke access at any time through your SAP system (transaction SOAUTH2)

## Data Residency

- **On-premise deployment:** When deployed within your infrastructure, all data remains within your network. No data leaves your environment.
- **Cloud-hosted (mcp.syntaai.com):** Data passes through the MCP server hosted on AWS (Mumbai region, ap-south-1) but is not stored or logged.

## Security Measures

- All communications use HTTPS/TLS encryption
- OAuth 2.0 for authentication (no static credentials)
- Safety annotations on all tools (readOnlyHint, destructiveHint)
- The `lock_unlock_user` tool is the only write operation and is clearly marked as destructive
- No server-side logging of SAP data content

## Your Rights

You have the right to:
- **Disconnect** — Remove the MCP connector from Claude at any time
- **Revoke access** — Revoke OAuth tokens in your SAP system
- **Audit** — Review which tools were invoked via SAP security audit log (SM20)
- **Delete** — No data is stored, so there is nothing to delete on our side

## Children's Privacy

This Service is intended for enterprise use by authorized SAP administrators. It is not directed at children under 13 (or applicable age in your jurisdiction).

## Changes to This Policy

We may update this privacy policy from time to time. Changes will be posted to this repository with an updated "Last updated" date.

## Contact

For privacy-related questions or concerns:

- **Email:** contact@syntaai.com
- **Company:** SyntaAI
- **Website:** [www.syntaai.com](https://www.syntaai.com)

---

*Compatible with SAP® ERP and SAP® S/4HANA®. SAP is a registered trademark of SAP SE.*
