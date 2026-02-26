# SyntaAI ERP Security MCP Server

AI-powered ERP security analysis & compliance for SAP® systems via the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/).

**20 tools** for vulnerability scanning, user management, compliance reporting, and role analysis — accessible directly from Claude.

[![MCP](https://img.shields.io/badge/MCP-Compatible-blue)](https://modelcontextprotocol.io/)
[![Transport](https://img.shields.io/badge/Transport-Streamable%20HTTP-green)]()
[![Auth](https://img.shields.io/badge/Auth-OAuth%202.0-orange)]()
[![License](https://img.shields.io/badge/License-Apache%202.0-red)](LICENSE)

## Overview

SyntaAI ERP Security connects Claude to your SAP® system, enabling natural language security analysis. Ask Claude to find vulnerabilities, check compliance, review user access, and generate reports — all through conversation.

**Endpoint:** `https://mcp.syntaai.com/mcp`

### Why This Exists

- SAP processes **77% of the world's transactional revenue**
- **64% of SAP customers** lack security tools due to cost barriers
- Zero SAP security coverage existed in the MCP ecosystem — until now

## Tools (20)

### User Management (5)
| Tool | Description |
|------|-------------|
| `list_users` | List all SAP user accounts with filtering by status and type |
| `get_user_details` | Get detailed user information including roles, profiles, login history |
| `lock_unlock_user` | Lock or unlock a SAP user account |
| `list_user_roles` | List all roles and profiles assigned to a user |
| `find_inactive_users` | Find users who haven't logged in for N days |

### Security Analysis (5)
| Tool | Description |
|------|-------------|
| `get_security_parameters` | Get SAP security profile parameters vs. best practices |
| `check_critical_authorizations` | Find users with SAP_ALL, SAP_NEW, and dangerous profiles |
| `get_audit_log` | Retrieve security audit log entries for monitoring |
| `check_default_passwords` | Check for accounts with default/initial passwords |
| `get_rfc_connections` | Analyze RFC destinations for stored credentials |

### Compliance & Audit (5)
| Tool | Description |
|------|-------------|
| `run_sod_check` | Check for Segregation of Duties violations |
| `generate_compliance_report` | Generate SOX, GDPR, ISO 27001, or NIST assessment |
| `list_privileged_users` | List all users with elevated privileges |
| `check_password_policy` | Analyze password policy against best practices |
| `get_transport_log` | Get transport request log for change management audit |

### Role & Authorization (5)
| Tool | Description |
|------|-------------|
| `list_roles` | List all security roles with optional search |
| `get_role_details` | Get role details including authorizations and assigned users |
| `compare_user_access` | Compare access rights between two users |
| `find_users_with_role` | Find all users with a specific role |
| `get_authorization_trace` | Get authorization check trace entries |

## Resources (5)

| Resource | Description |
|----------|-------------|
| `sap://system/info` | SAP system information |
| `sap://security/overview` | Security posture overview with risk summary |
| `sap://compliance/frameworks` | Supported compliance frameworks |
| `sap://security/controls` | Security controls catalog (1,400+ checks) |
| `sap://users/summary` | User account statistics |

## Prompts (8)

| Prompt | Description |
|--------|-------------|
| `security_audit` | Run a full security audit |
| `sox_compliance_check` | SOX compliance assessment |
| `user_access_review` | Periodic user access review |
| `sod_analysis` | Segregation of Duties deep dive |
| `inactive_user_cleanup` | Inactive user cleanup plan |
| `rfc_security_review` | RFC connection security review |
| `privileged_access_review` | Privileged access review |
| `password_policy_assessment` | Password policy strength assessment |

## Quick Start

### Connect via Claude.ai

1. Go to **Settings → Connectors → Add Connector**
2. Enter URL: `https://mcp.syntaai.com/mcp`
3. Authenticate with your SAP system credentials (OAuth 2.0)
4. Start asking Claude about your SAP security

### Example Prompts

```
"Are there any users with SAP_ALL profile?"

"Check for segregation of duties violations"

"Find all users who haven't logged in for 90 days"

"Generate a SOX compliance report"

"Show me RFC connections that store credentials"

"Compare access between J.SMITH and M.JONES"

"Run a full security audit and prioritize findings"
```

## Architecture

```
Claude ←→ MCP (Streamable HTTP) ←→ SyntaAI Server ←→ SAP OData APIs
                                         |
                                    OAuth 2.0
                                    (SAP Auth)
```

- **Transport:** Streamable HTTP (MCP spec 2025-03-26)
- **Authentication:** OAuth 2.0 via SAP authorization server
- **SAP Connectivity:** OData REST APIs (no proprietary dependencies)
- **Deployment:** 100% on-premise compatible

## Requirements

- SAP system with OData services enabled (S/4HANA, ECC 7.4+)
- OAuth 2.0 configured in SAP (transaction SOAUTH2)
- Read-only access for security scanning tools
- Network connectivity between MCP server and SAP system

## Local Development

```bash
# Clone
git clone https://github.com/SYNTAAI/erp-security-mcp.git
cd erp-security-mcp

# Setup
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run with demo data
python server.py

# Server starts at http://localhost:8000/mcp
```

## Configuration

Set environment variables for SAP connectivity:

```bash
SAP_ODATA_BASE_URL=https://your-sap-system.com/sap/opu/odata/sap
SAP_OAUTH_TOKEN_URL=https://your-sap-system.com/sap/bc/sec/oauth2/token
SAP_OAUTH_CLIENT_ID=your_client_id
SAP_OAUTH_CLIENT_SECRET=your_client_secret
SAP_CLIENT=100
```

## Security & Privacy

- **No data stored** — All queries are pass-through to your SAP system
- **Read-only by default** — Only `lock_unlock_user` modifies data (marked as destructive)
- **On-premise compatible** — Deploy within your network perimeter
- **OAuth 2.0** — Industry-standard authentication
- See [PRIVACY.md](PRIVACY.md) for full privacy policy

## Compliance Frameworks

The server supports assessment against:
- **SOX** — Sarbanes-Oxley Act (financial controls)
- **GDPR** — General Data Protection Regulation (data privacy)
- **ISO 27001** — Information security management
- **NIST CSF** — Cybersecurity framework

## About SyntaAI

SyntaAI provides AI-powered ERP security solutions for mid-market enterprises. Our platform combines deep SAP domain expertise with modern AI capabilities to make enterprise security accessible and affordable.

- **Website:** [www.syntaai.com](https://www.syntaai.com)
- **Contact:** contact@syntaai.com
- **Founders:** 15+ years combined SAP security experience

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.

---

*Compatible with SAP® ERP and SAP® S/4HANA®. SAP is a registered trademark of SAP SE.*
