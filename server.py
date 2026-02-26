"""
SyntaAI ERP Security MCP Server — with OAuth 2.0

This is the updated server.py that adds OAuth 2.0 authentication on top of
the existing 20 tools, 5 resources, and 8 prompts.

Changes from the original server.py:
  1. Imports SyntaAIOAuthProvider
  2. Passes auth_server_provider + auth settings to FastMCP()
  3. All tools/resources/prompts remain identical
  4. MCP SDK auto-creates:
     - /.well-known/oauth-authorization-server  (RFC 8414)
     - /.well-known/oauth-protected-resource    (RFC 9728)
     - /authorize
     - /token
     - /register  (Dynamic Client Registration)
     - /revoke

Drop this file + oauth_provider.py onto the EC2 at /opt/mcp-server/
and restart the service.

Usage:
  python server.py                    # default: Streamable HTTP on :8000
  MCP_NO_AUTH=1 python server.py      # disable auth (dev mode)
"""

import os
import logging

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.server import TransportSecuritySettings
from mcp.server.auth.settings import (
    AuthSettings,
    ClientRegistrationOptions,
    RevocationOptions,
)

# --- Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("syntaai.server")

# --- Import demo data (unchanged from original) ---
from demo_data import (
    DEMO_USERS, DEMO_ROLES, DEMO_VULNERABILITIES,
    DEMO_AUDIT_LOG, DEMO_RFC_CONNECTIONS, DEMO_TRANSPORT_LOG,
    DEMO_SOD_VIOLATIONS, DEMO_SECURITY_PARAMETERS,
    DEMO_SYSTEM_INFO, DEMO_COMPLIANCE_FRAMEWORKS,
    DEMO_SECURITY_CONTROLS,
)

# --- OAuth Setup ---
ISSUER_URL = os.getenv("SYNTAAI_ISSUER_URL", "https://mcp.syntaai.com")
NO_AUTH = os.getenv("MCP_NO_AUTH", "").lower() in ("1", "true", "yes")

_TRANSPORT_SECURITY = TransportSecuritySettings(
    enable_dns_rebinding_protection=True,
    allowed_hosts=["127.0.0.1:*", "localhost:*", "[::1]:*", "mcp.syntaai.com:*", "mcp.syntaai.com"],
    allowed_origins=["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*", "https://mcp.syntaai.com", "https://mcp.syntaai.com:*"],
)

if NO_AUTH:
    logger.warning("Running WITHOUT authentication (MCP_NO_AUTH=1)")
    mcp = FastMCP(
        "SyntaAI ERP Security",
        instructions=(
            "SyntaAI ERP Security MCP Server provides AI-powered security analysis "
            "for SAP systems. Use the available tools to scan for vulnerabilities, "
            "review user access, check compliance, and analyze roles."
        ),
        host="0.0.0.0",
        port=8000,
        transport_security=_TRANSPORT_SECURITY,
    )
else:
    from oauth_provider import SyntaAIOAuthProvider

    oauth_provider = SyntaAIOAuthProvider()

    mcp = FastMCP(
        "SyntaAI ERP Security",
        instructions=(
            "SyntaAI ERP Security MCP Server provides AI-powered security analysis "
            "for SAP systems. Use the available tools to scan for vulnerabilities, "
            "review user access, check compliance, and analyze roles."
        ),
        auth_server_provider=oauth_provider,
        auth=AuthSettings(
            issuer_url=ISSUER_URL,
            resource_server_url=ISSUER_URL,
            revocation_options=RevocationOptions(enabled=True),
            client_registration_options=ClientRegistrationOptions(
                enabled=True,
                valid_scopes=[
                    "erp:read",
                    "erp:write",
                    "erp:admin",
                    "user:read",
                    "user:manage",
                    "compliance:read",
                    "audit:read",
                ],
                default_scopes=["erp:read", "user:read", "compliance:read", "audit:read"],
            ),
            required_scopes=["erp:read"],
        ),
        host="0.0.0.0",
        port=8000,
        transport_security=_TRANSPORT_SECURITY,
    )
    logger.info("OAuth 2.0 enabled (issuer: %s)", ISSUER_URL)


# ============================================================================
# TOOLS (20) — identical to original
# ============================================================================

# --- User Management (5) ---

@mcp.tool()
def list_users(status: str = "all", user_type: str = "all") -> dict:
    """List all SAP user accounts with filtering by status (active/locked/expired/all) and type (dialog/system/communication/all)."""
    users = DEMO_USERS
    if status != "all":
        users = [u for u in users if u["status"].lower() == status.lower()]
    if user_type != "all":
        users = [u for u in users if u["user_type"].lower() == user_type.lower()]
    return {"total": len(users), "users": users}


@mcp.tool()
def get_user_details(username: str) -> dict:
    """Get detailed user information including roles, profiles, login history, and lock status."""
    for u in DEMO_USERS:
        if u["username"].upper() == username.upper():
            return {"found": True, "user": u}
    return {"found": False, "message": f"User {username} not found"}


@mcp.tool()
def lock_unlock_user(username: str, action: str = "lock") -> dict:
    """Lock or unlock a SAP user account. Action must be 'lock' or 'unlock'. This is a destructive operation."""
    for u in DEMO_USERS:
        if u["username"].upper() == username.upper():
            new_status = "Locked" if action == "lock" else "Active"
            return {
                "success": True,
                "username": username,
                "action": action,
                "previous_status": u["status"],
                "new_status": new_status,
                "message": f"User {username} has been {action}ed (demo mode — no actual change)",
            }
    return {"success": False, "message": f"User {username} not found"}


@mcp.tool()
def list_user_roles(username: str) -> dict:
    """List all roles and profiles assigned to a specific user."""
    for u in DEMO_USERS:
        if u["username"].upper() == username.upper():
            return {
                "username": username,
                "roles": u.get("roles", []),
                "profiles": u.get("profiles", []),
                "total_roles": len(u.get("roles", [])),
                "total_profiles": len(u.get("profiles", [])),
            }
    return {"found": False, "message": f"User {username} not found"}


@mcp.tool()
def find_inactive_users(days: int = 90) -> dict:
    """Find users who haven't logged in for the specified number of days."""
    inactive = [u for u in DEMO_USERS if u.get("days_since_login", 0) >= days]
    return {
        "threshold_days": days,
        "inactive_count": len(inactive),
        "users": inactive,
        "recommendation": f"Review and consider disabling {len(inactive)} inactive users",
    }


# --- Security Analysis (5) ---

@mcp.tool()
def get_security_parameters() -> dict:
    """Get SAP security profile parameters compared against best practices."""
    return {
        "total_parameters": len(DEMO_SECURITY_PARAMETERS),
        "parameters": DEMO_SECURITY_PARAMETERS,
    }


@mcp.tool()
def check_critical_authorizations() -> dict:
    """Find users with SAP_ALL, SAP_NEW, S_A.SYSTEM, and other dangerous profiles/authorizations."""
    critical = []
    for u in DEMO_USERS:
        profs = u.get("profiles", [])
        dangerous = [p for p in profs if p in ("SAP_ALL", "SAP_NEW", "S_A.SYSTEM")]
        if dangerous:
            critical.append({
                "username": u["username"],
                "full_name": u.get("full_name", ""),
                "dangerous_profiles": dangerous,
                "risk": "CRITICAL",
            })
    return {
        "critical_users": len(critical),
        "users": critical,
        "recommendation": "Remove SAP_ALL and SAP_NEW from all non-emergency accounts",
    }


@mcp.tool()
def get_audit_log(event_type: str = "all", limit: int = 50) -> dict:
    """Retrieve security audit log entries. Filter by event_type: all, login_failed, auth_check, user_change, transaction."""
    logs = DEMO_AUDIT_LOG
    if event_type != "all":
        logs = [l for l in logs if l.get("event_type", "").lower() == event_type.lower()]
    return {"total": len(logs[:limit]), "entries": logs[:limit]}


@mcp.tool()
def check_default_passwords() -> dict:
    """Check for accounts that still have default or initial passwords set."""
    default_pw = [u for u in DEMO_USERS if u.get("default_password", False)]
    return {
        "accounts_with_default_passwords": len(default_pw),
        "users": default_pw,
        "risk": "HIGH" if default_pw else "LOW",
        "recommendation": "Force password change for all accounts with default passwords",
    }


@mcp.tool()
def get_rfc_connections() -> dict:
    """Analyze RFC destinations for stored credentials and security risks."""
    return {
        "total_connections": len(DEMO_RFC_CONNECTIONS),
        "connections": DEMO_RFC_CONNECTIONS,
        "stored_credentials_count": sum(
            1 for r in DEMO_RFC_CONNECTIONS if r.get("stored_credentials", False)
        ),
    }


# --- Compliance & Audit (5) ---

@mcp.tool()
def run_sod_check(username: str = "") -> dict:
    """Check for Segregation of Duties violations. Optionally filter by username."""
    violations = DEMO_SOD_VIOLATIONS
    if username:
        violations = [v for v in violations if v.get("username", "").upper() == username.upper()]
    return {
        "total_violations": len(violations),
        "violations": violations,
        "risk_summary": {
            "critical": sum(1 for v in violations if v.get("risk_level") == "Critical"),
            "high": sum(1 for v in violations if v.get("risk_level") == "High"),
            "medium": sum(1 for v in violations if v.get("risk_level") == "Medium"),
        },
    }


@mcp.tool()
def generate_compliance_report(framework: str = "SOX") -> dict:
    """Generate a compliance assessment report for SOX, GDPR, ISO27001, or NIST framework."""
    fw = framework.upper()
    if fw not in ("SOX", "GDPR", "ISO27001", "NIST"):
        return {"error": f"Unknown framework: {framework}. Use SOX, GDPR, ISO27001, or NIST"}

    # Simulated compliance data
    scores = {"SOX": 72, "GDPR": 68, "ISO27001": 75, "NIST": 70}
    return {
        "framework": fw,
        "overall_score": scores.get(fw, 70),
        "max_score": 100,
        "status": "NEEDS_IMPROVEMENT" if scores.get(fw, 70) < 80 else "COMPLIANT",
        "findings_count": 12,
        "critical_findings": 3,
        "report_date": "2026-02-26",
        "next_review": "2026-05-26",
        "top_findings": [
            {"id": "F-001", "severity": "CRITICAL", "description": "Users with SAP_ALL profile detected", "framework_control": f"{fw}-AC-1"},
            {"id": "F-002", "severity": "HIGH", "description": "Weak password policy parameters", "framework_control": f"{fw}-IA-5"},
            {"id": "F-003", "severity": "HIGH", "description": "Segregation of duties violations found", "framework_control": f"{fw}-AC-5"},
        ],
    }


@mcp.tool()
def list_privileged_users() -> dict:
    """List all users with elevated privileges (admin roles, SAP_ALL, basis access)."""
    privileged = [u for u in DEMO_USERS if u.get("has_debug_auth", False) or any(p in ("SAP_ALL", "SAP_NEW") for p in u.get("profiles", []))]
    return {
        "privileged_count": len(privileged),
        "users": privileged,
        "recommendation": "Review privileged access quarterly",
    }


@mcp.tool()
def check_password_policy() -> dict:
    """Analyze the current password policy configuration against security best practices."""
    policy = {
        "min_length": {"current": 8, "recommended": 12, "compliant": False},
        "complexity_required": {"current": True, "recommended": True, "compliant": True},
        "max_age_days": {"current": 90, "recommended": 60, "compliant": False},
        "min_age_days": {"current": 1, "recommended": 1, "compliant": True},
        "history_count": {"current": 5, "recommended": 12, "compliant": False},
        "lockout_threshold": {"current": 5, "recommended": 3, "compliant": False},
        "lockout_duration_min": {"current": 30, "recommended": 30, "compliant": True},
    }
    compliant = sum(1 for v in policy.values() if v["compliant"])
    return {
        "total_checks": len(policy),
        "compliant": compliant,
        "non_compliant": len(policy) - compliant,
        "score": round(compliant / len(policy) * 100),
        "policy": policy,
    }


@mcp.tool()
def get_transport_log(limit: int = 20) -> dict:
    """Get transport request log for change management audit trail."""
    return {"total": len(DEMO_TRANSPORT_LOG[:limit]), "transports": DEMO_TRANSPORT_LOG[:limit]}


# --- Role & Authorization (5) ---

@mcp.tool()
def list_roles(search: str = "") -> dict:
    """List all security roles with optional search filter."""
    roles = DEMO_ROLES
    if search:
        roles = [r for r in roles if search.upper() in r["role_name"].upper() or search.upper() in r.get("description", "").upper()]
    return {"total": len(roles), "roles": roles}


@mcp.tool()
def get_role_details(role_name: str) -> dict:
    """Get detailed role information including authorizations, assigned users, and risk level."""
    for r in DEMO_ROLES:
        if r["role_name"].upper() == role_name.upper():
            return {"found": True, "role": r}
    return {"found": False, "message": f"Role {role_name} not found"}


@mcp.tool()
def compare_user_access(user1: str, user2: str) -> dict:
    """Compare access rights between two SAP users — roles, profiles, and authorizations."""
    u1 = next((u for u in DEMO_USERS if u["username"].upper() == user1.upper()), None)
    u2 = next((u for u in DEMO_USERS if u["username"].upper() == user2.upper()), None)
    if not u1:
        return {"error": f"User {user1} not found"}
    if not u2:
        return {"error": f"User {user2} not found"}

    r1 = set(u1.get("roles", []))
    r2 = set(u2.get("roles", []))
    return {
        "user1": user1,
        "user2": user2,
        "common_roles": sorted(r1 & r2),
        "only_user1": sorted(r1 - r2),
        "only_user2": sorted(r2 - r1),
        "user1_total_roles": len(r1),
        "user2_total_roles": len(r2),
    }


@mcp.tool()
def find_users_with_role(role_name: str) -> dict:
    """Find all users who have a specific role assigned."""
    users = [u for u in DEMO_USERS if role_name.upper() in [r.upper() for r in u.get("roles", [])]]
    return {
        "role": role_name,
        "assigned_users": len(users),
        "users": [{"username": u["username"], "full_name": u.get("full_name", ""), "status": u["status"]} for u in users],
    }


@mcp.tool()
def get_authorization_trace(username: str = "", transaction: str = "") -> dict:
    """Get authorization check trace entries. Filter by username and/or transaction code."""
    traces = [
        {"timestamp": "2026-02-26T10:15:00Z", "username": "J.SMITH", "transaction": "SU01", "auth_object": "S_USER_GRP", "result": "SUCCESS"},
        {"timestamp": "2026-02-26T10:16:00Z", "username": "M.JONES", "transaction": "SE38", "auth_object": "S_DEVELOP", "result": "FAILED"},
        {"timestamp": "2026-02-26T10:17:00Z", "username": "J.SMITH", "transaction": "SM21", "auth_object": "S_ADMI_FCD", "result": "SUCCESS"},
        {"timestamp": "2026-02-26T10:18:00Z", "username": "A.BROWN", "transaction": "FB01", "auth_object": "F_BKPF_BUK", "result": "SUCCESS"},
    ]
    if username:
        traces = [t for t in traces if t["username"].upper() == username.upper()]
    if transaction:
        traces = [t for t in traces if t["transaction"].upper() == transaction.upper()]
    return {"total": len(traces), "traces": traces}


# ============================================================================
# RESOURCES (5)
# ============================================================================

@mcp.resource("sap://system/info")
def system_info() -> str:
    """SAP system information including SID, version, and component details."""
    import json
    return json.dumps(DEMO_SYSTEM_INFO, indent=2)


@mcp.resource("sap://security/overview")
def security_overview() -> str:
    """Security posture overview with risk summary and key metrics."""
    import json
    overview = {
        "risk_score": 65,
        "risk_level": "MEDIUM",
        "total_users": len(DEMO_USERS),
        "active_users": sum(1 for u in DEMO_USERS if u["status"] == "Active"),
        "locked_users": sum(1 for u in DEMO_USERS if u["status"] == "Locked"),
        "privileged_users": sum(1 for u in DEMO_USERS if u.get("has_debug_auth", False) or any(p in ("SAP_ALL", "SAP_NEW") for p in u.get("profiles", []))),
        "sod_violations": len(DEMO_SOD_VIOLATIONS),
        "critical_findings": 5,
        "open_vulnerabilities": len(DEMO_VULNERABILITIES),
        "last_scan": "2026-02-26T08:00:00Z",
    }
    return json.dumps(overview, indent=2)


@mcp.resource("sap://compliance/frameworks")
def compliance_frameworks() -> str:
    """Supported compliance frameworks and their assessment status."""
    import json
    return json.dumps(DEMO_COMPLIANCE_FRAMEWORKS, indent=2)


@mcp.resource("sap://security/controls")
def security_controls() -> str:
    """Security controls catalog — 1,400+ checks across SAP modules."""
    import json
    return json.dumps(DEMO_SECURITY_CONTROLS, indent=2)


@mcp.resource("sap://users/summary")
def users_summary() -> str:
    """User account statistics — total, active, locked, expired, by type."""
    import json
    summary = {
        "total": len(DEMO_USERS),
        "by_status": {},
        "by_type": {},
    }
    for u in DEMO_USERS:
        s = u["status"]
        summary["by_status"][s] = summary["by_status"].get(s, 0) + 1
        t = u.get("user_type", "Dialog")
        summary["by_type"][t] = summary["by_type"].get(t, 0) + 1
    return json.dumps(summary, indent=2)


# ============================================================================
# PROMPTS (8)
# ============================================================================

@mcp.prompt()
def security_audit() -> str:
    """Run a comprehensive security audit of the SAP system."""
    return (
        "Please perform a full security audit of this SAP system. "
        "Start by checking critical authorizations, then review password policy, "
        "look for inactive users, check RFC connections, run SoD analysis, "
        "and generate a compliance report. Prioritize findings by risk level "
        "and provide actionable recommendations."
    )


@mcp.prompt()
def sox_compliance_check() -> str:
    """Perform a Sarbanes-Oxley compliance assessment."""
    return (
        "Run a SOX compliance assessment. Check segregation of duties, "
        "review privileged access, verify password policies meet SOX requirements, "
        "and examine the change management audit trail. Generate the SOX "
        "compliance report and highlight any gaps."
    )


@mcp.prompt()
def user_access_review() -> str:
    """Conduct a periodic user access review."""
    return (
        "Conduct a user access review. List all users and their roles, "
        "identify inactive users (90+ days), find users with excessive privileges, "
        "check for default passwords, and compare access between similar roles. "
        "Recommend access removals and role adjustments."
    )


@mcp.prompt()
def sod_analysis() -> str:
    """Deep dive into Segregation of Duties violations."""
    return (
        "Perform a detailed Segregation of Duties analysis. Run the SoD check, "
        "then for each violation, examine the specific users, roles, and "
        "conflicting authorizations. Suggest remediation options including "
        "role redesign and compensating controls."
    )


@mcp.prompt()
def inactive_user_cleanup() -> str:
    """Plan for cleaning up inactive user accounts."""
    return (
        "Help me clean up inactive user accounts. Find all users inactive "
        "for 90+ days, categorize them by user type (dialog, system, "
        "communication), check if any have critical roles, and create "
        "a prioritized cleanup plan with lock/disable recommendations."
    )


@mcp.prompt()
def rfc_security_review() -> str:
    """Review RFC connection security."""
    return (
        "Review all RFC connections for security risks. Check for stored "
        "credentials, identify connections to production systems, look for "
        "RFC connections using privileged accounts, and recommend "
        "security improvements."
    )


@mcp.prompt()
def privileged_access_review() -> str:
    """Review privileged access across the SAP system."""
    return (
        "Review privileged access in the SAP system. List all users with "
        "SAP_ALL, SAP_NEW, or admin roles. Check if privileged access is "
        "justified, identify any dormant privileged accounts, and suggest "
        "a least-privilege remediation plan."
    )


@mcp.prompt()
def password_policy_assessment() -> str:
    """Assess password policy strength against best practices."""
    return (
        "Assess the SAP password policy. Check current settings against "
        "industry best practices (NIST, CIS), identify weak parameters, "
        "check for accounts with default passwords, and recommend "
        "specific parameter changes with SAP transaction codes."
    )


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    from starlette.routing import Route

    logger.info("Starting SyntaAI MCP Server on 0.0.0.0:8000")
    logger.info("OAuth: %s", "DISABLED" if NO_AUTH else "ENABLED")
    logger.info("Endpoint: http://0.0.0.0:8000/mcp")

    app = mcp.streamable_http_app()

    if not NO_AUTH:
        from oauth_provider import login_page_handler
        # Mount the login page route and store the provider in app state
        app.routes.insert(0, Route("/syntaai-login", login_page_handler, methods=["GET", "POST"]))
        app.state.oauth_provider = oauth_provider

    config = uvicorn.Config(app, host="0.0.0.0", port=8000, log_level="info")
    server = uvicorn.Server(config)
    import anyio
    anyio.run(server.serve)
