"""
SyntaAI ERP Security MCP Server
AI-powered ERP security analysis & compliance for SAP systems.
17+ tools for vulnerability scanning, user management, and compliance reporting.

Transport: Streamable HTTP
Auth: OAuth 2.0 (via SAP system)
"""

import os
import json
import logging
from datetime import datetime, timedelta
from typing import Any
from mcp.server.fastmcp import FastMCP

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("syntaai-mcp")

# ============================================================
# Server Configuration
# ============================================================

mcp = FastMCP(
    name="SyntaAI ERP Security",
    instructions="""You are an ERP security analyst assistant powered by SyntaAI. 
    You help users analyze SAP security posture, find vulnerabilities, 
    manage user access, and generate compliance reports.
    Always prioritize critical findings (SAP_ALL, dormant admins, SoD violations).
    Present findings by risk severity: Critical > High > Medium > Low.""",
    stateless_http=True,
    json_response=True,
)

# ============================================================
# Demo Data (Replace with real OData calls when SAP CAL is ready)
# ============================================================

from demo_data import (
    DEMO_USERS,
    DEMO_ROLES,
    DEMO_SECURITY_PARAMS,
    DEMO_AUDIT_LOG,
    DEMO_RFC_CONNECTIONS,
    DEMO_SOD_VIOLATIONS,
    DEMO_TRANSPORT_LOG,
    DEMO_AUTH_TRACE,
)


# ============================================================
# RESOURCES - Read-only data endpoints
# ============================================================

@mcp.resource("sap://system/info")
def get_system_info() -> str:
    """SAP System Information - basic details about the connected SAP system."""
    return json.dumps({
        "system_id": "S4H",
        "system_type": "SAP S/4HANA 2023",
        "client": "100",
        "hostname": "demo-s4h.syntaai.com",
        "kernel_release": "793",
        "database": "HANA 2.0 SPS07",
        "os": "Linux",
        "last_scan": datetime.now().isoformat(),
        "total_users": len(DEMO_USERS),
        "active_users": sum(1 for u in DEMO_USERS if u["status"] == "Active"),
    })


@mcp.resource("sap://security/overview")
def get_security_overview() -> str:
    """Security Posture Overview - high-level risk summary of the SAP system."""
    critical = sum(1 for u in DEMO_USERS if "SAP_ALL" in u.get("profiles", []))
    dormant = sum(1 for u in DEMO_USERS if u.get("days_since_login", 0) > 90)
    sod_count = len(DEMO_SOD_VIOLATIONS)
    
    return json.dumps({
        "overall_risk": "HIGH",
        "critical_findings": critical,
        "high_findings": sod_count,
        "medium_findings": dormant,
        "low_findings": 3,
        "summary": {
            "users_with_sap_all": critical,
            "dormant_users_90d": dormant,
            "sod_violations": sod_count,
            "weak_password_policy": True,
            "rfc_with_stored_credentials": sum(1 for r in DEMO_RFC_CONNECTIONS if r["stored_credentials"]),
        }
    })


@mcp.resource("sap://compliance/frameworks")
def get_compliance_frameworks() -> str:
    """Supported Compliance Frameworks available for assessment."""
    return json.dumps({
        "frameworks": [
            {"id": "SOX", "name": "Sarbanes-Oxley Act", "controls": 45, "description": "Financial reporting controls for public companies"},
            {"id": "GDPR", "name": "General Data Protection Regulation", "controls": 32, "description": "EU data privacy and protection"},
            {"id": "ISO27001", "name": "ISO/IEC 27001:2022", "controls": 58, "description": "Information security management"},
            {"id": "NIST", "name": "NIST Cybersecurity Framework", "controls": 41, "description": "US cybersecurity standards"},
        ]
    })


@mcp.resource("sap://security/controls")
def get_security_controls() -> str:
    """Security Controls Catalog - list of all security checks available."""
    return json.dumps({
        "total_controls": 1400,
        "categories": [
            {"name": "User Management", "count": 280, "description": "User lifecycle, access, authentication"},
            {"name": "Authorization", "count": 350, "description": "Roles, profiles, critical permissions"},
            {"name": "System Configuration", "count": 220, "description": "Profile parameters, security settings"},
            {"name": "Network Security", "count": 180, "description": "RFC, ICF, gateway security"},
            {"name": "Audit & Logging", "count": 150, "description": "Security audit log, change documents"},
            {"name": "Compliance", "count": 220, "description": "SOX, GDPR, ISO 27001 controls"},
        ]
    })


@mcp.resource("sap://users/summary")
def get_users_summary() -> str:
    """User Statistics Summary - overview of user accounts in the system."""
    users = DEMO_USERS
    return json.dumps({
        "total_users": len(users),
        "active_users": sum(1 for u in users if u["status"] == "Active"),
        "locked_users": sum(1 for u in users if u["status"] == "Locked"),
        "dormant_90d": sum(1 for u in users if u.get("days_since_login", 0) > 90),
        "dialog_users": sum(1 for u in users if u["user_type"] == "Dialog"),
        "system_users": sum(1 for u in users if u["user_type"] == "System"),
        "service_users": sum(1 for u in users if u["user_type"] == "Service"),
        "users_with_sap_all": sum(1 for u in users if "SAP_ALL" in u.get("profiles", [])),
    })


# ============================================================
# TOOLS - User Management (5)
# ============================================================

@mcp.tool(
    annotations={
        "title": "List SAP Users",
        "readOnlyHint": True,
        "destructiveHint": False,
    }
)
def list_users(
    status: str = "all",
    user_type: str = "all",
    limit: int = 50,
) -> dict[str, Any]:
    """List all SAP user accounts with optional filtering by status and type.
    
    Args:
        status: Filter by status - 'active', 'locked', or 'all'
        user_type: Filter by type - 'Dialog', 'System', 'Service', 'Communication', or 'all'
        limit: Maximum number of users to return (default 50)
    """
    users = DEMO_USERS
    
    if status != "all":
        users = [u for u in users if u["status"].lower() == status.lower()]
    if user_type != "all":
        users = [u for u in users if u["user_type"].lower() == user_type.lower()]
    
    return {
        "total_count": len(users),
        "returned_count": min(len(users), limit),
        "users": users[:limit],
    }


@mcp.tool(
    annotations={
        "title": "Get User Details",
        "readOnlyHint": True,
        "destructiveHint": False,
    }
)
def get_user_details(username: str) -> dict[str, Any]:
    """Get detailed information about a specific SAP user including roles, profiles, and login history.
    
    Args:
        username: The SAP username to look up (e.g., 'ADMIN01', 'J.SMITH')
    """
    user = next((u for u in DEMO_USERS if u["username"].upper() == username.upper()), None)
    
    if not user:
        return {"error": f"User '{username}' not found", "suggestion": "Use list_users to see available users"}
    
    return {"user": user}


@mcp.tool(
    annotations={
        "title": "Lock or Unlock User",
        "readOnlyHint": False,
        "destructiveHint": True,
    }
)
def lock_unlock_user(username: str, action: str) -> dict[str, Any]:
    """Lock or unlock a SAP user account. Use with caution - locking prevents user login.
    
    Args:
        username: The SAP username to lock/unlock
        action: 'lock' or 'unlock'
    """
    user = next((u for u in DEMO_USERS if u["username"].upper() == username.upper()), None)
    
    if not user:
        return {"error": f"User '{username}' not found"}
    
    if action.lower() not in ("lock", "unlock"):
        return {"error": "Action must be 'lock' or 'unlock'"}
    
    old_status = user["status"]
    new_status = "Locked" if action.lower() == "lock" else "Active"
    user["status"] = new_status
    
    return {
        "username": username.upper(),
        "action": action.lower(),
        "previous_status": old_status,
        "new_status": new_status,
        "timestamp": datetime.now().isoformat(),
        "message": f"User {username.upper()} has been {action.lower()}ed successfully",
    }


@mcp.tool(
    annotations={
        "title": "List User Role Assignments",
        "readOnlyHint": True,
        "destructiveHint": False,
    }
)
def list_user_roles(username: str) -> dict[str, Any]:
    """List all roles and profiles assigned to a specific SAP user.
    
    Args:
        username: The SAP username to check
    """
    user = next((u for u in DEMO_USERS if u["username"].upper() == username.upper()), None)
    
    if not user:
        return {"error": f"User '{username}' not found"}
    
    return {
        "username": username.upper(),
        "roles": user.get("roles", []),
        "profiles": user.get("profiles", []),
        "role_count": len(user.get("roles", [])),
        "has_critical_profiles": any(p in user.get("profiles", []) for p in ["SAP_ALL", "SAP_NEW"]),
    }


@mcp.tool(
    annotations={
        "title": "Find Inactive/Dormant Users",
        "readOnlyHint": True,
        "destructiveHint": False,
    }
)
def find_inactive_users(days: int = 90) -> dict[str, Any]:
    """Find users who haven't logged in for a specified number of days.
    
    Args:
        days: Number of days of inactivity (default 90)
    """
    inactive = [u for u in DEMO_USERS if u.get("days_since_login", 0) > days]
    
    # Sort by days since login, most inactive first
    inactive.sort(key=lambda x: x.get("days_since_login", 0), reverse=True)
    
    return {
        "threshold_days": days,
        "inactive_count": len(inactive),
        "risk_note": "Dormant accounts are prime targets for unauthorized access. Consider locking or removing these accounts.",
        "users": [{
            "username": u["username"],
            "full_name": u["full_name"],
            "days_since_login": u["days_since_login"],
            "user_type": u["user_type"],
            "has_critical_access": any(p in u.get("profiles", []) for p in ["SAP_ALL", "SAP_NEW"]),
            "roles": u.get("roles", []),
        } for u in inactive],
    }


# ============================================================
# TOOLS - Security Analysis (5)
# ============================================================

@mcp.tool(
    annotations={
        "title": "Get Security Parameters",
        "readOnlyHint": True,
        "destructiveHint": False,
    }
)
def get_security_parameters() -> dict[str, Any]:
    """Get SAP system security profile parameters and check against best practices."""
    params = DEMO_SECURITY_PARAMS
    
    non_compliant = [p for p in params if not p["compliant"]]
    
    return {
        "total_parameters": len(params),
        "compliant": len(params) - len(non_compliant),
        "non_compliant": len(non_compliant),
        "parameters": params,
        "risk_summary": f"{len(non_compliant)} parameters do not meet security best practices",
    }


@mcp.tool(
    annotations={
        "title": "Check Critical Authorizations",
        "readOnlyHint": True,
        "destructiveHint": False,
    }
)
def check_critical_authorizations() -> dict[str, Any]:
    """Check for users with critical authorizations like SAP_ALL, SAP_NEW, and other dangerous profiles."""
    critical_users = []
    
    for user in DEMO_USERS:
        critical_profiles = [p for p in user.get("profiles", []) if p in ["SAP_ALL", "SAP_NEW"]]
        critical_roles = [r for r in user.get("roles", []) if "ADMIN" in r.upper() or "SUPER" in r.upper()]
        
        if critical_profiles or critical_roles:
            critical_users.append({
                "username": user["username"],
                "full_name": user["full_name"],
                "status": user["status"],
                "user_type": user["user_type"],
                "critical_profiles": critical_profiles,
                "critical_roles": critical_roles,
                "risk_level": "CRITICAL" if "SAP_ALL" in critical_profiles else "HIGH",
                "recommendation": "Remove SAP_ALL immediately - assign specific roles instead" if "SAP_ALL" in critical_profiles else "Review admin role necessity",
            })
    
    return {
        "total_critical_users": len(critical_users),
        "sap_all_count": sum(1 for u in critical_users if "SAP_ALL" in u["critical_profiles"]),
        "risk_level": "CRITICAL" if any("SAP_ALL" in u["critical_profiles"] for u in critical_users) else "HIGH",
        "users": critical_users,
        "recommendation": "SAP_ALL grants unrestricted access to all system functions. It should NEVER be assigned in production systems.",
    }


@mcp.tool(
    annotations={
        "title": "Get Security Audit Log",
        "readOnlyHint": True,
        "destructiveHint": False,
    }
)
def get_audit_log(
    event_type: str = "all",
    days: int = 7,
    limit: int = 50,
) -> dict[str, Any]:
    """Retrieve security audit log entries for suspicious activity monitoring.
    
    Args:
        event_type: Filter by type - 'login_failed', 'auth_change', 'user_change', 'rfc_call', or 'all'
        days: Number of days to look back (default 7)
        limit: Maximum entries to return (default 50)
    """
    entries = DEMO_AUDIT_LOG
    
    if event_type != "all":
        entries = [e for e in entries if e["event_type"] == event_type]
    
    return {
        "period_days": days,
        "total_entries": len(entries),
        "returned_entries": min(len(entries), limit),
        "entries": entries[:limit],
        "summary": {
            "failed_logins": sum(1 for e in DEMO_AUDIT_LOG if e["event_type"] == "login_failed"),
            "auth_changes": sum(1 for e in DEMO_AUDIT_LOG if e["event_type"] == "auth_change"),
            "user_changes": sum(1 for e in DEMO_AUDIT_LOG if e["event_type"] == "user_change"),
        }
    }


@mcp.tool(
    annotations={
        "title": "Check Default Passwords",
        "readOnlyHint": True,
        "destructiveHint": False,
    }
)
def check_default_passwords() -> dict[str, Any]:
    """Check for SAP user accounts that may still have default or initial passwords."""
    users_with_default = [u for u in DEMO_USERS if u.get("default_password", False)]
    
    return {
        "total_checked": len(DEMO_USERS),
        "default_password_count": len(users_with_default),
        "risk_level": "CRITICAL" if users_with_default else "LOW",
        "users": [{
            "username": u["username"],
            "full_name": u["full_name"],
            "user_type": u["user_type"],
            "status": u["status"],
            "created_date": u.get("created_date", "Unknown"),
        } for u in users_with_default],
        "recommendation": "Force password change for all accounts with default passwords immediately.",
    }


@mcp.tool(
    annotations={
        "title": "Get RFC Connection Security",
        "readOnlyHint": True,
        "destructiveHint": False,
    }
)
def get_rfc_connections() -> dict[str, Any]:
    """Analyze RFC (Remote Function Call) destinations for security risks like stored credentials."""
    connections = DEMO_RFC_CONNECTIONS
    
    risky = [c for c in connections if c["stored_credentials"] or c["connection_type"] == "3"]
    
    return {
        "total_connections": len(connections),
        "risky_connections": len(risky),
        "risk_level": "HIGH" if risky else "LOW",
        "connections": connections,
        "recommendation": "RFC destinations with stored credentials pose a significant risk. Use trusted RFC or SSO instead.",
    }


# ============================================================
# TOOLS - Compliance & Audit (5)
# ============================================================

@mcp.tool(
    annotations={
        "title": "Run Segregation of Duties Check",
        "readOnlyHint": True,
        "destructiveHint": False,
    }
)
def run_sod_check(username: str = "all") -> dict[str, Any]:
    """Check for Segregation of Duties (SoD) violations - users with conflicting access rights.
    
    Args:
        username: Check specific user or 'all' for full system scan
    """
    violations = DEMO_SOD_VIOLATIONS
    
    if username != "all":
        violations = [v for v in violations if v["username"].upper() == username.upper()]
    
    return {
        "total_violations": len(violations),
        "critical_violations": sum(1 for v in violations if v["risk_level"] == "Critical"),
        "high_violations": sum(1 for v in violations if v["risk_level"] == "High"),
        "violations": violations,
        "recommendation": "SoD violations indicate users can both initiate and approve transactions, creating fraud risk.",
    }


@mcp.tool(
    annotations={
        "title": "Generate Compliance Report",
        "readOnlyHint": True,
        "destructiveHint": False,
    }
)
def generate_compliance_report(framework: str = "SOX") -> dict[str, Any]:
    """Generate a compliance assessment report for a specific regulatory framework.
    
    Args:
        framework: Compliance framework - 'SOX', 'GDPR', 'ISO27001', or 'NIST'
    """
    framework = framework.upper().replace(" ", "").replace("-", "")
    
    framework_data = {
        "SOX": {
            "name": "Sarbanes-Oxley Act",
            "total_controls": 45,
            "passed": 31,
            "failed": 9,
            "not_tested": 5,
            "key_findings": [
                {"control": "SOX-AC01", "description": "Access Control - Privileged Users", "status": "FAIL", "detail": "3 users have SAP_ALL profile in production"},
                {"control": "SOX-AC02", "description": "Segregation of Duties", "status": "FAIL", "detail": "7 SoD violations found across finance roles"},
                {"control": "SOX-AC03", "description": "User Access Reviews", "status": "FAIL", "detail": "5 dormant accounts with privileged access not reviewed in 90+ days"},
                {"control": "SOX-CL01", "description": "Change Management Logging", "status": "PASS", "detail": "All transport logs active and complete"},
                {"control": "SOX-AU01", "description": "Audit Trail", "status": "PASS", "detail": "Security audit log enabled with adequate retention"},
            ]
        },
        "GDPR": {
            "name": "General Data Protection Regulation",
            "total_controls": 32,
            "passed": 24,
            "failed": 6,
            "not_tested": 2,
            "key_findings": [
                {"control": "GDPR-DP01", "description": "Data Access Minimization", "status": "FAIL", "detail": "Excessive access rights found for 12 users"},
                {"control": "GDPR-DP02", "description": "Personal Data Encryption", "status": "PASS", "detail": "HANA encryption enabled for sensitive tables"},
                {"control": "GDPR-AU01", "description": "Access Logging", "status": "PASS", "detail": "Read access logging enabled for personal data tables"},
                {"control": "GDPR-RT01", "description": "Right to Erasure", "status": "FAIL", "detail": "No automated data deletion process configured"},
            ]
        },
        "ISO27001": {
            "name": "ISO/IEC 27001:2022",
            "total_controls": 58,
            "passed": 42,
            "failed": 11,
            "not_tested": 5,
            "key_findings": [
                {"control": "A.8.2", "description": "Privileged Access Rights", "status": "FAIL", "detail": "SAP_ALL assigned to non-emergency accounts"},
                {"control": "A.8.3", "description": "Information Access Restriction", "status": "FAIL", "detail": "Broad RFC access without restrictions"},
                {"control": "A.8.5", "description": "Secure Authentication", "status": "FAIL", "detail": "Password policy below recommended standards"},
                {"control": "A.8.15", "description": "Logging", "status": "PASS", "detail": "Comprehensive audit logging in place"},
            ]
        },
        "NIST": {
            "name": "NIST Cybersecurity Framework",
            "total_controls": 41,
            "passed": 30,
            "failed": 8,
            "not_tested": 3,
            "key_findings": [
                {"control": "PR.AC-1", "description": "Identity & Access Management", "status": "FAIL", "detail": "Dormant privileged accounts detected"},
                {"control": "PR.AC-4", "description": "Access Permissions", "status": "FAIL", "detail": "Excessive privileges not following least-privilege principle"},
                {"control": "DE.CM-1", "description": "Network Monitoring", "status": "PASS", "detail": "RFC monitoring active"},
            ]
        },
    }
    
    if framework not in framework_data:
        return {"error": f"Framework '{framework}' not supported. Use: SOX, GDPR, ISO27001, or NIST"}
    
    data = framework_data[framework]
    compliance_pct = round((data["passed"] / data["total_controls"]) * 100, 1)
    
    return {
        "framework": data["name"],
        "assessment_date": datetime.now().isoformat(),
        "system": "S4H/100",
        "compliance_percentage": compliance_pct,
        "overall_status": "NON-COMPLIANT" if data["failed"] > 0 else "COMPLIANT",
        "summary": {
            "total_controls": data["total_controls"],
            "passed": data["passed"],
            "failed": data["failed"],
            "not_tested": data["not_tested"],
        },
        "key_findings": data["key_findings"],
        "recommendation": f"Address {data['failed']} failed controls to achieve compliance. Focus on critical access control findings first.",
    }


@mcp.tool(
    annotations={
        "title": "List Privileged Users",
        "readOnlyHint": True,
        "destructiveHint": False,
    }
)
def list_privileged_users() -> dict[str, Any]:
    """List all users with elevated privileges including admin roles, SAP_ALL, and critical transaction access."""
    privileged = []
    
    for user in DEMO_USERS:
        priv_indicators = []
        
        if "SAP_ALL" in user.get("profiles", []):
            priv_indicators.append("SAP_ALL profile")
        if "SAP_NEW" in user.get("profiles", []):
            priv_indicators.append("SAP_NEW profile")
        if any("ADMIN" in r.upper() for r in user.get("roles", [])):
            priv_indicators.append("Admin role")
        if any("BASIS" in r.upper() for r in user.get("roles", [])):
            priv_indicators.append("Basis role")
        if user.get("has_debug_auth", False):
            priv_indicators.append("Debug authorization")
        
        if priv_indicators:
            privileged.append({
                "username": user["username"],
                "full_name": user["full_name"],
                "status": user["status"],
                "privilege_indicators": priv_indicators,
                "risk_level": "CRITICAL" if "SAP_ALL profile" in priv_indicators else "HIGH",
                "last_login_days_ago": user.get("days_since_login", 0),
            })
    
    return {
        "total_privileged_users": len(privileged),
        "critical_risk": sum(1 for p in privileged if p["risk_level"] == "CRITICAL"),
        "users": privileged,
        "recommendation": "Review all privileged accounts quarterly. Remove unnecessary elevated access.",
    }


@mcp.tool(
    annotations={
        "title": "Check Password Policy",
        "readOnlyHint": True,
        "destructiveHint": False,
    }
)
def check_password_policy() -> dict[str, Any]:
    """Analyze the SAP system password policy against security best practices."""
    policy = {
        "min_length": {"current": 6, "recommended": 12, "compliant": False},
        "max_idle_days": {"current": 180, "recommended": 90, "compliant": False},
        "password_history": {"current": 5, "recommended": 12, "compliant": False},
        "min_uppercase": {"current": 0, "recommended": 1, "compliant": False},
        "min_lowercase": {"current": 0, "recommended": 1, "compliant": False},
        "min_digits": {"current": 1, "recommended": 1, "compliant": True},
        "min_special": {"current": 0, "recommended": 1, "compliant": False},
        "max_failed_attempts": {"current": 5, "recommended": 5, "compliant": True},
        "lockout_duration_min": {"current": 30, "recommended": 30, "compliant": True},
        "password_expiry_days": {"current": 90, "recommended": 90, "compliant": True},
    }
    
    non_compliant = {k: v for k, v in policy.items() if not v["compliant"]}
    
    return {
        "total_checks": len(policy),
        "compliant": len(policy) - len(non_compliant),
        "non_compliant": len(non_compliant),
        "overall_status": "WEAK" if len(non_compliant) > 3 else "MODERATE" if non_compliant else "STRONG",
        "policy_details": policy,
        "failed_checks": non_compliant,
        "recommendation": "Password policy is below recommended standards. Increase minimum length to 12 and require mixed character types.",
    }


@mcp.tool(
    annotations={
        "title": "Get Transport Change Log",
        "readOnlyHint": True,
        "destructiveHint": False,
    }
)
def get_transport_log(days: int = 30, limit: int = 50) -> dict[str, Any]:
    """Get transport request log showing system changes for change management auditing.
    
    Args:
        days: Number of days to look back (default 30)
        limit: Maximum entries to return (default 50)
    """
    return {
        "period_days": days,
        "total_transports": len(DEMO_TRANSPORT_LOG),
        "transports": DEMO_TRANSPORT_LOG[:limit],
        "summary": {
            "development": sum(1 for t in DEMO_TRANSPORT_LOG if t["type"] == "Workbench"),
            "customizing": sum(1 for t in DEMO_TRANSPORT_LOG if t["type"] == "Customizing"),
            "imported": sum(1 for t in DEMO_TRANSPORT_LOG if t["status"] == "Imported"),
            "released": sum(1 for t in DEMO_TRANSPORT_LOG if t["status"] == "Released"),
        }
    }


# ============================================================
# TOOLS - Role & Authorization (5)
# ============================================================

@mcp.tool(
    annotations={
        "title": "List Security Roles",
        "readOnlyHint": True,
        "destructiveHint": False,
    }
)
def list_roles(search: str = "") -> dict[str, Any]:
    """List all security roles in the SAP system with optional search filter.
    
    Args:
        search: Search term to filter roles by name (optional)
    """
    roles = DEMO_ROLES
    
    if search:
        roles = [r for r in roles if search.upper() in r["role_name"].upper()]
    
    return {
        "total_roles": len(roles),
        "roles": roles,
    }


@mcp.tool(
    annotations={
        "title": "Get Role Details",
        "readOnlyHint": True,
        "destructiveHint": False,
    }
)
def get_role_details(role_name: str) -> dict[str, Any]:
    """Get detailed information about a specific SAP security role including authorizations and assigned users.
    
    Args:
        role_name: The SAP role name (e.g., 'Z_FI_ACCOUNTS_PAYABLE')
    """
    role = next((r for r in DEMO_ROLES if r["role_name"].upper() == role_name.upper()), None)
    
    if not role:
        return {"error": f"Role '{role_name}' not found", "suggestion": "Use list_roles to see available roles"}
    
    # Find users assigned to this role
    assigned_users = [u["username"] for u in DEMO_USERS if role_name in u.get("roles", [])]
    
    return {
        "role": role,
        "assigned_users": assigned_users,
        "user_count": len(assigned_users),
    }


@mcp.tool(
    annotations={
        "title": "Compare User Access",
        "readOnlyHint": True,
        "destructiveHint": False,
    }
)
def compare_user_access(user1: str, user2: str) -> dict[str, Any]:
    """Compare access rights between two SAP users to identify differences and anomalies.
    
    Args:
        user1: First SAP username
        user2: Second SAP username
    """
    u1 = next((u for u in DEMO_USERS if u["username"].upper() == user1.upper()), None)
    u2 = next((u for u in DEMO_USERS if u["username"].upper() == user2.upper()), None)
    
    if not u1:
        return {"error": f"User '{user1}' not found"}
    if not u2:
        return {"error": f"User '{user2}' not found"}
    
    roles1 = set(u1.get("roles", []))
    roles2 = set(u2.get("roles", []))
    profiles1 = set(u1.get("profiles", []))
    profiles2 = set(u2.get("profiles", []))
    
    return {
        "user1": {"username": u1["username"], "full_name": u1["full_name"]},
        "user2": {"username": u2["username"], "full_name": u2["full_name"]},
        "common_roles": list(roles1 & roles2),
        "only_user1_roles": list(roles1 - roles2),
        "only_user2_roles": list(roles2 - roles1),
        "common_profiles": list(profiles1 & profiles2),
        "only_user1_profiles": list(profiles1 - profiles2),
        "only_user2_profiles": list(profiles2 - profiles1),
        "risk_note": "Significant access differences between users in the same role may indicate access creep.",
    }


@mcp.tool(
    annotations={
        "title": "Find Users With Specific Role",
        "readOnlyHint": True,
        "destructiveHint": False,
    }
)
def find_users_with_role(role_name: str) -> dict[str, Any]:
    """Find all users who have a specific role assigned.
    
    Args:
        role_name: The SAP role name to search for
    """
    users = [u for u in DEMO_USERS if role_name.upper() in [r.upper() for r in u.get("roles", [])]]
    
    return {
        "role_name": role_name.upper(),
        "user_count": len(users),
        "users": [{
            "username": u["username"],
            "full_name": u["full_name"],
            "status": u["status"],
            "user_type": u["user_type"],
            "last_login_days_ago": u.get("days_since_login", 0),
        } for u in users],
    }


@mcp.tool(
    annotations={
        "title": "Get Authorization Trace",
        "readOnlyHint": True,
        "destructiveHint": False,
    }
)
def get_authorization_trace(username: str = "all", limit: int = 50) -> dict[str, Any]:
    """Get authorization check trace entries showing what permissions users actually use.
    
    Args:
        username: Filter by username or 'all' for system-wide trace
        limit: Maximum entries to return (default 50)
    """
    traces = DEMO_AUTH_TRACE
    
    if username != "all":
        traces = [t for t in traces if t["username"].upper() == username.upper()]
    
    return {
        "total_entries": len(traces),
        "returned_entries": min(len(traces), limit),
        "traces": traces[:limit],
        "summary": {
            "successful_checks": sum(1 for t in traces if t["result"] == "PASS"),
            "failed_checks": sum(1 for t in traces if t["result"] == "FAIL"),
        }
    }


# ============================================================
# PROMPTS - Pre-built workflow templates
# ============================================================

@mcp.prompt()
def security_audit() -> str:
    """Run a comprehensive security audit of the SAP system."""
    return """Please perform a full security audit of the SAP system. Follow these steps:

1. First, check the security overview for the current risk posture
2. Check for users with critical authorizations (SAP_ALL, SAP_NEW)
3. Find all dormant/inactive users (90+ days)
4. Run a segregation of duties check
5. Check the password policy
6. Review RFC connections for stored credentials
7. Check for default passwords

After gathering all findings, provide:
- Executive summary with overall risk rating
- Critical findings that need immediate action
- Recommended remediation steps prioritized by risk
- Timeline suggestion for addressing each finding"""


@mcp.prompt()
def sox_compliance_check() -> str:
    """Run a SOX compliance assessment."""
    return """Please perform a Sarbanes-Oxley (SOX) compliance assessment:

1. Generate the SOX compliance report
2. Check segregation of duties violations (critical for SOX)
3. Review privileged user access
4. Check the audit log for unauthorized changes
5. Review the transport log for change management compliance

Provide a compliance summary with:
- Overall compliance percentage
- Failed controls with details
- Remediation recommendations for each finding
- Priority ranking for fixes"""


@mcp.prompt()
def user_access_review() -> str:
    """Perform a periodic user access review."""
    return """Please perform a comprehensive user access review:

1. List all users and their current status
2. Identify dormant accounts (90+ days inactive)
3. Check for users with critical authorizations
4. List all privileged users
5. Check for default passwords
6. Run segregation of duties check

For each finding, recommend:
- Accounts to lock or remove
- Excessive privileges to revoke
- SoD conflicts to resolve
- Default passwords to force-change"""


@mcp.prompt()
def sod_analysis() -> str:
    """Deep dive into Segregation of Duties violations."""
    return """Please perform a detailed Segregation of Duties (SoD) analysis:

1. Run the SoD check for all users
2. For each violation, get the user details
3. Check if violating users also have other critical access
4. Cross-reference with dormant account status

Provide:
- Summary of all SoD violations by risk level
- Business impact analysis for each conflict
- Mitigation options (role redesign, compensating controls)
- Priority remediation plan"""


@mcp.prompt()
def inactive_user_cleanup() -> str:
    """Plan for cleaning up inactive user accounts."""
    return """Please create an inactive user cleanup plan:

1. Find all users inactive for 90+ days
2. Check which inactive users have privileged access
3. Get role details for inactive privileged users
4. Check if any inactive users have SoD violations

Create a cleanup plan with:
- Users to lock immediately (inactive + privileged)
- Users to notify before locking (inactive + active roles)
- Users safe to deactivate
- Estimated risk reduction from cleanup"""


@mcp.prompt()
def rfc_security_review() -> str:
    """Review RFC connection security."""
    return """Please review RFC connection security:

1. Get all RFC connections and their security status
2. Identify connections with stored credentials
3. Check security parameters related to RFC
4. Review audit log for RFC-related events

Provide:
- List of risky RFC destinations
- Recommendations for securing each connection
- Impact assessment of removing stored credentials"""


@mcp.prompt()
def privileged_access_review() -> str:
    """Review all privileged access in the system."""
    return """Please perform a privileged access review:

1. List all privileged users
2. Check critical authorizations
3. Compare privileged users' access for consistency
4. Cross-reference with inactive user list
5. Check for SoD violations among privileged users

Provide:
- Privileged access matrix
- Anomalies and outliers
- Recommendations for privilege reduction
- Emergency access procedure assessment"""


@mcp.prompt()
def password_policy_assessment() -> str:
    """Assess password policy strength."""
    return """Please assess the SAP system password policy:

1. Check current password policy settings
2. Get security parameters related to authentication
3. Check for users with default passwords
4. Review audit log for failed login attempts

Provide:
- Current policy vs. best practices comparison
- Specific parameter changes needed
- Impact assessment of strengthening the policy
- Implementation recommendations"""


# ============================================================
# Run Server
# ============================================================

if __name__ == "__main__":
    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",
        port=8000,
    )
