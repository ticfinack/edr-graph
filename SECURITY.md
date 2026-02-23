# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in edr-graph, please report it responsibly using **GitHub's private vulnerability reporting**:

1. Go to the [Security Advisories](https://github.com/ticfinack/edr-graph/security/advisories) page
2. Click **"Report a vulnerability"**
3. Fill in the details of the vulnerability

**Please do NOT open a public issue for security vulnerabilities.**

### What to expect

- **Acknowledgement** within 72 hours of your report
- **Status update** within 7 days with an initial assessment
- A fix or mitigation plan for confirmed vulnerabilities

### Scope

The following are in scope for security reports:

- Authentication and authorization bypasses
- Remote code execution
- Injection vulnerabilities (command injection, SQL injection, etc.)
- Sensitive data exposure (credentials, tokens, PII leakage)
- gRPC and API endpoint vulnerabilities
- Agent-to-server communication security issues

### Out of Scope

- Denial of service via resource exhaustion on localhost-only endpoints
- Vulnerabilities in dependencies (report these upstream; we will update promptly)
- Issues requiring physical access to the host running the agent
