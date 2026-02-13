# Agent-Keyhole

**A Trust-Boundary for LLM Agents.** 
Your agent never holds your real credentials.

## Overview
Agent-Keyhole is a credential firewall designed for autonomous agents. It runs a secure sidecar process that manages your real API keys in RAM (sourced from OS Keychains or an encrypted Vault), while your Agent process only sees dummy placeholders.

## Integration
- **Transparent:** Patches \`https\` and \`fetch\` automatically.
- **Secure:** IPC over Unix Sockets with One-Time-Tokens (OTT).
- **Redacted:** Scans and scrubs responses to prevent credential "echo" leaks.

## License
MIT
