# Strider Tools - MCP Discovery Utilities

This directory contains standalone Python tools for discovering and inventorying Model Context Protocol (MCP) servers configured on a local system.

## Overview

The MCP Discovery Tool scans common configuration locations for popular LLM clients and AI development tools to identify configured MCP servers. It supports:

- **Anthropic Claude** (Desktop & Claude Code)
- **GitHub Copilot**
- **OpenAI/Codex**
- **Google Gemini CLI**
- **Hugging Face**
- **Continue.dev**
- **Sourcegraph Cody**
- **Ollama**
- **Cursor IDE**
- **VS Code Extensions**

## Platform Support

The tool runs natively on all major platforms:
- **macOS** (Darwin)
- **Windows** (Win32)
- **Linux**

It automatically detects the platform and scans appropriate configuration locations:
- macOS: `~/Library/Application Support/`, `~/.config/`, `~/.claude/`
- Windows: `%APPDATA%`, `%LOCALAPPDATA%`, `~/.config/`
- Linux: `~/.config/`, `~/.local/share/`, `~/.cache/`

## Installation & Setup

### Prerequisites

- Python 3.7 or higher
- No external dependencies (uses only standard library)

### Setting Up a Virtual Environment

It's recommended to use a virtual environment to isolate the tool:

```bash
# Navigate to the tools directory
cd /path/to/Strider/tools

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate

# On Windows (PowerShell):
.\venv\Scripts\Activate.ps1

# On Windows (CMD):
venv\Scripts\activate.bat
```

### Installing Dependencies (Optional)

The tool uses only Python standard library modules, so no additional packages are required. However, if you want to set up a complete environment:

```bash
# Verify Python version
python --version  # Should be 3.7+

# Optional: Create requirements.txt for future enhancements
pip freeze > requirements.txt
```

## Usage

### Basic Discovery Scan

```bash
# Run the discovery tool
python mcp_discovery.py

# Or make it executable (macOS/Linux)
chmod +x mcp_discovery.py
./mcp_discovery.py
```

### Output

The tool generates:
1. **Console output** - Real-time discovery progress and summary
2. **CSV file** - `output/mcp_inventory.csv` - Spreadsheet-compatible inventory
3. **JSON file** - `output/mcp_inventory.json` - Structured data for integration

### Example Output

```
============================================================
STRIDER - MCP Discovery Tool
Endpoint Core Agent Component
============================================================

[*] Starting MCP server discovery on hostname.local
[*] User: username
[*] Platform: Darwin
[*] Timestamp: 2025-11-17T02:00:00.000000Z
------------------------------------------------------------
[+] Found Claude Desktop config: /Users/username/Library/Application Support/Claude/claude_desktop_config.json
    [>] Discovered: postgres (Risk: 0.15)
    [>] Discovered: github (Risk: 0.55)
    [>] Discovered: filesystem (Risk: 0.20)
------------------------------------------------------------
[*] Total MCP servers discovered: 3

============================================================
MCP SERVER INVENTORY SUMMARY
============================================================

Risk Distribution:
  HIGH RISK (>= 0.5):   1 servers
  MEDIUM RISK (0.3-0.5): 0 servers
  LOW RISK (< 0.3):      2 servers

HIGH RISK SERVERS:
  - github: 0.55
    Risk Factors: CUSTOM_BINARY, SENSITIVE_ENV_VARS, CODE_REPOSITORY_ACCESS
```

## Risk Scoring

The tool assigns risk scores (0.0 - 1.0) based on security indicators:

| Risk Factor | Score | Description |
|-------------|-------|-------------|
| Custom Binary | +0.30 | Direct executable (not npx/uv managed) |
| Sensitive Env Vars | +0.25 | Contains TOKEN, KEY, SECRET, PASSWORD |
| File System Access | +0.20 | Has filesystem access capabilities |
| Database Access | +0.15 | Connects to databases (Postgres, Redis, etc.) |
| External URL | +0.10 | Connects to external services |
| Script Execution | +0.05 | Runs Python/Node scripts |

### Risk Categories

- **HIGH RISK (≥ 0.5)**: Requires immediate review
- **MEDIUM RISK (0.3 - 0.5)**: Should be monitored
- **LOW RISK (< 0.3)**: Standard configurations

## Configuration Locations Scanned

### Claude Desktop
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%/Claude/claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

### Claude Code
- All: `~/.claude/settings.json`, `~/.claude.json`
- macOS: `~/Library/Application Support/Claude Code/config.json`
- Windows: `%APPDATA%/Claude Code/config.json`

### GitHub Copilot
- All: `~/.config/github-copilot/config.json`
- macOS: `~/Library/Application Support/GitHub Copilot/config.json`
- Windows: `%APPDATA%/GitHub Copilot/config.json`

### Google Gemini CLI
- All: `~/.config/gemini/config.json`, `~/.gemini/config.json`
- macOS: `~/Library/Application Support/Gemini/config.json`
- Windows: `%APPDATA%/Gemini/config.json`

### Cursor IDE
- All: `~/.cursor/mcp.json`, `~/.cursor/settings.json`
- Platform-specific globalStorage paths

See the source code for complete list of all scanned locations.

## Output Files

### CSV Format (`mcp_inventory.csv`)

| Field | Description |
|-------|-------------|
| timestamp | Discovery time (ISO 8601 UTC) |
| server_name | MCP server identifier |
| command | Executable command |
| args | Command arguments |
| env_vars | Environment variables (masked) |
| config_path | Source configuration file |
| url | External URL (if applicable) |
| risk_score | Calculated risk (0.0 - 1.0) |
| risk_factors | Identified risk indicators |
| hostname | Machine hostname |
| user | Current user |

### JSON Format (`mcp_inventory.json`)

```json
{
  "scan_metadata": {
    "timestamp": "2025-11-17T02:00:00.000000Z",
    "hostname": "hostname.local",
    "user": "username",
    "platform": "Darwin",
    "total_servers": 14
  },
  "servers": [
    {
      "timestamp": "2025-11-17T02:00:00.000000Z",
      "server_name": "github",
      "command": "/path/to/binary",
      "args": "stdio",
      "env_vars": "{\"GITHUB_TOKEN\": \"ghp_xxxxx...\"}",
      "config_path": "/path/to/config.json",
      "url": "",
      "risk_score": "0.55",
      "risk_factors": "CUSTOM_BINARY;SENSITIVE_ENV_VARS",
      "hostname": "hostname.local",
      "user": "username"
    }
  ]
}
```

## Security Considerations

### Sensitive Data Masking

The tool automatically masks sensitive environment variables in output:
- Tokens, keys, secrets, and passwords are truncated
- Format: `"TOKEN": "first10chars..."`

### Privacy

- All scanning is local - no data is sent externally
- Configuration files are read-only
- Output files remain on the local system

## Integration with Strider

This tool can be used standalone or as part of the larger Strider AI-SPM platform:

```bash
# Standalone usage
python tools/mcp_discovery.py

# Output can be ingested by Strider agent-core for advanced analysis
# or sent to the Strider Data Plane for centralized monitoring
```

## Enterprise Deployment

The Python discovery tool is ideal for immediate enterprise deployment with zero external dependencies. Deploy via existing system management infrastructure and gain instant visibility into Shadow AI across your endpoint fleet.

### Deployment Strategy

1. **Package the Script** - Bundle `mcp_discovery.py` (single file, no dependencies)
2. **Deploy via System Management** - Distribute using JAMF, SCCM, Intune, Ansible, or Chef
3. **Schedule Daily Execution** - Configure cron, launchd, or Task Scheduler
4. **Collect Output Files** - Retrieve CSV/JSON through your management tool
5. **Centralize in CMDB** - Import inventory data into your asset management system

### Example: Scheduled Deployment

**macOS (launchd):**
```bash
# Daily scan at 2 AM
/usr/bin/python3 /usr/local/bin/mcp_discovery.py
# Output: /usr/local/bin/output/mcp_inventory.csv
```

**Windows (Task Scheduler):**
```powershell
# PowerShell scheduled task
python.exe C:\Tools\mcp_discovery.py
# Output: C:\Tools\output\mcp_inventory.csv
```

**Linux (cron):**
```bash
# Add to crontab - run daily at 3 AM
0 3 * * * /usr/bin/python3 /opt/strider/mcp_discovery.py
```

### CMDB & SIEM Integration

The structured CSV/JSON output integrates directly with:

- **ServiceNow CMDB** - Import as Configuration Items with risk metadata
- **Jira Assets** - Track MCP servers as discoverable software assets
- **Splunk** - Index JSON for real-time security monitoring and alerting
- **Elastic SIEM** - Ingest for threat detection and compliance dashboards
- **Microsoft Sentinel** - Feed into cloud-native SIEM
- **Custom Data Lakes** - Standard formats for any analytics pipeline

### Example: ServiceNow Import

```python
# ServiceNow REST API integration
import requests
import json

with open('output/mcp_inventory.json') as f:
    data = json.load(f)

for server in data['servers']:
    ci_record = {
        'name': server['server_name'],
        'u_risk_score': server['risk_score'],
        'u_risk_factors': server['risk_factors'],
        'u_hostname': server['hostname'],
        'u_discovery_time': server['timestamp']
    }
    # POST to ServiceNow CI table
```

### Benefits for Security Teams

- **Zero Infrastructure Required** - Single Python file, no servers or databases
- **No External Dependencies** - Uses only Python standard library
- **Immediate ROI** - Deploy in minutes, get results immediately
- **Minimal Attack Surface** - No network connectivity, no cloud services
- **Compliance Ready** - Full audit trail with timestamps and risk scores
- **Cost Effective** - Leverage existing Python installations and management tools
- **Vendor Agnostic** - Standard output formats work with any CMDB/SIEM

### Deployment Checklist

- [ ] Verify Python 3.7+ installed on target endpoints
- [ ] Test script execution with appropriate permissions
- [ ] Configure output directory with write access
- [ ] Set up scheduled task (daily recommended)
- [ ] Configure file collection in system management tool
- [ ] Set up CMDB/SIEM ingestion pipeline
- [ ] Create alerting rules for HIGH RISK servers
- [ ] Document baseline of approved MCP servers

This approach provides immediate visibility into Shadow AI without requiring additional infrastructure, vendor contracts, or cloud dependencies. Start detecting unauthorized AI tools today using your existing enterprise management investment.

## Extending the Tool

### Adding New LLM Client Support

1. Add configuration paths in `_get_config_locations()`
2. Add parsing logic if config format differs from standard MCP schema
3. Update the `discover_all()` method to include the new client

### Custom Risk Factors

Modify `_calculate_risk_score()` and `_identify_risk_factors()` in the `MCPServerInfo` class to add new risk indicators.

## Troubleshooting

### Common Issues

1. **Permission Denied**: Ensure read access to configuration directories
2. **Module Not Found**: Verify Python 3.7+ is installed
3. **No Servers Found**: Check if LLM clients are installed and configured

### Debug Mode

Add print statements or use Python debugger:

```bash
python -m pdb mcp_discovery.py
```

## License

Part of the Strider AI-SPM Platform. See main project README for license information.

## Contributing

Contributions welcome! Areas of interest:
- Additional LLM client support
- Enhanced risk scoring algorithms
- Platform-specific optimizations
- Output format enhancements (SIEM integration, etc.)
