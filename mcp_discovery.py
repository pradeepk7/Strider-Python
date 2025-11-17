#!/usr/bin/env python3
"""
MCP Discovery Tool - Endpoint Core Agent Component
Strider AI-SPM Platform

Discovers and inventories Model Context Protocol (MCP) servers configured on the local system.
Extracts metadata including server names, command paths, arguments, and environment variables.
Outputs findings to CSV for security analysis.
"""

import json
import csv
import os
import sys
import platform
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
import hashlib
import socket


class MCPServerInfo:
    """Represents a single MCP server configuration."""

    def __init__(
        self,
        name: str,
        command: str,
        args: List[str],
        env_vars: Dict[str, str],
        config_path: str,
        url: Optional[str] = None
    ):
        self.name = name
        self.command = command
        self.args = args
        self.env_vars = env_vars
        self.config_path = config_path
        self.url = url
        self.discovered_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        self.risk_score = self._calculate_risk_score()
        self.risk_factors = self._identify_risk_factors()

    def _calculate_risk_score(self) -> float:
        """Calculate risk score based on server configuration."""
        score = 0.0

        # High risk: Direct binary execution (not npx/uv)
        if not self.command.startswith(("npx", "uvx", "uv")):
            if os.path.isfile(self.command):
                score += 0.3  # Custom binary

        # Medium risk: Environment variables with sensitive patterns
        sensitive_patterns = ["TOKEN", "KEY", "SECRET", "PASSWORD", "CREDENTIAL"]
        for key in self.env_vars.keys():
            if any(pattern in key.upper() for pattern in sensitive_patterns):
                score += 0.25
                break

        # Medium risk: File system access
        if "filesystem" in self.name.lower() or any("filesystem" in arg for arg in self.args):
            score += 0.2

        # Medium risk: Database access
        if any(db in self.name.lower() for db in ["postgres", "mysql", "redis", "mongo"]):
            score += 0.15

        # Low risk: External URL connection
        if self.url:
            score += 0.1

        # Low risk: Python/Node execution
        if any(runner in self.command for runner in ["python", "node", "run"]):
            score += 0.05

        return min(score, 1.0)

    def _identify_risk_factors(self) -> List[str]:
        """Identify specific risk factors for this server."""
        factors = []

        if not self.command.startswith(("npx", "uvx", "uv")):
            if os.path.isfile(self.command):
                factors.append("CUSTOM_BINARY")

        sensitive_patterns = ["TOKEN", "KEY", "SECRET", "PASSWORD", "CREDENTIAL"]
        for key in self.env_vars.keys():
            if any(pattern in key.upper() for pattern in sensitive_patterns):
                factors.append("SENSITIVE_ENV_VARS")
                break

        if "filesystem" in self.name.lower():
            factors.append("FILE_SYSTEM_ACCESS")

        if any(db in self.name.lower() for db in ["postgres", "mysql", "redis", "mongo"]):
            factors.append("DATABASE_ACCESS")

        if self.url:
            factors.append("EXTERNAL_URL")

        if "github" in self.name.lower():
            factors.append("CODE_REPOSITORY_ACCESS")

        if any(tool in self.name.lower() for tool in ["playwright", "mobile"]):
            factors.append("AUTOMATION_CAPABILITY")

        return factors

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for CSV export."""
        # Mask sensitive environment variables
        masked_env = {}
        for key, value in self.env_vars.items():
            if any(pattern in key.upper() for pattern in ["TOKEN", "KEY", "SECRET", "PASSWORD"]):
                masked_env[key] = value[:10] + "..." if len(value) > 10 else "***"
            else:
                masked_env[key] = value

        # Get username cross-platform (USER on Unix/macOS, USERNAME on Windows)
        username = os.environ.get("USER", os.environ.get("USERNAME", "unknown"))

        return {
            "timestamp": self.discovered_at,
            "server_name": self.name,
            "command": self.command,
            "args": " ".join(self.args),
            "env_vars": json.dumps(masked_env),
            "config_path": self.config_path,
            "url": self.url or "",
            "risk_score": f"{self.risk_score:.2f}",
            "risk_factors": ";".join(self.risk_factors),
            "hostname": socket.gethostname(),
            "user": username,
        }


class MCPDiscovery:
    """Main discovery engine for MCP servers."""

    def __init__(self):
        self.home = Path.home()
        self.platform = platform.system()  # 'Darwin', 'Windows', 'Linux'
        self.config_locations = self._get_config_locations()
        self.discovered_servers: List[MCPServerInfo] = []
        self._processed_configs: set = set()  # Track processed config files to avoid duplicates

    def _get_platform_app_data(self) -> Path:
        """Get the platform-specific application data directory."""
        if self.platform == "Windows":
            # Windows: %APPDATA% (typically C:\Users\<user>\AppData\Roaming)
            return Path(os.environ.get("APPDATA", self.home / "AppData" / "Roaming"))
        elif self.platform == "Darwin":
            # macOS: ~/Library/Application Support
            return self.home / "Library" / "Application Support"
        else:
            # Linux: ~/.config
            return self.home / ".config"

    def _get_platform_local_app_data(self) -> Path:
        """Get the platform-specific local application data directory."""
        if self.platform == "Windows":
            # Windows: %LOCALAPPDATA% (typically C:\Users\<user>\AppData\Local)
            return Path(os.environ.get("LOCALAPPDATA", self.home / "AppData" / "Local"))
        elif self.platform == "Darwin":
            return self.home / "Library" / "Application Support"
        else:
            return self.home / ".local" / "share"

    def _get_config_locations(self) -> Dict[str, List[Path]]:
        """Define known MCP configuration file locations for all platforms."""
        app_data = self._get_platform_app_data()
        local_app_data = self._get_platform_local_app_data()

        locations = {
            # Anthropic Claude Desktop
            "claude_desktop": [
                # macOS
                self.home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
                # Windows
                app_data / "Claude" / "claude_desktop_config.json",
                local_app_data / "Claude" / "claude_desktop_config.json",
                # Linux
                self.home / ".config" / "claude" / "config.json",
                self.home / ".config" / "Claude" / "claude_desktop_config.json",
                self.home / ".claude" / "config.json",
            ],
            # Claude Code
            "claude_code": [
                # All platforms
                self.home / ".claude" / "settings.json",
                self.home / ".claude.json",
                self.home / ".config" / "claude-code" / "config.json",
                # macOS
                self.home / "Library" / "Application Support" / "Claude Code" / "config.json",
                # Windows
                app_data / "Claude Code" / "config.json",
            ],
            # IDE Extensions - VS Code
            "vscode": [
                # All platforms
                self.home / ".vscode" / "extensions",
                self.home / ".vscode" / "settings.json",
                # Windows specific
                app_data / "Code" / "User" / "settings.json",
                # macOS specific
                self.home / "Library" / "Application Support" / "Code" / "User" / "settings.json",
                # Linux specific
                self.home / ".config" / "Code" / "User" / "settings.json",
            ],
            # Cursor IDE
            "cursor": [
                # macOS
                self.home / "Library" / "Application Support" / "Cursor" / "User" / "globalStorage" / "saoudrizwan.claude-dev" / "settings" / "cline_mcp_settings.json",
                # Windows
                app_data / "Cursor" / "User" / "globalStorage" / "saoudrizwan.claude-dev" / "settings" / "cline_mcp_settings.json",
                # Linux
                self.home / ".config" / "Cursor" / "User" / "globalStorage" / "saoudrizwan.claude-dev" / "settings" / "cline_mcp_settings.json",
                # All platforms
                self.home / ".cursor" / "mcp.json",
                self.home / ".cursor" / "settings.json",
            ],
            # GitHub Copilot
            "copilot": [
                # All platforms
                self.home / ".config" / "github-copilot" / "config.json",
                self.home / ".copilot" / "config.json",
                # macOS
                self.home / "Library" / "Application Support" / "GitHub Copilot" / "config.json",
                # Windows
                app_data / "GitHub Copilot" / "config.json",
                local_app_data / "GitHub Copilot" / "config.json",
            ],
            # OpenAI Codex / ChatGPT
            "openai": [
                # All platforms
                self.home / ".config" / "openai" / "config.json",
                self.home / ".openai" / "config.json",
                self.home / ".config" / "codex" / "config.json",
                # macOS
                self.home / "Library" / "Application Support" / "OpenAI" / "config.json",
                # Windows
                app_data / "OpenAI" / "config.json",
                app_data / "ChatGPT" / "config.json",
            ],
            # Google Gemini CLI
            "gemini": [
                # All platforms
                self.home / ".config" / "gemini" / "config.json",
                self.home / ".gemini" / "config.json",
                self.home / ".config" / "google-ai" / "config.json",
                # macOS
                self.home / "Library" / "Application Support" / "Gemini" / "config.json",
                # Windows
                app_data / "Gemini" / "config.json",
                app_data / "Google" / "Gemini" / "config.json",
            ],
            # Hugging Face
            "huggingface": [
                # All platforms
                self.home / ".cache" / "huggingface" / "mcp_config.json",
                self.home / ".config" / "huggingface" / "config.json",
                self.home / ".huggingface" / "config.json",
                # Windows
                local_app_data / "huggingface" / "config.json",
            ],
            # Continue.dev
            "continue": [
                # All platforms
                self.home / ".continue" / "config.json",
                self.home / ".config" / "continue" / "config.json",
            ],
            # Cody (Sourcegraph)
            "cody": [
                # All platforms
                self.home / ".config" / "cody" / "config.json",
                self.home / ".cody" / "config.json",
                # macOS
                self.home / "Library" / "Application Support" / "Cody" / "config.json",
                # Windows
                app_data / "Cody" / "config.json",
            ],
            # Ollama
            "ollama": [
                # All platforms
                self.home / ".ollama" / "config.json",
                self.home / ".config" / "ollama" / "config.json",
                # Windows
                local_app_data / "Ollama" / "config.json",
            ],
            # Custom/Generic locations
            "custom": [
                self.home / ".config" / "mcp",
                self.home / ".mcp",
                self.home / ".mcp.json",
                self.home / ".config" / "ai-tools" / "mcp.json",
            ]
        }
        return locations

    def discover_all(self) -> List[MCPServerInfo]:
        """Discover all MCP servers from known configuration locations."""
        username = os.environ.get("USER", os.environ.get("USERNAME", "unknown"))
        print(f"[*] Starting MCP server discovery on {socket.gethostname()}")
        print(f"[*] User: {username}")
        print(f"[*] Platform: {self.platform}")
        print(f"[*] Timestamp: {datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')}")
        print("-" * 60)

        # Claude Desktop Configuration
        for config_path in self.config_locations["claude_desktop"]:
            if config_path.exists():
                print(f"[+] Found Claude Desktop config: {config_path}")
                self._parse_claude_desktop_config(config_path)

        # Claude Code Configuration
        for config_path in self.config_locations["claude_code"]:
            if config_path.exists():
                print(f"[+] Found Claude Code config: {config_path}")
                self._parse_generic_json_config(config_path, "Claude Code")

        # VS Code Extensions
        for ext_path in self.config_locations["vscode"]:
            if ext_path.exists():
                if ext_path.is_dir():
                    print(f"[*] Scanning VS Code extensions: {ext_path}")
                    self._scan_vscode_extensions(ext_path)
                elif ext_path.is_file():
                    print(f"[+] Found VS Code settings: {ext_path}")
                    self._parse_generic_json_config(ext_path, "VS Code")

        # Cursor IDE
        for config_path in self.config_locations["cursor"]:
            if config_path.exists():
                print(f"[+] Found Cursor IDE config: {config_path}")
                self._parse_cursor_config(config_path)

        # GitHub Copilot
        for config_path in self.config_locations["copilot"]:
            if config_path.exists():
                print(f"[+] Found GitHub Copilot config: {config_path}")
                self._parse_generic_json_config(config_path, "GitHub Copilot")

        # OpenAI / Codex
        for config_path in self.config_locations["openai"]:
            if config_path.exists():
                print(f"[+] Found OpenAI/Codex config: {config_path}")
                self._parse_generic_json_config(config_path, "OpenAI")

        # Google Gemini CLI
        for config_path in self.config_locations["gemini"]:
            if config_path.exists():
                print(f"[+] Found Gemini CLI config: {config_path}")
                self._parse_generic_json_config(config_path, "Gemini")

        # Hugging Face
        for config_path in self.config_locations["huggingface"]:
            if config_path.exists():
                print(f"[+] Found Hugging Face config: {config_path}")
                self._parse_generic_json_config(config_path, "Hugging Face")

        # Continue.dev
        for config_path in self.config_locations["continue"]:
            if config_path.exists():
                print(f"[+] Found Continue.dev config: {config_path}")
                self._parse_continue_config(config_path)

        # Cody (Sourcegraph)
        for config_path in self.config_locations["cody"]:
            if config_path.exists():
                print(f"[+] Found Cody config: {config_path}")
                self._parse_generic_json_config(config_path, "Cody")

        # Ollama
        for config_path in self.config_locations["ollama"]:
            if config_path.exists():
                print(f"[+] Found Ollama config: {config_path}")
                self._parse_generic_json_config(config_path, "Ollama")

        # Custom locations
        for custom_path in self.config_locations["custom"]:
            if custom_path.exists():
                print(f"[+] Found custom MCP config: {custom_path}")
                if custom_path.is_file():
                    self._parse_generic_mcp_config(custom_path)
                elif custom_path.is_dir():
                    self._scan_directory_for_configs(custom_path)

        print("-" * 60)
        print(f"[*] Total MCP servers discovered: {len(self.discovered_servers)}")

        return self.discovered_servers

    def _parse_claude_desktop_config(self, config_path: Path):
        """Parse Claude Desktop configuration file."""
        # Avoid processing the same config file multiple times
        config_key = str(config_path.resolve())
        if config_key in self._processed_configs:
            return
        self._processed_configs.add(config_key)

        try:
            with open(config_path, 'r') as f:
                config = json.load(f)

            mcp_servers = config.get("mcpServers", {})

            for name, server_config in mcp_servers.items():
                # Handle URL-based servers (like Hugging Face)
                if "url" in server_config:
                    server = MCPServerInfo(
                        name=name,
                        command="",
                        args=[],
                        env_vars={},
                        config_path=str(config_path),
                        url=server_config["url"]
                    )
                else:
                    server = MCPServerInfo(
                        name=name,
                        command=server_config.get("command", ""),
                        args=server_config.get("args", []),
                        env_vars=server_config.get("env", {}),
                        config_path=str(config_path)
                    )

                self.discovered_servers.append(server)
                print(f"    [>] Discovered: {name} (Risk: {server.risk_score:.2f})")

        except json.JSONDecodeError as e:
            print(f"    [!] Error parsing JSON: {e}")
        except Exception as e:
            print(f"    [!] Error reading config: {e}")

    def _parse_cursor_config(self, config_path: Path):
        """Parse Cursor IDE MCP configuration."""
        # Avoid processing the same config file multiple times
        config_key = str(config_path.resolve())
        if config_key in self._processed_configs:
            return
        self._processed_configs.add(config_key)

        try:
            with open(config_path, 'r') as f:
                config = json.load(f)

            # Cursor may have different structure, adapt as needed
            if "mcpServers" in config:
                # Remove from processed so _parse_claude_desktop_config can process it
                self._processed_configs.discard(config_key)
                self._parse_claude_desktop_config(config_path)
            elif isinstance(config, dict):
                for name, server_config in config.items():
                    if isinstance(server_config, dict) and "command" in server_config:
                        server = MCPServerInfo(
                            name=name,
                            command=server_config.get("command", ""),
                            args=server_config.get("args", []),
                            env_vars=server_config.get("env", {}),
                            config_path=str(config_path)
                        )
                        self.discovered_servers.append(server)
                        print(f"    [>] Discovered: {name} (Risk: {server.risk_score:.2f})")

        except Exception as e:
            print(f"    [!] Error reading Cursor config: {e}")

    def _scan_vscode_extensions(self, ext_path: Path):
        """Scan VS Code extensions directory for MCP configurations."""
        try:
            for ext_dir in ext_path.iterdir():
                if ext_dir.is_dir():
                    # Check for MCP config files in extension
                    for config_name in ["mcp.json", "mcp-config.json", "package.json"]:
                        config_file = ext_dir / config_name
                        if config_file.exists():
                            self._parse_vscode_ext_config(config_file, ext_dir.name)
        except Exception as e:
            print(f"    [!] Error scanning VS Code extensions: {e}")

    def _parse_vscode_ext_config(self, config_path: Path, ext_name: str):
        """Parse VS Code extension MCP configuration."""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)

            # Check for MCP server definitions
            if "mcpServers" in config:
                for name, server_config in config["mcpServers"].items():
                    server = MCPServerInfo(
                        name=f"{ext_name}/{name}",
                        command=server_config.get("command", ""),
                        args=server_config.get("args", []),
                        env_vars=server_config.get("env", {}),
                        config_path=str(config_path)
                    )
                    self.discovered_servers.append(server)
                    print(f"    [>] Discovered: {ext_name}/{name} (Risk: {server.risk_score:.2f})")
        except Exception:
            pass  # Silent fail for non-MCP extensions

    def _parse_generic_mcp_config(self, config_path: Path):
        """Parse generic MCP configuration file."""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)

            if "mcpServers" in config:
                self._parse_claude_desktop_config(config_path)
        except Exception as e:
            print(f"    [!] Error reading generic config: {e}")

    def _scan_directory_for_configs(self, dir_path: Path):
        """Scan directory for MCP configuration files."""
        try:
            for file_path in dir_path.rglob("*.json"):
                self._parse_generic_mcp_config(file_path)
        except Exception as e:
            print(f"    [!] Error scanning directory: {e}")

    def _parse_generic_json_config(self, config_path: Path, source_name: str):
        """Parse generic JSON config that might contain MCP servers."""
        # Avoid processing the same config file multiple times
        config_key = str(config_path.resolve())
        if config_key in self._processed_configs:
            return
        self._processed_configs.add(config_key)

        try:
            with open(config_path, 'r') as f:
                config = json.load(f)

            # Check for various MCP server definition patterns
            if "mcpServers" in config:
                # Remove from processed so _parse_claude_desktop_config can process it
                self._processed_configs.discard(config_key)
                self._parse_claude_desktop_config(config_path)
            elif "mcp" in config and isinstance(config["mcp"], dict):
                # Some configs nest MCP under a "mcp" key
                if "servers" in config["mcp"]:
                    for name, server_config in config["mcp"]["servers"].items():
                        server = self._create_server_from_config(name, server_config, config_path, source_name)
                        if server:
                            self.discovered_servers.append(server)
            elif "tools" in config and isinstance(config["tools"], list):
                # Some configs use a "tools" array
                for tool in config["tools"]:
                    if isinstance(tool, dict) and tool.get("type") == "mcp":
                        name = tool.get("name", "unknown")
                        server = self._create_server_from_config(name, tool, config_path, source_name)
                        if server:
                            self.discovered_servers.append(server)
            elif "extensions" in config and isinstance(config["extensions"], dict):
                # Check for MCP in extensions config
                for ext_name, ext_config in config["extensions"].items():
                    if "mcp" in ext_name.lower() or (isinstance(ext_config, dict) and "mcpServers" in ext_config):
                        if isinstance(ext_config, dict) and "mcpServers" in ext_config:
                            for name, srv_config in ext_config["mcpServers"].items():
                                server = self._create_server_from_config(name, srv_config, config_path, source_name)
                                if server:
                                    self.discovered_servers.append(server)

        except json.JSONDecodeError:
            pass  # Not valid JSON
        except Exception as e:
            print(f"    [!] Error reading {source_name} config: {e}")

    def _parse_continue_config(self, config_path: Path):
        """Parse Continue.dev configuration file."""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)

            # Continue.dev has a specific config structure
            if "models" in config:
                for model in config.get("models", []):
                    if isinstance(model, dict) and "provider" in model:
                        # Check if model uses MCP
                        if model.get("useMcp", False) or "mcp" in str(model).lower():
                            server = MCPServerInfo(
                                name=f"continue/{model.get('title', model.get('provider', 'unknown'))}",
                                command=model.get("command", ""),
                                args=model.get("args", []),
                                env_vars=model.get("env", {}),
                                config_path=str(config_path),
                                url=model.get("apiBase", None)
                            )
                            self.discovered_servers.append(server)
                            print(f"    [>] Discovered: continue/{model.get('title', 'model')} (Risk: {server.risk_score:.2f})")

            # Also check for explicit MCP servers
            if "mcpServers" in config:
                self._parse_claude_desktop_config(config_path)

        except Exception as e:
            print(f"    [!] Error reading Continue.dev config: {e}")

    def _create_server_from_config(self, name: str, server_config: dict, config_path: Path, source_name: str) -> Optional[MCPServerInfo]:
        """Create MCPServerInfo from various config formats."""
        try:
            if "url" in server_config:
                server = MCPServerInfo(
                    name=f"{source_name}/{name}",
                    command="",
                    args=[],
                    env_vars={},
                    config_path=str(config_path),
                    url=server_config["url"]
                )
            else:
                server = MCPServerInfo(
                    name=f"{source_name}/{name}" if "/" not in name else name,
                    command=server_config.get("command", server_config.get("cmd", "")),
                    args=server_config.get("args", server_config.get("arguments", [])),
                    env_vars=server_config.get("env", server_config.get("environment", {})),
                    config_path=str(config_path)
                )

            print(f"    [>] Discovered: {server.name} (Risk: {server.risk_score:.2f})")
            return server
        except Exception:
            return None

    def export_to_csv(self, output_path: str = "mcp_inventory.csv"):
        """Export discovered servers to CSV file."""
        if not self.discovered_servers:
            print("[!] No servers to export")
            return

        fieldnames = [
            "timestamp",
            "server_name",
            "command",
            "args",
            "env_vars",
            "config_path",
            "url",
            "risk_score",
            "risk_factors",
            "hostname",
            "user"
        ]

        with open(output_path, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for server in self.discovered_servers:
                writer.writerow(server.to_dict())

        print(f"[+] Exported {len(self.discovered_servers)} servers to {output_path}")

    def export_to_json(self, output_path: str = "mcp_inventory.json"):
        """Export discovered servers to JSON file."""
        if not self.discovered_servers:
            print("[!] No servers to export")
            return

        # Get username cross-platform
        username = os.environ.get("USER", os.environ.get("USERNAME", "unknown"))

        data = {
            "scan_metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "hostname": socket.gethostname(),
                "user": username,
                "platform": self.platform,
                "total_servers": len(self.discovered_servers),
            },
            "servers": [server.to_dict() for server in self.discovered_servers]
        }

        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"[+] Exported {len(self.discovered_servers)} servers to {output_path}")

    def print_summary(self):
        """Print a summary of discovered servers."""
        if not self.discovered_servers:
            print("[!] No MCP servers discovered")
            return

        print("\n" + "=" * 60)
        print("MCP SERVER INVENTORY SUMMARY")
        print("=" * 60)

        # Risk categorization
        high_risk = [s for s in self.discovered_servers if s.risk_score >= 0.5]
        medium_risk = [s for s in self.discovered_servers if 0.3 <= s.risk_score < 0.5]
        low_risk = [s for s in self.discovered_servers if s.risk_score < 0.3]

        print(f"\nRisk Distribution:")
        print(f"  HIGH RISK (>= 0.5):   {len(high_risk)} servers")
        print(f"  MEDIUM RISK (0.3-0.5): {len(medium_risk)} servers")
        print(f"  LOW RISK (< 0.3):      {len(low_risk)} servers")

        if high_risk:
            print(f"\nHIGH RISK SERVERS:")
            for server in high_risk:
                print(f"  - {server.name}: {server.risk_score:.2f}")
                print(f"    Risk Factors: {', '.join(server.risk_factors)}")

        print(f"\nAll Discovered Servers:")
        for i, server in enumerate(self.discovered_servers, 1):
            print(f"  {i}. {server.name}")
            print(f"     Command: {server.command or server.url}")
            print(f"     Risk Score: {server.risk_score:.2f}")
            if server.risk_factors:
                print(f"     Risk Factors: {', '.join(server.risk_factors)}")
            print()


def main():
    """Main entry point for MCP discovery tool."""
    print("=" * 60)
    print("STRIDER - MCP Discovery Tool")
    print("Endpoint Core Agent Component")
    print("=" * 60)
    print()

    discovery = MCPDiscovery()

    # Discover all MCP servers
    servers = discovery.discover_all()

    # Print summary
    discovery.print_summary()

    # Export to CSV and JSON - output directory relative to this script
    output_dir = Path(__file__).parent / "output"
    output_dir.mkdir(exist_ok=True)

    csv_path = output_dir / "mcp_inventory.csv"
    json_path = output_dir / "mcp_inventory.json"

    discovery.export_to_csv(str(csv_path))
    discovery.export_to_json(str(json_path))

    print(f"\n[*] Discovery complete. Check {output_dir} for results.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
