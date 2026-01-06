import subprocess
import sys
from typing import Dict, Any


class PentestingTools:
    """Pentesting tools wrapper with real-time output streaming"""
    
    @staticmethod
    def run_command(command: list, stream_output=True) -> Dict[str, Any]:
        """
        Execute a system command with optional real-time output
        
        Args:
            command: List with command and arguments
            stream_output: If True, displays output in real-time
            
        Returns:
            Dict with success status, output, and error messages
        """
        try:
            if stream_output:
                # Streaming mode: show output as it executes
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                    universal_newlines=True
                )
                
                stdout_lines = []
                stderr_lines = []
                
                # Read stdout in real-time
                for line in process.stdout:
                    print(line, end='')
                    sys.stdout.flush()
                    stdout_lines.append(line)
                
                # Wait for completion
                process.wait()
                
                # Read stderr if any
                stderr = process.stderr.read()
                if stderr:
                    print(stderr, file=sys.stderr)
                    stderr_lines.append(stderr)
                
                stdout = ''.join(stdout_lines)
                stderr = ''.join(stderr_lines)
                
                return {
                    "success": process.returncode == 0,
                    "output": stdout,
                    "error": stderr
                }
            else:
                # Standard mode: wait and return all at once
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                return {
                    "success": result.returncode == 0,
                    "output": result.stdout,
                    "error": result.stderr
                }
                
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "output": "",
                "error": "Timeout: command exceeded 5 minutes"
            }
        except Exception as e:
            return {
                "success": False,
                "output": "",
                "error": str(e)
            }
    
    def nmap(self, args: list) -> str:
        """Execute nmap with arguments defined by the LLM"""
        command = ["nmap"] + args
        print(f"🔍 Running: {' '.join(command)}\n")
        result = self.run_command(command, stream_output=True)
        return result["output"] if result["success"] else f"Error: {result['error']}"

    def gobuster(self, args: list) -> str:
        """Execute gobuster with arguments defined by the LLM"""
        command = ["gobuster"] + args
        print(f"📂 Running: {' '.join(command)}\n")
        result = self.run_command(command, stream_output=True)
        return result["output"] if result["success"] else f"Error: {result['error']}"
    
    def whatweb(self, args: list) -> str:
        """Execute whatweb with arguments defined by the LLM"""
        command = ["whatweb"] + args
        print(f"🌐 Running: {' '.join(command)}\n")
        result = self.run_command(command, stream_output=True)
        return result["output"] if result["success"] else f"Error: {result['error']}"
    
    def nikto(self, args: list) -> str:
        """Execute nikto web scanner for vulnerability detection"""
        command = ["nikto"] + args
        print(f"🔎 Running: {' '.join(command)}\n")
        result = self.run_command(command, stream_output=True)
        return result["output"] if result["success"] else f"Error: {result['error']}"
    
    def enum4linux(self, args: list) -> str:
        """Execute enum4linux for SMB/Windows enumeration"""
        command = ["enum4linux"] + args
        print(f"🪟 Running: {' '.join(command)}\n")
        result = self.run_command(command, stream_output=True)
        return result["output"] if result["success"] else f"Error: {result['error']}"
    
    def smbclient(self, args: list) -> str:
        """Execute smbclient to interact with SMB shares"""
        command = ["smbclient"] + args
        print(f"📁 Running: {' '.join(command)}\n")
        result = self.run_command(command, stream_output=True)
        return result["output"] if result["success"] else f"Error: {result['error']}"
    
    def ftp(self, args: list) -> str:
        """Execute ftp client to test FTP access"""
        command = ["ftp"] + args
        print(f"📤 Running: {' '.join(command)}\n")
        result = self.run_command(command, stream_output=True)
        return result["output"] if result["success"] else f"Error: {result['error']}"
    
    def ssh(self, args: list) -> str:
        """Execute ssh commands for SSH enumeration"""
        command = ["ssh"] + args
        print(f"🔑 Running: {' '.join(command)}\n")
        result = self.run_command(command, stream_output=True)
        return result["output"] if result["success"] else f"Error: {result['error']}"
    
    def hydra(self, args: list) -> str:
        """Execute hydra for password brute-forcing (use responsibly)"""
        command = ["hydra"] + args
        print(f"🔓 Running: {' '.join(command)}\n")
        result = self.run_command(command, stream_output=True)
        return result["output"] if result["success"] else f"Error: {result['error']}"
    
    def searchsploit(self, args: list) -> str:
        """Search exploit database for known vulnerabilities"""
        command = ["searchsploit"] + args
        print(f"💣 Running: {' '.join(command)}\n")
        result = self.run_command(command, stream_output=True)
        return result["output"] if result["success"] else f"Error: {result['error']}"
    
    def nc(self, args: list) -> str:
        """Execute netcat for manual service interaction"""
        command = ["nc"] + args
        print(f"🔌 Running: {' '.join(command)}\n")
        result = self.run_command(command, stream_output=True)
        return result["output"] if result["success"] else f"Error: {result['error']}"
    
    def get_tool_definitions(self) -> list:
        """Define available tools for LLM function calling"""
        return [
            {
                "type": "function",
                "function": {
                    "name": "nmap",
                    "description": (
                        "Execute nmap port scanner. Use for initial scan AND service-specific scripts. "
                        "Initial scan: ['-sV', '-sC', '-T4', '10.10.10.5'] "
                        "FTP scripts: ['--script', 'ftp-anon,ftp-bounce', '-p21', 'TARGET'] "
                        "SMB scripts: ['--script', 'smb-enum-*', '-p445', 'TARGET'] "
                        "SSH scripts: ['--script', 'ssh-auth-methods', '-p22', 'TARGET'] "
                        "MySQL scripts: ['--script', 'mysql-*', '-p3306', 'TARGET'] "
                        "All scripts: ['--script', 'vuln', '-p', 'PORT', 'TARGET'] "
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "List of nmap arguments. Target must be last element. Use --script for service-specific enumeration."
                            }
                        },
                        "required": ["args"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "gobuster",
                    "description": (
                        "Web directory enumeration. ONLY use if HTTP/HTTPS service is confirmed on ports 80, 443, 8080, 8443, etc. "
                        "DO NOT use on FTP, SSH, SMB, or database services. "
                        "Requires: ['dir', '-u', 'http://TARGET:PORT', '-w', '/usr/share/wordlists/dirb/common.txt', '-t', '50'] "
                        "⚠️ This tool is EXCLUSIVELY for web servers. If the service is not HTTP/HTTPS, DO NOT use this tool."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Gobuster arguments. ONLY use if you confirmed HTTP/HTTPS service."
                            }
                        },
                        "required": ["args"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "whatweb",
                    "description": (
                        "Web technology fingerprinting. ONLY use if HTTP/HTTPS service is confirmed. "
                        "DO NOT use on FTP, SSH, SMB, or database services. "
                        "Use BEFORE gobuster to identify CMS/frameworks. "
                        "Requires: ['-a', '3', 'http://TARGET:PORT'] "
                        "⚠️ This tool is EXCLUSIVELY for web servers."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Whatweb arguments. ONLY use if you confirmed HTTP/HTTPS service."
                            }
                        },
                        "required": ["args"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "nikto",
                    "description": (
                        "Web vulnerability scanner. ONLY use if HTTP/HTTPS service is confirmed. "
                        "DO NOT use on non-web services. Use AFTER whatweb and gobuster. "
                        "Requires: ['-h', 'TARGET', '-p', 'PORT'] "
                        "⚠️ This tool is EXCLUSIVELY for web servers."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Nikto arguments. ONLY use if you confirmed HTTP/HTTPS service."
                            }
                        },
                        "required": ["args"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "enum4linux",
                    "description": (
                        "SMB/Windows enumeration. ONLY use if SMB (port 445) or NetBIOS (port 139) is open. "
                        "DO NOT use on FTP, HTTP, SSH, or other services. "
                        "Extracts users, shares, groups, policies from Windows/Samba targets. "
                        "Use: ['-a', 'TARGET'] for complete enumeration. "
                        "⚠️ This tool is EXCLUSIVELY for SMB/NetBIOS services."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "enum4linux arguments. ONLY use if you confirmed SMB/NetBIOS service."
                            }
                        },
                        "required": ["args"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "smbclient",
                    "description": (
                        "SMB client to interact with shares. ONLY use if SMB (port 445) is open. "
                        "DO NOT use on other services. Use AFTER enum4linux. "
                        "List shares: ['-L', '//TARGET', '-N'] (-N for anonymous) "
                        "⚠️ This tool is EXCLUSIVELY for SMB services."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "smbclient arguments. ONLY use if you confirmed SMB service."
                            }
                        },
                        "required": ["args"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "searchsploit",
                    "description": (
                        "Search exploit-db for known vulnerabilities. Use AFTER identifying service versions. "
                        "Search by service name and version. Returns exploit codes and descriptions. "
                        "Example: ['apache 2.4.18'] or ['openssh 7.2']"
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Search terms. Service name and version."
                            }
                        },
                        "required": ["args"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "nc",
                    "description": (
                        "Netcat for manual service interaction and banner grabbing. "
                        "Useful for unknown services or manual testing. "
                        "Banner grab: ['-nv', '10.10.10.5', '21'] (connects to port 21). "
                        "Example: ['-nv', '10.10.10.5', '9999']"
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Netcat arguments. Include target IP and port."
                            }
                        },
                        "required": ["args"]
                    }
                }
            }
        ]