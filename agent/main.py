import ollama
import json
from tools import PentestingTools


class HTBAgent:
    def __init__(self, model="deepseek-r1"):
        self.model = model
        self.tools = PentestingTools()
        self.messages = []
        self.findings = []
        self.consecutive_no_tool_calls = 0  # Track when agent stops using tools
        
        # System prompt with detailed decision-making logic
        self.system_prompt = """You are an expert penetration tester and security researcher specializing in CTFs and HackTheBox.

YOUR MISSION: Perform complete reconnaissance and enumeration of the target autonomously.

═══════════════════════════════════════════════════════════════════════════════
PHASE 1: INITIAL RECONNAISSANCE
═══════════════════════════════════════════════════════════════════════════════
Start with nmap to identify ALL open ports and services:
- Use: nmap with ["-sV", "-sC", "-T4", "TARGET"]
- Analyze the output carefully to identify EACH service and version

═══════════════════════════════════════════════════════════════════════════════
PHASE 2: SERVICE-SPECIFIC ENUMERATION
═══════════════════════════════════════════════════════════════════════════════
Based on DISCOVERED services (not assumptions), apply these rules:

┌─────────────────────────────────────────────────────────────────────────────┐
│ IF PORT 21 (FTP) IS OPEN:                                                  │
│ 1. Try anonymous FTP login: nmap with ["--script", "ftp-anon", "-p21", "TARGET"]
│ 2. Check FTP bounce: nmap with ["--script", "ftp-bounce", "-p21", "TARGET"]
│ 3. Search exploits: searchsploit with ["ftp", "VERSION"]                   │
│  DO NOT use gobuster, whatweb, or nikto - these are for HTTP only!      │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ IF PORT 22 (SSH) IS OPEN:                                                  │
│ 1. Note the version for vulnerability research                             │
│ 2. Search exploits: searchsploit with ["openssh", "VERSION"]               │
│ 3. Check auth methods: nmap with ["--script", "ssh-auth-methods", "-p22", "TARGET"]
│  DO NOT attempt brute force without explicit permission                  │
│  DO NOT use web tools (gobuster, nikto, whatweb)                        │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ IF PORT 80, 443, 8080, 8443, or other HTTP/HTTPS IS OPEN:                 │
│ 1. FIRST: whatweb with ["-a", "3", "http://TARGET:PORT"]                  │
│ 2. THEN: gobuster with ["dir", "-u", "http://TARGET", "-w", "WORDLIST", "-t", "50"]
│ 3. THEN: nikto with ["-h", "TARGET", "-p", "PORT"]                        │
│ 4. Search exploits based on identified CMS/framework                       │
│   ONLY use these tools if HTTP/HTTPS service is confirmed!              │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ IF PORT 139, 445 (SMB/NetBIOS) IS OPEN:                                   │
│ 1. FIRST: enum4linux with ["-a", "TARGET"]                                │
│ 2. THEN: smbclient with ["-L", "//TARGET", "-N"]                          │
│ 3. Try null session: smbclient with ["//TARGET/IPC$", "-N"]               │
│ 4. Search exploits: searchsploit with ["smb", "windows"]                  │
│  DO NOT use web tools (gobuster, whatweb, nikto)                        │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ IF PORT 3306 (MySQL), 5432 (PostgreSQL), 1433 (MSSQL) IS OPEN:            │
│ 1. Note the version                                                        │
│ 2. Search exploits: searchsploit with ["mysql/postgresql/mssql", "VERSION"]│
│ 3. Use nmap scripts: nmap with ["--script", "mysql-*", "-p3306", "TARGET"]│
│  DO NOT use web tools                                                   │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ FOR UNKNOWN OR NON-STANDARD PORTS:                                         │
│ 1. Use nc for banner grabbing: nc with ["-nv", "TARGET", "PORT"]          │
│ 2. Use nmap service detection: nmap with ["-sV", "-p", "PORT", "TARGET"]  │
│ 3. Search based on identified service                                      │
└─────────────────────────────────────────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════════════════════
CRITICAL DECISION-MAKING RULES:
═══════════════════════════════════════════════════════════════════════════════
1. NEVER use gobuster/whatweb/nikto on non-HTTP services (FTP, SSH, SMB, etc.)
2. NEVER use enum4linux/smbclient on non-SMB services
3. ALWAYS match the tool to the service type
4. If unsure about a service, use nc or nmap scripts first
5. Search exploits ONLY after identifying the exact service version
6. Work through services ONE AT A TIME methodically

═══════════════════════════════════════════════════════════════════════════════
REASONING FORMAT (MANDATORY):
═══════════════════════════════════════════════════════════════════════════════
Before EVERY action, state:
"I found [SERVICE] on port [PORT]. According to my methodology, for [SERVICE] I should use [TOOL] because [REASON]. I will NOT use [WRONG_TOOLS] as they are for [OTHER_SERVICE_TYPES]."

Example good reasoning:
"I found FTP on port 21. According to my methodology, for FTP I should test anonymous login using nmap ftp-anon script. I will NOT use gobuster or whatweb as those are exclusively for HTTP services."

Example bad reasoning (AVOID):
"I found FTP on port 21. I'll use gobuster to enumerate directories."  ❌ WRONG!

═══════════════════════════════════════════════════════════════════════════════
COMPLETION CRITERIA:
═══════════════════════════════════════════════════════════════════════════════
Provide final report when:
- ALL discovered services have been enumerated with appropriate tools
- Exploit searches completed for all services with identified versions
- No more service-appropriate tools remain to use

FINAL REPORT MUST INCLUDE:
- List of all services and versions
- Enumeration results per service
- Found vulnerabilities or interesting findings
- Recommended attack vectors based on findings

Available tools: nmap, gobuster, whatweb, nikto, enum4linux, smbclient, searchsploit, nc"""
    
    def call_tool(self, tool_name: str, arguments: dict) -> str:
        """Execute a pentesting tool and return results"""
        
        # Map function names to methods
        tool_map = {
            "nmap": self.tools.nmap,
            "gobuster": self.tools.gobuster,
            "whatweb": self.tools.whatweb,
            "nikto": self.tools.nikto,
            "enum4linux": self.tools.enum4linux,
            "smbclient": self.tools.smbclient,
            "searchsploit": self.tools.searchsploit
            #"nc": self.tools.nc
        }
        
        if tool_name not in tool_map:
            return f"Error: tool '{tool_name}' not found"
        
        try:
            # Execute the function with arguments
            result = tool_map[tool_name](**arguments)
            
            # Store findings
            self.findings.append({
                "tool": tool_name,
                "arguments": arguments,
                "result": result[:1000]  # Store first 1000 chars for summary
            })
            
            return result
        except Exception as e:
            return f"Error executing {tool_name}: {str(e)}"
    
    def run(self, target: str, max_iterations: int = 20):
        """
        Run the autonomous pentesting agent with auto-completion
        
        Args:
            target: Target IP address or hostname
            max_iterations: Maximum iterations (safety limit)
        """
        print(f"\n{'='*80}")
        print(f"HTB AUTONOMOUS AGENT")
        print(f"{'='*80}")
        print(f"Target: {target}")
        print(f"Model: {self.model}")
        print(f"Max iterations: {max_iterations}")
        print(f"{'='*80}\n")
        
        # Initial message
        self.messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": f"Target: {target}\n\nBegin autonomous reconnaissance. When you've exhausted all useful reconnaissance options, provide your final report and STOP."}
        ]
        
        # Agent loop
        for iteration in range(max_iterations):
            print(f"\n{'─'*80}")
            print(f"ITERATION {iteration + 1}/{max_iterations}")
            print(f"{'─'*80}\n")
            
            try:
                # Call LLM with tool calling
                response = ollama.chat(
                    model=self.model,
                    messages=self.messages,
                    tools=self.tools.get_tool_definitions()
                )
                
                # Add assistant's response to history
                self.messages.append(response["message"])
                
                # Check if the model wants to use a tool
                if response["message"].get("tool_calls"):
                    # Reset counter - agent is still working
                    self.consecutive_no_tool_calls = 0
                    
                    tool_calls = response["message"]["tool_calls"]
                    
                    for tool_call in tool_calls:
                        function_name = tool_call["function"]["name"]
                        arguments = tool_call["function"]["arguments"]
                        
                        print(f"AGENT DECISION: Execute {function_name}")
                        print(f"Parameters: {json.dumps(arguments, indent=2)}")
                        print(f"\n{'▼'*80}")
                        print(f"EXECUTING: {function_name.upper()}")
                        print(f"{'▼'*80}\n")
                        
                        # Execute the tool
                        result = self.call_tool(function_name, arguments)
                        
                        # Display full output
                        print(result)
                        print(f"\n{'▲'*80}")
                        print(f"COMPLETED: {function_name.upper()}")
                        print(f"{'▲'*80}\n")
                        
                        # Add result to conversation for analysis
                        self.messages.append({
                            "role": "tool",
                            "content": result
                        })
                
                else:
                    # Model responded without calling tools
                    agent_response = response["message"]["content"]
                    
                    # Increment counter
                    self.consecutive_no_tool_calls += 1
                    
                    # Check if this is final report or reasoning
                    completion_keywords = [
                        "reconnaissance complete",
                        "final report",
                        "summary of findings",
                        "completed analysis",
                        "no more useful",
                        "exhausted",
                        "attack vectors:",
                        "recommended next steps:"
                    ]
                    
                    is_final = any(keyword in agent_response.lower() for keyword in completion_keywords)
                    
                    if is_final or self.consecutive_no_tool_calls >= 2:
                        # Agent has concluded or stopped using tools twice in a row
                        print(f"\n{'='*80}")
                        print(f"FINAL RECONNAISSANCE REPORT")
                        print(f"{'='*80}\n")
                        print(agent_response)
                        print(f"\n{'='*80}")
                        print(f"RECONNAISSANCE COMPLETED")
                        print(f"{'='*80}\n")
                        break
                    else:
                        # Agent is reasoning about next steps
                        print(f"AGENT REASONING:\n")
                        print(agent_response)
                        print()
                        
            except Exception as e:
                print(f"ERROR: {str(e)}")
                import traceback
                traceback.print_exc()
                break
        
        else:
            # Max iterations reached (shouldn't happen often now)
            print(f"\nWARNING: Maximum iterations reached")
            print(f"The agent didn't naturally conclude. This may indicate:")
            print(f"  - Target requires deeper analysis (try --deep)")
            print(f"  - Agent is stuck in a loop")
            print(f"  - More powerful model needed\n")
        
        # Print summary of all actions taken
        print(f"\n{'='*80}")
        print(f"ACTIONS PERFORMED: {len(self.findings)}")
        print(f"{'='*80}")
        for i, finding in enumerate(self.findings, 1):
            print(f"{i}. {finding['tool']} - {finding['arguments']}")
        print(f"{'='*80}\n")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description='HTB Autonomous Pentesting Agent with Auto-Completion',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 10.10.10.5
  %(prog)s scanme.nmap.org --quick
  %(prog)s 192.168.1.100 --deep
  %(prog)s target.htb --model llama3.1:8b

The agent will automatically stop when reconnaissance is complete.
        """
    )
    
    parser.add_argument('target', 
                       help='Target IP address or hostname')
    
    parser.add_argument('--quick', 
                       action='store_true',
                       help='Quick reconnaissance (10 iterations max)')
    
    parser.add_argument('--deep', 
                       action='store_true',
                       help='Deep reconnaissance (30 iterations max)')
    
    parser.add_argument('--iterations', 
                       type=int, 
                       default=20,
                       help='Maximum iterations (default: 20)')
    
    parser.add_argument('--model', 
                       default='llama3.2',
                       help='Ollama model to use (default: llama3.2)')
    
    args = parser.parse_args()
    
    # Determine max iterations
    if args.quick:
        max_iterations = 10
    elif args.deep:
        max_iterations = 30
    else:
        max_iterations = args.iterations
    
    print(f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    HTB AUTONOMOUS PENTESTING AGENT v2.0                      ║
║                         with Auto-Completion Detection                       ║
╚══════════════════════════════════════════════════════════════════════════════╝
""")
    
    # Create and run agent
    agent = HTBAgent(model=args.model)
    agent.run(args.target, max_iterations=max_iterations)
    
    print(f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                           RECONNAISSANCE FINISHED                            ║
╚══════════════════════════════════════════════════════════════════════════════╝
""")