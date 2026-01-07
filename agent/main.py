import ollama
import json
from tools import PentestingTools


# ANSI color codes
class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


class HTBAgent:
    def __init__(self, reasoning_model="deepseek-r1:7b", executor_model="llama3.2"):
        """
        Dual-model HTB pentesting agent with EXECUTOR-FIRST architecture
        
        Args:
            reasoning_model: Model for strategic thinking and decision-making
            executor_model: Model for tool execution and tactical operations
        """
        self.reasoning_model = reasoning_model
        self.executor_model = executor_model
        self.tools = PentestingTools()
        
        # Separate conversation histories for each model
        self.reasoning_history = []
        self.executor_history = []
        
        # Shared knowledge base
        self.discovered_services = []
        self.findings = []
        self.completed_actions = []
        self.downloaded_files = []
        
        # System prompts for each model
        self.reasoning_prompt = """You are a methodical penetration testing strategist.

Your job is to analyze tool outputs and determine the logical next step in the enumeration process.
DO NOT REPEAT COMMANDS ITERATIONS, YOUR OBJECTIVE IS TO OBTAIN THE FLAG AS EFFICIENTLY AS POSSIBLE.

CRITICAL RULES:

1. TOOL-TO-SERVICE MATCHING (STRICT)
   - enum4linux is ONLY for SMB (ports 445/139) - NEVER for FTP
   - smbclient is ONLY for SMB (ports 445/139) - NEVER for FTP
   - ftp tool is ONLY for FTP (port 21) - NEVER for other services
   - whatweb/gobuster/nikto are ONLY for HTTP/HTTPS (ports 80/443/8080/8443)
   
   If you suggest a tool for the wrong service, the system will fail.

2. FTP ENUMERATION SEQUENCE (port 21 only)
   Phase 1: Initial nmap scan discovers port 21
   Phase 2: Run nmap --script ftp-anon to check anonymous access
   Phase 3: If anonymous works + files visible -> Use ftp tool to download files
   Phase 4: After download -> Use cat to read file contents
   Phase 5: FTP complete -> Move to next service
   
   Example FTP progression:
   - "Port 21 open" -> next_step: "nmap" with ftp-anon script
   - "ftp-anon shows flag.txt" -> next_step: "ftp" to download
   - "Downloaded flag.txt" -> next_step: "cat" to read
   - "Read flag content" -> FTP complete

3. OUTPUT FORMAT - MUST BE VALID JSON

   {
     "understanding": "Brief summary of current state",
     "next_step": "exact_tool_name",
     "rationale": "One sentence why this tool",
     "target": "service:21 or file:flag.txt",
     "status": "continue"
   }
   
   Valid tool names: nmap, ftp, cat, gobuster, whatweb, nikto, enum4linux, smbclient, searchsploit, nc
   
   IMPORTANT: Your JSON must be complete and valid. Do not truncate any fields.

4. EVIDENCE-BASED ONLY
   Only suggest tools for services that are shown as "open" in scan results.
   Port not discovered = Don't use tools for it.

5. WORKFLOW UNDERSTANDING
   Ask yourself: What phase am I in? What's the next logical step?
   
   If last tool was "nmap ftp-anon" and it showed files -> Use "ftp" tool
   If last tool was "ftp" and downloaded file -> Use "cat" tool
   If last tool was "cat" and read contents -> Mark service complete

Return ONLY valid, complete JSON. Ensure all fields are properly closed with quotes."""

        self.executor_prompt = """You are a tactical pentesting executor.

Your job is to translate strategic decisions into precise tool commands.

You have access to these tools:
- nmap: Port scanning and service detection
- ftp: FTP client for file operations
- gobuster: Web directory enumeration
- whatweb: Web technology fingerprinting
- nikto: Web vulnerability scanner
- enum4linux: SMB/Windows enumeration
- smbclient: SMB share interaction
- searchsploit: Exploit database search
- nc: Service interaction and banner grabbing
- cat: Read file contents

EXECUTION RULES:

1. Always use function calling - never return JSON manually
2. Match the tool to the strategic instruction
3. Include target in arguments
4. Use correct argument formats

Common patterns:
- nmap initial scan: ["-sV", "-T4", "TARGET"]
- nmap ftp-anon: ["--script", "ftp-anon", "-p21", "TARGET"]
- ftp list: ["TARGET", ["ls"], "anonymous", "anonymous"]
- ftp download: ["TARGET", ["get filename"], "anonymous", "anonymous"]
- cat file: ["filename"]
- whatweb: ["-a", "3", "http://TARGET"]
- gobuster: ["dir", "-u", "http://TARGET", "-w", "/usr/share/wordlists/dirb/common.txt"]
- enum4linux: ["-a", "TARGET"]
- nc banner: ["-nv", "TARGET", "PORT"]

Call the appropriate function with correct arguments now."""

    def executor_agent_execute(self, instruction: str, target: str) -> dict:
        """
        Executor model executes a tool based on instructions
        
        Args:
            instruction: What to execute
            target: Target IP address
            
        Returns:
            Execution plan with tool and arguments
        """
        prompt = f"""Execute this task on target {target}:

{instruction}

Call the appropriate function with correct arguments."""

        self.executor_history.append({
            "role": "user",
            "content": prompt
        })
        
        try:
            response = ollama.chat(
                model=self.executor_model,
                messages=[
                    {"role": "system", "content": self.executor_prompt}
                ] + self.executor_history,
                tools=self.tools.get_tool_definitions(),
            )
            
            message = response['message']
            
            if message.get('tool_calls'):
                tool_call = message['tool_calls'][0]
                tool_name = tool_call['function']['name']
                tool_args = tool_call['function']['arguments']
                
                args = tool_args.get('args', [])
                
                self.executor_history.append({
                    "role": "assistant",
                    "content": message.get('content', ''),
                    "tool_calls": message.get('tool_calls')
                })
                
                return {
                    "tool": tool_name,
                    "args": args,
                    "explanation": f"Function calling: {tool_name}"
                }
            else:
                content = message.get('content', '')
                tool = self._infer_tool_from_instruction(instruction)
                return {
                    "tool": tool,
                    "args": self._get_default_args(tool, target),
                    "explanation": "Fallback execution"
                }
            
        except Exception as e:
            print(f"{Colors.RED}ERROR in executor agent: {e}{Colors.ENDC}")
            tool = self._infer_tool_from_instruction(instruction)
            return {
                "tool": tool,
                "args": self._get_default_args(tool, target),
                "explanation": f"Error fallback: {str(e)}"
            }

    def reasoning_agent_analyze(self, execution_result: str, tool_used: str, iteration: int) -> dict:
        """
        Reasoning model analyzes execution results and decides next action
        
        Args:
            execution_result: Output from the last tool execution
            tool_used: Name of the tool that was just executed
            iteration: Current iteration number
            
        Returns:
            Strategic decision with next action
        """
        # Build enumeration state summary
        state_summary = self._build_enumeration_state()
        
        # Extract key information from last execution
        key_info = self._extract_key_info(execution_result, tool_used)
        
        prompt = f"""ITERATION {iteration}

LAST TOOL: {tool_used}

KEY FINDINGS FROM OUTPUT:
{key_info}

ENUMERATION STATE:
{state_summary}

Based on this information, what is the next logical step?

Think through the workflow:
- If you just ran nmap and found FTP with files -> Use ftp tool to download
- If you just downloaded a file with ftp -> Use cat to read it
- If you just read a file -> Move to next service or complete

Respond with ONLY valid JSON. Ensure all JSON fields are complete and properly quoted."""

        self.reasoning_history.append({
            "role": "user",
            "content": prompt
        })
        
        try:
            response = ollama.chat(
                model=self.reasoning_model,
                messages=[
                    {"role": "system", "content": self.reasoning_prompt}
                ] + self.reasoning_history,
                format="json"  # Force JSON output
            )
            
            content = response['message']['content']
            self.reasoning_history.append({
                "role": "assistant",
                "content": content
            })
            
            # Clean and parse JSON
            content = content.strip()
            
            # Remove any markdown artifacts
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]
            
            # Try to extract valid JSON
            start_idx = content.find('{')
            end_idx = content.rfind('}')
            
            if start_idx == -1 or end_idx == -1:
                raise ValueError("No JSON object found in response")
            
            content = content[start_idx:end_idx+1]
            
            # Attempt to parse
            decision = json.loads(content)
            
            # Validate required fields
            if "next_step" not in decision:
                raise ValueError("Missing required field: next_step")
            
            # Validate tool choice matches service
            next_tool = decision.get("next_step", "")
            target = decision.get("target", "")
            
            # Check for invalid tool-service combinations
            if next_tool == "enum4linux" and "ftp" in target.lower():
                print(f"{Colors.YELLOW}WARNING: Model suggested enum4linux for FTP. Correcting to ftp tool.{Colors.ENDC}")
                decision["next_step"] = "ftp"
                decision["rationale"] = "Download files from FTP (corrected from invalid enum4linux suggestion)"
            
            if next_tool == "smbclient" and "ftp" in target.lower():
                print(f"{Colors.YELLOW}WARNING: Model suggested smbclient for FTP. Correcting to ftp tool.{Colors.ENDC}")
                decision["next_step"] = "ftp"
                decision["rationale"] = "Download files from FTP (corrected from invalid smbclient suggestion)"
            
            # Extract discovered services if provided
            if "discovered_services" in decision:
                for service in decision["discovered_services"]:
                    if service not in self.discovered_services:
                        self.discovered_services.append(service)
            
            return decision
            
        except json.JSONDecodeError as e:
            print(f"{Colors.RED}WARNING: Failed to parse JSON: {e}{Colors.ENDC}")
            print(f"Raw response: {content[:500]}")
            
            # Retry with more explicit instructions
            self.reasoning_history.append({
                "role": "user",
                "content": f"Your last response had invalid JSON. Error: {str(e)}. Please respond with ONLY a valid JSON object with fields: understanding, next_step, rationale, target, status. Ensure all strings are properly quoted and the JSON is complete."
            })
            
            try:
                response = ollama.chat(
                    model=self.reasoning_model,
                    messages=[
                        {"role": "system", "content": self.reasoning_prompt}
                    ] + self.reasoning_history,
                    format="json"
                )
                
                content = response['message']['content'].strip()
                start_idx = content.find('{')
                end_idx = content.rfind('}')
                
                if start_idx != -1 and end_idx != -1:
                    content = content[start_idx:end_idx+1]
                    decision = json.loads(content)
                    return decision
            except:
                pass
            
            # Final fallback: infer from context
            print(f"{Colors.YELLOW}Using fallback decision based on context{Colors.ENDC}")
            return self._create_fallback_decision(tool_used, execution_result)
            
        except Exception as e:
            print(f"{Colors.RED}ERROR in reasoning agent: {e}{Colors.ENDC}")
            return self._create_fallback_decision(tool_used, execution_result)

    def _extract_key_info(self, output: str, tool: str) -> str:
        """Extract key information from tool output"""
        lines = []
        
        if tool == "nmap":
            lines.append("Open ports and services:")
            for line in output.split('\n'):
                if 'open' in line.lower() or 'ftp-anon' in line.lower() or '.txt' in line:
                    lines.append(f"  {line.strip()}")
        
        elif tool == "ftp":
            if "226" in output or "successfully" in output.lower():
                lines.append("FTP operation completed successfully")
            if "flag" in output.lower():
                lines.append("Flag-related content detected")
        
        elif tool == "cat":
            lines.append("File contents:")
            lines.append(f"  {output[:200]}")
        
        return "\n".join(lines) if lines else output[:500]

    def _create_fallback_decision(self, last_tool: str, last_output: str) -> dict:
        """Create a reasonable fallback decision when reasoning fails"""
        
        # If we just ran nmap and see FTP files, download them
        if last_tool == "nmap" and "flag.txt" in last_output.lower():
            return {
                "understanding": "Fallback: FTP files detected",
                "next_step": "ftp",
                "rationale": "Download visible files from FTP",
                "target": "ftp:21",
                "status": "continue"
            }
        
        # If we just used FTP, read the downloaded files
        if last_tool == "ftp" and any(f in self.downloaded_files for f in ["flag.txt"]):
            return {
                "understanding": "Fallback: Files downloaded",
                "next_step": "cat",
                "rationale": "Read downloaded file contents",
                "target": "file:flag.txt",
                "status": "continue"
            }
        
        # If we just read a file, mark complete
        if last_tool == "cat":
            return {
                "understanding": "Fallback: File contents read",
                "next_step": "complete",
                "rationale": "Enumeration complete",
                "target": "none",
                "status": "complete"
            }
        
        # Default: mark as error
        return {
            "understanding": "Fallback: Unable to determine next step",
            "next_step": "error",
            "rationale": "Reasoning failed",
            "target": "none",
            "status": "error"
        }

    def _build_enumeration_state(self) -> str:
        """Build a clear summary of enumeration progress"""
        lines = []
        
        lines.append("Discovered Services:")
        if self.discovered_services:
            for svc in self.discovered_services:
                lines.append(f"  - {svc}")
        else:
            lines.append("  - None yet")
        
        lines.append("\nCompleted Actions:")
        if self.completed_actions:
            for action in self.completed_actions:
                args_preview = str(action['args'])[:60]
                lines.append(f"  {action['iteration']}. {action['tool']} -> {args_preview}")
        else:
            lines.append("  - None yet")
        
        lines.append("\nDownloaded Files:")
        if self.downloaded_files:
            for f in self.downloaded_files:
                lines.append(f"  - {f}")
        else:
            lines.append("  - None yet")
        
        return "\n".join(lines)

    def _infer_tool_from_instruction(self, instruction: str) -> str:
        """Infer which tool to use from instruction text"""
        instruction_lower = instruction.lower()
        if "cat" in instruction_lower or "read" in instruction_lower:
            return "cat"
        elif "nmap" in instruction_lower or "initial" in instruction_lower or "scan" in instruction_lower:
            return "nmap"
        elif "ftp" in instruction_lower:
            return "ftp"
        elif "gobuster" in instruction_lower:
            return "gobuster"
        elif "whatweb" in instruction_lower:
            return "whatweb"
        elif "nikto" in instruction_lower:
            return "nikto"
        elif "enum4linux" in instruction_lower:
            return "enum4linux"
        elif "smbclient" in instruction_lower:
            return "smbclient"
        elif "searchsploit" in instruction_lower:
            return "searchsploit"
        elif "nc" in instruction_lower or "netcat" in instruction_lower:
            return "nc"
        else:
            return "nmap"

    def _get_default_args(self, tool: str, target: str) -> list:
        """Provide sensible default arguments for each tool"""
        defaults = {
            "nmap": ["-sV", "-sC", "-T4", target],
            "ftp": [target, ["ls"], "anonymous", "anonymous"],
            "cat": ["flag.txt"],
            "gobuster": ["dir", "-u", f"http://{target}", "-w", "/usr/share/wordlists/dirb/common.txt", "-t", "50"],
            "whatweb": ["-a", "3", f"http://{target}"],
            "nikto": ["-h", target],
            "enum4linux": ["-a", target],
            "smbclient": ["-L", f"//{target}", "-N"],
            "searchsploit": [target],
            "nc": ["-nv", target, "80"]
        }
        return defaults.get(tool, [target])

    def execute_tool(self, tool_name: str, arguments: list) -> str:
        """Execute the actual pentesting tool"""
        tool_map = {
            "nmap": self.tools.nmap,
            "ftp": self.tools.ftp,
            "cat": self.tools.cat,
            "gobuster": self.tools.gobuster,
            "whatweb": self.tools.whatweb,
            "nikto": self.tools.nikto,
            "enum4linux": self.tools.enum4linux,
            "smbclient": self.tools.smbclient,
            "searchsploit": self.tools.searchsploit,
            "nc": self.tools.nc
        }
        
        if tool_name not in tool_map:
            return f"Error: Unknown tool '{tool_name}'"
        
        try:
            result = tool_map[tool_name](args=arguments)
            
            # Track downloaded files
            if tool_name == "ftp" and "get" in str(arguments).lower():
                for arg in arguments:
                    if isinstance(arg, list):
                        for cmd in arg:
                            if "get" in cmd.lower():
                                filename = cmd.split()[-1] if len(cmd.split()) > 1 else "unknown"
                                if filename not in self.downloaded_files:
                                    self.downloaded_files.append(filename)
            
            return result
        except Exception as e:
            return f"Error executing {tool_name}: {str(e)}"

    def run(self, target: str):
        """
        Run dual-model autonomous pentesting agent
        
        Args:
            target: Target IP address
        """
        print(f"""
{'='*80}
DUAL-MODEL HTB PENTESTING AGENT
{'='*80}

Target: {target}
Reasoning Model: {self.reasoning_model}
Executor Model: {self.executor_model}

{'='*80}
""")
        
        max_iterations = 25
        
        # ITERATION 0: EXECUTOR STARTS WITH INITIAL NMAP
        print(f"\n{'─'*80}")
        print(f"ITERATION 0: INITIAL RECONNAISSANCE")
        print(f"{'─'*80}\n")
        
        print(f"{Colors.GREEN}EXECUTOR MODEL: Starting with initial nmap scan{Colors.ENDC}\n")
        
        execution = self.executor_agent_execute(
            instruction="Perform initial nmap scan with service version detection and default scripts",
            target=target
        )
        
        print(f"{Colors.GREEN}Tool: {execution.get('tool')}")
        print(f"Arguments: {execution.get('args')}{Colors.ENDC}\n")
        
        tool = execution.get('tool')
        args = execution.get('args', [])
        
        result = self.execute_tool(tool, args)
        
        self.completed_actions.append({
            "iteration": 0,
            "tool": tool,
            "args": args
        })
        
        # Parse services
        if "open" in result.lower():
            for line in result.split('\n'):
                if "/tcp" in line or "/udp" in line:
                    self.discovered_services.append(line.strip())
        
        # MAIN LOOP
        for iteration in range(1, max_iterations + 1):
            print(f"\n{'─'*80}")
            print(f"ITERATION {iteration}/{max_iterations}")
            print(f"{'─'*80}\n")
            
            # REASONING analyzes
            print(f"{Colors.BLUE}REASONING MODEL: Analyzing results{Colors.ENDC}\n")
            decision = self.reasoning_agent_analyze(result, tool, iteration)
            
            if decision.get("status") == "complete":
                print(f"\n{'='*80}")
                print("RECONNAISSANCE COMPLETE")
                print(f"{'='*80}\n")
                print(f"{Colors.BLUE}Understanding: {decision.get('understanding', 'N/A')}{Colors.ENDC}")
                break
            
            if decision.get("status") == "error":
                print(f"{Colors.RED}ERROR: Reasoning model error. Stopping.{Colors.ENDC}")
                break
            
            print(f"{Colors.BLUE}Understanding: {decision.get('understanding', 'N/A')[:300]}")
            print(f"Next Step: {decision.get('next_step', 'N/A')}")
            print(f"Rationale: {decision.get('rationale', 'N/A')[:300]}")
            print(f"Target: {decision.get('target', 'N/A')}{Colors.ENDC}\n")
            
            # EXECUTOR executes
            print(f"{Colors.GREEN}EXECUTOR MODEL: Preparing command{Colors.ENDC}\n")
            
            instruction = f"Execute {decision.get('next_step')} for {decision.get('target')}. {decision.get('rationale', '')}"
            execution = self.executor_agent_execute(instruction, target)
            
            print(f"{Colors.GREEN}Tool: {execution.get('tool')}")
            print(f"Arguments: {execution.get('args')}{Colors.ENDC}\n")
            
            tool = execution.get('tool')
            args = execution.get('args', [])
            
            if tool and tool != "error":
                result = self.execute_tool(tool, args)
                
                self.completed_actions.append({
                    "iteration": iteration,
                    "tool": tool,
                    "args": args
                })
            else:
                print(f"{Colors.RED}WARNING: Skipping execution due to error{Colors.ENDC}\n")
                result = "Error in execution"
        
        else:
            print(f"\n{Colors.YELLOW}WARNING: Maximum iterations reached{Colors.ENDC}")
        
        # Summary
        print(f"\n{'='*80}")
        print("EXECUTION SUMMARY")
        print(f"{'='*80}")
        print(f"Total actions: {len(self.completed_actions)}")
        print(f"Services found: {len(self.discovered_services)}")
        print(f"Files downloaded: {len(self.downloaded_files)}")
        print(f"{'='*80}\n")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python main.py <target_ip>")
        sys.exit(1)
    
    target = sys.argv[1]
    
    parts = target.split('.')
    if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        print(f"ERROR: Invalid IP address format: {target}")
        sys.exit(1)
    
    agent = HTBAgent(
        reasoning_model="deepseek-r1:7b",
        executor_model="llama3.2"
    )
    
    agent.run(target)