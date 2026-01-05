import subprocess
import sys
from typing import Dict, Any


class PentestingTools:
    """Herramientas de pentesting con schemas para tool calling"""
    
    @staticmethod
    def run_command(command: list, stream_output=True) -> Dict[str, Any]:
        """
        Ejecuta un comando del sistema y muestra salida en tiempo real
        
        Args:
            command: Lista con el comando y sus argumentos
            stream_output: Si True, muestra la salida en tiempo real
        """
        try:
            if stream_output:
                # Modo streaming: muestra mientras ejecuta
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
                
                # Leer stdout en tiempo real
                for line in process.stdout:
                    print(line, end='')  # Mostrar en consola
                    sys.stdout.flush()
                    stdout_lines.append(line)
                
                # Esperar a que termine
                process.wait()
                
                # Leer stderr si hay
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
                # Modo normal: espera y devuelve todo
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
                "error": "Timeout: comando excedió 5 minutos"
            }
        except Exception as e:
            return {
                "success": False,
                "output": "",
                "error": str(e)
            }
    
    def nmap(self, args: list) -> str:
        """
        Ejecuta nmap con argumentos definidos por el LLM
        """
        command = ["nmap"] + args

        print(f"Ejecutando: {' '.join(command)}\n")
        result = self.run_command(command, stream_output=True)

        return result["output"] if result["success"] else f"Error: {result['error']}"

    
    def gobuster(self, args: list) -> str:
        """
        Ejecuta gobuster con argumentos definidos por el LLM
        """
        command = ["gobuster"] + args

        print(f"Ejecutando: {' '.join(command)}\n")
        result = self.run_command(command, stream_output=True)

        return result["output"] if result["success"] else f"Error: {result['error']}"
    
    def whatweb(self, args: list) -> str:
        """
        Ejecuta whatweb con argumentos definidos por el LLM
        """
        command = ["whatweb"] + args

        print(f"Ejecutando: {' '.join(command)}\n")
        result = self.run_command(command, stream_output=True)

        return result["output"] if result["success"] else f"Error: {result['error']}"
    
    def get_tool_definitions(self) -> list:
        return [
            {
                "type": "function",
                "function": {
                    "name": "nmap",
                    "description": (
                        "Ejecuta nmap. Elige tú los flags, técnicas y targets "
                        "como lo haría un pentester humano."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": (
                                    "Lista de argumentos EXACTOS para nmap, "
                                    "por ejemplo: ['-sS', '-p-', '-T4', '10.10.10.10']"
                                )
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
                        "Ejecuta gobuster. Decide el modo (dir, dns, vhost), "
                        "wordlists, threads y target."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": (
                                    "Argumentos completos para gobuster, "
                                    "ejemplo: ['dir', '-u', 'http://target', '-w', 'wordlist.txt']"
                                )
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
                        "Ejecuta whatweb para fingerprinting web. "
                        "Decide el nivel de agresividad y el target."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "args": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": (
                                    "Argumentos completos para whatweb, "
                                    "ejemplo: ['-a', '3', 'http://target']"
                                )
                            }
                        },
                        "required": ["args"]
                    }
                }
            }
        ]

