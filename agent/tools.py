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
    
    def nmap_scan(self, target: str, scan_type: str = "basic") -> str:
        """
        Escanea un objetivo con nmap
        """
        scan_options = {
            "basic": ["-sV", "-sC"],
            "full": ["-p-", "-sV", "-sC", "-A"],
            "quick": ["-T4", "-F"],
            "stealth": ["-sS", "-sV"]
        }
        
        options = scan_options.get(scan_type, scan_options["basic"])
        command = ["nmap"] + options + [target]
        
        print(f"Ejecutando: {' '.join(command)}\n")
        result = self.run_command(command, stream_output=True)  # <-- streaming ON
        
        if result["success"]:
            return result["output"]
        else:
            return f"Error: {result['error']}"
    
    def gobuster_scan(self, target: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> str:
        """
        Enumera directorios y archivos en un servidor web
        """
        command = [
            "gobuster", "dir",
            "-u", target,
            "-w", wordlist,
            "-t", "20"  # Sin -q para ver progreso
        ]
        
        print(f"Ejecutando: {' '.join(command)}\n")
        result = self.run_command(command, stream_output=True)  # <-- streaming ON
        
        if result["success"]:
            return result["output"] if result["output"] else "No se encontraron directorios"
        else:
            return f"Error: {result['error']}"
    
    def whatweb_scan(self, target: str) -> str:
        """
        Identifica tecnologías web del objetivo
        """
        command = ["whatweb", "-a", "3", target]
        
        print(f"Ejecutando: {' '.join(command)}\n")
        result = self.run_command(command, stream_output=True)  # <-- streaming ON
        
        if result["success"]:
            return result["output"]
        else:
            return f"Error: {result['error']}"
    
    def get_tool_definitions(self) -> list:
        """
        Define las tools para Ollama en formato OpenAI
        Esto es lo que le dice al LLM qué funciones puede llamar
        """
        return [
            {
                "type": "function",
                "function": {
                    "name": "nmap_scan",
                    "description": "Escanea puertos y servicios de un objetivo usando nmap. Úsalo para descubrir qué puertos están abiertos y qué servicios corren.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "target": {
                                "type": "string",
                                "description": "IP o hostname del objetivo a escanear"
                            },
                            "scan_type": {
                                "type": "string",
                                "enum": ["basic", "full", "quick", "stealth"],
                                "description": "Tipo de escaneo. basic=común, full=todos los puertos, quick=rápido, stealth=sigiloso"
                            }
                        },
                        "required": ["target"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "gobuster_scan",
                    "description": "Enumera directorios y archivos en un servidor web usando fuzzing. Úsalo cuando encuentres un puerto HTTP/HTTPS abierto.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "target": {
                                "type": "string",
                                "description": "URL completa del sitio web (debe incluir http:// o https://)"
                            },
                            "wordlist": {
                                "type": "string",
                                "description": "Ruta al wordlist (opcional, usa /usr/share/wordlists/dirb/common.txt por defecto)"
                            }
                        },
                        "required": ["target"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "whatweb_scan",
                    "description": "Identifica tecnologías web, CMS, frameworks y versiones. Úsalo para reconnaissance web.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "target": {
                                "type": "string",
                                "description": "URL del sitio web a analizar"
                            }
                        },
                        "required": ["target"]
                    }
                }
            }
        ]
