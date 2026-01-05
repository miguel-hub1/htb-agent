import ollama
import json
from tools import PentestingTools


class HTBAgent:
    def __init__(self, model="llama3.2"):
        self.model = model
        self.tools = PentestingTools()
        self.messages = []
        
        # System prompt que guía al agente
        self.system_prompt = """Eres un pentester experto especializado en CTFs y HackTheBox.

Tu objetivo es analizar objetivos de forma metódica y autónoma:

1. RECONNAISSANCE: Empieza siempre con nmap para identificar servicios
2. ENUMERATION: Según los puertos abiertos, enumera (ej: gobuster si hay HTTP)
3. ANALYSIS: Analiza los resultados y decide siguientes pasos
4. ITERATE: Continúa explorando hasta tener suficiente información

Cuando termines el análisis inicial, resume los hallazgos más importantes.

IMPORTANTE: Llama las funciones una a la vez y analiza los resultados antes de continuar."""
    
    def call_tool(self, tool_name: str, arguments: dict) -> str:
        """Ejecuta una herramienta y devuelve el resultado"""
        
        # Mapeo de nombres de funciones a métodos
        tool_map = {
            "nmap": self.tools.nmap,
            "gobuster": self.tools.gobuster,
            "whatweb": self.tools.whatweb
        }
        
        if tool_name not in tool_map:
            return f"Error: herramienta '{tool_name}' no encontrada"
        
        try:
            # Ejecutar la función con los argumentos
            result = tool_map[tool_name](**arguments)
            return result
        except Exception as e:
            return f"Error ejecutando {tool_name}: {str(e)}"
    
    def run(self, target: str, max_iterations: int = 100):
        """
        Ejecuta el agente autónomamente en el objetivo

        Args:
            target: IP o hostname del objetivo
            max_iterations: Máximo de iteraciones para evitar loops infinitos
        """
        print(f"\n{'='*70}")
        print(f"HTB Agent - Analizando: {target}")
        print(f"{'='*70}\n")

        # Mensaje inicial
        self.messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": f"Analiza el objetivo: {target}. Usa las herramientas disponibles de forma autónoma."}
        ]

        # Loop del agente
        for iteration in range(max_iterations):
            print(f"\n{'─'*70}")
            print(f"Iteración {iteration + 1}/{max_iterations}")
            print(f"{'─'*70}\n")
            
            try:
                # Llamada a Ollama con tool calling
                response = ollama.chat(
                    model=self.model,
                    messages=self.messages,
                    tools=self.tools.get_tool_definitions()
                )
                
                # Agregar respuesta del asistente al historial
                self.messages.append(response["message"])
                
                # Verificar si el modelo quiere usar una herramienta
                if response["message"].get("tool_calls"):
                    # El modelo decidió usar herramientas
                    tool_calls = response["message"]["tool_calls"]
                    
                    for tool_call in tool_calls:
                        function_name = tool_call["function"]["name"]
                        arguments = tool_call["function"]["arguments"]
                        
                        print(f"Agente decidió ejecutar: {function_name}")
                        print(f"Argumentos: {json.dumps(arguments, indent=2)}")
                        print(f"\n{'▼'*70}")
                        print(f"SALIDA DE {function_name.upper()}:")
                        print(f"{'▼'*70}\n")
                        
                        # Ejecutar la herramienta
                        result = self.call_tool(function_name, arguments)
                        
                        # ====== MOSTRAR SALIDA COMPLETA ======
                        print(result)  # SIN truncar
                        print(f"\n{'▲'*70}")
                        print(f"FIN DE {function_name.upper()}")
                        print(f"{'▲'*70}\n")
                        
                        # Agregar el resultado al historial para que el LLM lo vea
                        self.messages.append({
                            "role": "tool",
                            "content": result
                        })
                
                else:
                    # El modelo respondió sin llamar herramientas (análisis final)
                    final_response = response["message"]["content"]
                    print(f"\n{'='*70}")
                    print(f"ANÁLISIS FINAL DEL AGENTE:")
                    print(f"{'='*70}\n")
                    print(final_response)
                    print(f"\n{'='*70}")
                    print("Agente completó el análisis")
                    print(f"{'='*70}\n")
                    break
                    
            except Exception as e:
                print(f"Error: {str(e)}")
                import traceback
                traceback.print_exc()
                break

        else:
            print("\n Se alcanzó el máximo de iteraciones")


if __name__ == "__main__":
    import sys
    
    # Obtener target de argumentos o usar uno por defecto
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = "scanme.nmap.org"
        print(f"Uso: uv run main.py <target>")
        print(f"Usando target de prueba: {target}\n")
    
    # Crear y ejecutar el agente
    agent = HTBAgent()
    agent.run(target)
