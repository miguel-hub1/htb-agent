# HTB Pentesting Agent 🤖🔐

![Python](https://img.shields.io/badge/python-3.11+-blue.svg)
![Docker](https://img.shields.io/badge/docker-required-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Ollama](https://img.shields.io/badge/ollama-llama3.2-orange.svg)

Autonomous pentesting agent using LLM (Ollama) and tools like nmap, gobuster, etc. Designed for HackTheBox competitions.

## 🚀 Features

- ✅ Autonomous agent with LLM (Ollama + Llama 3.2)
- ✅ Native tool calling to execute pentesting tools
- ✅ Integration with nmap, gobuster, whatweb, nikto, sqlmap
- ✅ Dockerized with Kali Linux
- ✅ Real-time tool output streaming
- ✅ Quick/normal/deep scan modes

## 📋 Requirements

- Docker & Docker Compose
- 8GB RAM minimum (for LLM models)
- Linux (recommended) or WSL2

## 🛠️ Installation

### 1. Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/htb-agent.git
cd htb-agent
```

### 2. Configure Ollama

**Option A: Use local Ollama (recommended)**
```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Download model
ollama pull llama3.2:1b

# Edit docker-compose.yml and comment out the ollama service
# Change OLLAMA_HOST to http://host.docker.internal:11434
```

**Option B: Use Ollama in Docker**
```bash
docker-compose up -d ollama
docker exec -it ollama ollama pull llama3.2:1b
```

### 3. Start the agent
```bash
docker-compose build
docker-compose up -d
```

## 🎯 Usage

### Basic scan
```bash
docker exec -it htb-agent uv run main.py scanme.nmap.org
```

### Quick mode (3 iterations)
```bash
docker exec -it htb-agent uv run main.py scanme.nmap.org --quick
```

### With specific target
```bash
docker exec -it htb-agent uv run main.py 10.10.10.5
```

### Save logs
```bash
docker exec -it htb-agent uv run main.py target.com --save-log
```

### Help
```bash
docker exec -it htb-agent uv run main.py --help
```

## 📂 Project Structure
```
htb-agent/
├── agent/
│   ├── main.py           # Main agent with tool calling
│   ├── tools.py          # Pentesting tools
│   └── pyproject.toml    # Python dependencies (uv)
├── results/              # Logs and results (not versioned)
├── docker-compose.yml    # Service orchestration
├── Dockerfile.agent      # Agent image
└── README.md
```

## 🔧 Development

### Enter the container
```bash
docker exec -it htb-agent bash
```

### Add dependencies
```bash
docker exec -it htb-agent uv add package-name
```

### View logs
```bash
# Agent logs
docker logs -f htb-agent

# Ollama logs
docker logs -f ollama

# All services
docker-compose logs -f
```

### Interactive Python session
```bash
docker exec -it htb-agent uv run python

# Inside Python:
>>> from main import HTBAgent
>>> from tools import PentestingTools
>>> agent = HTBAgent()
>>> agent.run("scanme.nmap.org")
```

## 🎨 Advanced Usage

### Using different models
```bash
# Edit agent/main.py and change the model
class HTBAgent:
    def __init__(self, model="llama3.2:1b"):  # Change here
        # ...
```

Available models:
- `llama3.2:1b` - Fast and lightweight (1.3GB)
- `llama3.2:3b` - Balanced (2GB)
- `llama3.1:8b` - More powerful (4.7GB)
- `mistral:7b` - Excellent for code (4.1GB)

### Custom iterations
```bash
# 5 iterations
docker exec -it htb-agent uv run main.py target.com --iterations 5

# Deep scan (20 iterations)
docker exec -it htb-agent uv run main.py target.com --deep
```

### Add custom tools

Edit `agent/tools.py`:
```python
def your_custom_tool(self, target: str) -> str:
    """
    Your custom tool description
    
    Args:
        target: Target description
        
    Returns:
        Tool output
    """
    command = ["your-tool", target]
    result = self.run_command(command, stream_output=True)
    return result["output"]
```

Then add it to `get_tool_definitions()`:
```python
{
    "type": "function",
    "function": {
        "name": "your_custom_tool",
        "description": "What your tool does",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target to analyze"
                }
            },
            "required": ["target"]
        }
    }
}
```

## 🛡️ Disclaimer

**For educational and ethical use only.**

- ⚠️ Only scan systems you have permission to analyze
- ⚠️ Use in controlled environments (HTB, personal labs)
- ⚠️ Do not use in production or real systems without authorization
- ⚠️ Follow responsible disclosure practices
- ⚠️ Comply with local laws and regulations

## 🐛 Troubleshooting

### "Model not found" error
```bash
# Download the model
docker exec -it ollama ollama pull llama3.2:1b

# Verify it's downloaded
docker exec -it ollama ollama list
```

### Port already in use
```bash
# Stop existing Ollama instance
sudo systemctl stop ollama

# Or change the port in docker-compose.yml
ports:
  - "11435:11434"  # External port changed
```

### Container exits immediately
```bash
# Check logs
docker logs htb-agent

# Verify Dockerfile CMD
# Should be: CMD ["tail", "-f", "/dev/null"]
```

### Tools not working
```bash
# Enter container and test manually
docker exec -it htb-agent bash
nmap --version
gobuster version
```

## 📚 Resources

- [Ollama Documentation](https://ollama.com/)
- [HackTheBox](https://www.hackthebox.com/)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [Kali Linux Tools](https://www.kali.org/tools/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the project
2. Create a branch (`git checkout -b feature/new-tool`)
3. Commit your changes (`git commit -am 'Add new tool'`)
4. Push to the branch (`git push origin feature/new-tool`)
5. Open a Pull Request

### Contribution Guidelines

- Follow PEP 8 for Python code
- Add docstrings to all functions
- Update README if adding new features
- Test your changes before submitting
- Keep commits atomic and well-described

## 🗺️ Roadmap

- [ ] Add more tools (metasploit, burp suite API)
- [ ] Implement persistent memory
- [ ] Multiple specialized agents
- [ ] Automatic report generation
- [ ] Integration with external APIs (Shodan, VirusTotal)
- [ ] Web UI to control the agent
- [ ] Support for distributed scanning
- [ ] Custom wordlists management
- [ ] Vulnerability database integration
- [ ] Export to standard formats (JSON, XML, CSV)

## 📊 Architecture
```
┌─────────────────┐
│   Ollama LLM    │ ← Agent's brain (decision making)
└────────┬────────┘
         │
┌────────▼────────┐
│  Python Agent   │ ← Tool calling & orchestration
└────────┬────────┘
         │
┌────────▼────────┐
│  Pentesting     │ ← nmap, gobuster, nikto, etc.
│     Tools       │
└─────────────────┘
```

The agent uses **native tool calling** (function calling) to autonomously decide which tools to execute and in what order, based on the findings from previous steps.

## 📝 License

MIT License - see [LICENSE](LICENSE) for details.

## 👤 Author

Your Name - [@your_twitter](https://twitter.com/your_twitter)

Project Link: [https://github.com/YOUR_USERNAME/htb-agent](https://github.com/YOUR_USERNAME/htb-agent)

## 🙏 Acknowledgments

- [Anthropic Claude](https://www.anthropic.com/) for assistance in development
- [Ollama team](https://ollama.com/) for the amazing local LLM runtime
- [Kali Linux](https://www.kali.org/) for the comprehensive pentesting toolkit
- HackTheBox community for inspiration

---

⭐ If you find this project useful, please give it a star!

**Happy Hacking! 🚀**
