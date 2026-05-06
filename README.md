<div align="center">
  <img src="https://readme-typing-svg.herokuapp.com?font=JetBrains+Mono&weight=700&size=42&duration=3000&pause=800&color=FF6B00&center=true&vCenter=true&width=600&lines=pacPortScanner+Lua;%E2%8A%99+Scan.+Detect.+Report." alt="pacPortScanner Lua" />
</div>

## Run


```powershell
lua pacportscanner.lua
```

Headless scan:

```powershell
lua pacportscanner.lua 127.0.0.1 -p top100 --backend socket --no-tui
```

Web mode needs LuaSocket:

```powershell
luarocks install luasocket
lua pacportscanner.lua web --port 43110
```

## Features

| Area | Lua version |
| --- | --- |
| Setup | Prompt-based orange-on-dark setup flow |
| Scanner | LuaSocket TCP connect, with Windows PowerShell fallback |
| Ports | `top100`, `top1000`, `all`, lists, ranges |
| Targets | Hostname, IP, IPv4 CIDR |
| Output | JSON, CSV, self-contained HTML in `./data/` |
| CVE | Best-effort NVD lookup through PowerShell |
| Web | Minimal localhost UI when LuaSocket is installed |

## Notes

The Lua standard library has no built-in TCP or HTTP server. For the full web flow, install LuaSocket.
