#!/usr/bin/env lua

local VERSION = "0.1.0"
local ORANGE = "\27[38;2;255;107;0m"
local DIM = "\27[90m"
local RESET = "\27[0m"

local profiles = {
  stealth = { ports = "top100", timeout = 2.0, concurrency = 100, ping_sweep = true, cve = false, service = true, banner = false, os = false },
  fast = { ports = "top100", timeout = 1.0, concurrency = 500, ping_sweep = false, cve = false, service = true, banner = false, os = false },
  full = { ports = "1-65535", timeout = 1.5, concurrency = 500, ping_sweep = false, cve = false, service = true, banner = true, os = false },
  vulnerability = { ports = "top1000", timeout = 2.0, concurrency = 300, ping_sweep = true, cve = true, service = true, banner = true, os = true }
}

local top100 = {
  7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,
  139,143,144,179,199,389,427,443,444,445,465,513,514,515,543,544,548,
  554,587,631,646,873,990,993,995,1025,1026,1027,1028,1029,1110,1433,
  1720,1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3306,3389,
  3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,
  5900,6000,6001,6646,7070,8000,8008,8009,8080,8081,8443,8888,9100,
  9999,10000,32768,49152,49153,49154,49155,49156,49157
}

local services = {
  [21]="ftp",[22]="ssh",[23]="telnet",[25]="smtp",[53]="domain",[80]="http",
  [110]="pop3",[135]="msrpc",[139]="netbios-ssn",[143]="imap",[389]="ldap",
  [443]="https",[445]="microsoft-ds",[465]="smtps",[587]="submission",
  [993]="imaps",[995]="pop3s",[1433]="mssql",[2049]="nfs",[3000]="node-dev",
  [3306]="mysql",[3389]="rdp",[5432]="postgresql",[5900]="vnc",[6379]="redis",
  [8000]="http-alt",[8008]="http-alt",[8080]="http-proxy",[8081]="http-alt",
  [8443]="https-alt",[9200]="elasticsearch",[27017]="mongodb"
}

local function try_require(name)
  local ok, mod = pcall(require, name)
  if ok then return mod end
  return nil
end

local socket = try_require("socket")
local unpack_table = table.unpack or unpack

local function split(value, sep)
  local out = {}
  for part in tostring(value):gmatch("[^" .. sep .. "]+") do
    table.insert(out, part)
  end
  return out
end

local function unique_sorted(values)
  local seen, out = {}, {}
  for _, value in ipairs(values) do
    if not seen[value] then
      seen[value] = true
      table.insert(out, value)
    end
  end
  table.sort(out)
  return out
end

local function parse_port(value)
  local port = tonumber(value)
  if not port or port < 1 or port > 65535 or port % 1 ~= 0 then
    error("invalid TCP/UDP port: " .. tostring(value))
  end
  return port
end

local function parse_ports(spec)
  spec = tostring(spec or "top100"):lower():gsub("%s+", "")
  if spec == "top100" then return { unpack_table(top100) } end
  if spec == "top1000" then
    local ports = { unpack_table(top100) }
    for port = 1, 1000 do table.insert(ports, port) end
    local sorted = unique_sorted(ports)
    while #sorted > 1000 do table.remove(sorted) end
    return sorted
  end
  if spec == "all" then
    local ports = {}
    for port = 1, 65535 do table.insert(ports, port) end
    return ports
  end
  local ports = {}
  for _, part in ipairs(split(spec, ",")) do
    local startp, endp = part:match("^(%d+)%-(%d+)$")
    if startp then
      startp, endp = parse_port(startp), parse_port(endp)
      if startp > endp then error("invalid descending port range: " .. part) end
      for port = startp, endp do table.insert(ports, port) end
    else
      table.insert(ports, parse_port(part))
    end
  end
  if #ports == 0 then error("invalid port specification: " .. spec) end
  return unique_sorted(ports)
end

local function ipv4_to_num(ip)
  local a,b,c,d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
  if not a then return nil end
  return tonumber(a) * 16777216 + tonumber(b) * 65536 + tonumber(c) * 256 + tonumber(d)
end

local function num_to_ipv4(n)
  local a = math.floor(n / 16777216) % 256
  local b = math.floor(n / 65536) % 256
  local c = math.floor(n / 256) % 256
  local d = n % 256
  return string.format("%d.%d.%d.%d", a, b, c, d)
end

local function expand_target(target)
  local ip, prefix = tostring(target):match("^([^/]+)/(%d+)$")
  if not ip then return { target } end
  prefix = tonumber(prefix)
  local base = ipv4_to_num(ip)
  if not base or prefix < 0 or prefix > 32 then error("invalid IPv4 CIDR target: " .. target) end
  local count = 2 ^ (32 - prefix)
  if count > 65536 then error("CIDR target expands to too many hosts: " .. target) end
  local network = math.floor(base / count) * count
  local first = prefix <= 30 and network + 1 or network
  local last = prefix <= 30 and network + count - 2 or network + count - 1
  local out = {}
  for n = first, last do table.insert(out, num_to_ipv4(n)) end
  return out
end

local function expand_targets(targets)
  local out = {}
  for _, target in ipairs(targets) do
    for _, host in ipairs(expand_target(target)) do table.insert(out, host) end
  end
  return out
end

local function ps_quote(value)
  return "'" .. tostring(value):gsub("'", "''") .. "'"
end

local function powershell_connect(host, port, timeout)
  local ms = math.max(100, math.floor((timeout or 1) * 1000))
  local cmd = table.concat({
    "powershell -NoProfile -ExecutionPolicy Bypass -Command ",
    "\"$c=New-Object Net.Sockets.TcpClient;",
    "$iar=$c.BeginConnect(" .. ps_quote(host) .. "," .. tostring(port) .. ",$null,$null);",
    "$ok=$iar.AsyncWaitHandle.WaitOne(" .. tostring(ms) .. ",$false);",
    "if($ok -and $c.Connected){'open'}elseif($ok){'closed'}else{'filtered'};",
    "$c.Close()\""
  })
  local pipe = io.popen(cmd)
  if not pipe then return "filtered" end
  local output = pipe:read("*a") or ""
  pipe:close()
  return output:match("open") and "open" or output:match("closed") and "closed" or "filtered"
end

local function socket_connect(host, port, timeout_secs, banner_grab)
  if not socket then
    return powershell_connect(host, port, timeout_secs), nil
  end
  local tcp = socket.tcp()
  tcp:settimeout(timeout_secs or 1)
  local ok, err = tcp:connect(host, port)
  if not ok then
    tcp:close()
    if err == "connection refused" then return "closed", nil end
    return "filtered", nil
  end
  local banner = nil
  if banner_grab then
    if services[port] == "http" or services[port] == "http-alt" or services[port] == "http-proxy" then
      tcp:send("HEAD / HTTP/1.0\r\nUser-Agent: pacPortScanner-lua\r\n\r\n")
    end
    tcp:settimeout(math.min(timeout_secs or 1, 1.2))
    local data = tcp:receive(512)
    if data and #data > 0 then banner = data:gsub("%s+", " "):sub(1, 300) end
  end
  tcp:close()
  return "open", banner
end

local function lookup_cves(service, version)
  if not service then return {} end
  local query = (service .. " " .. (version or "")):gsub('"', "")
  local cmd = "powershell -NoProfile -ExecutionPolicy Bypass -Command \"try { $r=Invoke-RestMethod -Uri 'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=" .. query:gsub(" ", "%%20") .. "' -TimeoutSec 5; $r.vulnerabilities.cve.id | Select-Object -First 6 } catch {}\""
  local pipe = io.popen(cmd)
  if not pipe then return {} end
  local output = pipe:read("*a") or ""
  pipe:close()
  local cves = {}
  for id in output:gmatch("CVE%-%d+%-%d+") do
    table.insert(cves, { id = id, severity = "UNKNOWN", source = "nvd", url = "https://nvd.nist.gov/vuln/detail/" .. id })
  end
  return cves
end

local function scan(config, on_result, on_log)
  local hosts = expand_targets(config.targets)
  on_log("Using socket backend.")
  for _, host in ipairs(hosts) do
    for _, port in ipairs(config.ports) do
      local state, banner = socket_connect(host, port, config.timeout, config.banner)
      local result = {
        host = host,
        port = port,
        protocol = "tcp",
        state = state,
        service = state == "open" and services[port] or nil,
        version = nil,
        banner = banner,
        cves = {}
      }
      if config.cve and state == "open" then result.cves = lookup_cves(result.service, result.version) end
      on_result(result)
    end
  end
end

local function json_escape(value)
  return tostring(value or ""):gsub("\\", "\\\\"):gsub('"', '\\"'):gsub("\n", "\\n"):gsub("\r", "\\r")
end

local function result_to_json(result)
  local cve_json = {}
  for _, cve in ipairs(result.cves or {}) do
    table.insert(cve_json, string.format('{"id":"%s","severity":"%s","source":"%s","url":"%s"}', json_escape(cve.id), json_escape(cve.severity), json_escape(cve.source), json_escape(cve.url)))
  end
  return string.format('{"host":"%s","port":%d,"protocol":"tcp","state":"%s","service":"%s","version":"%s","banner":"%s","cves":[%s]}',
    json_escape(result.host), result.port, json_escape(result.state), json_escape(result.service), json_escape(result.version), json_escape(result.banner), table.concat(cve_json, ","))
end

local function timestamp()
  return os.date("%Y%m%d_%H%M%S")
end

local function mkdir_data()
  os.execute('if not exist data mkdir data >NUL 2>NUL')
end

local function export_all(results, config)
  mkdir_data()
  local stamp = timestamp()
  local json_path = "data/pacportscanner_" .. stamp .. ".json"
  local csv_path = "data/pacportscanner_" .. stamp .. ".csv"
  local html_path = "data/pacportscanner_" .. stamp .. ".html"
  local open, closed, filtered, with_cves = 0, 0, 0, 0
  for _, r in ipairs(results) do
    if r.state == "open" then open = open + 1 elseif r.state == "closed" then closed = closed + 1 else filtered = filtered + 1 end
    if #(r.cves or {}) > 0 then with_cves = with_cves + 1 end
  end
  local jf = assert(io.open(json_path, "w"))
  local rows = {}
  for _, r in ipairs(results) do table.insert(rows, result_to_json(r)) end
  jf:write(string.format('{"tool":"pacPortScanner Lua","generated_at":"%s","backend":"socket","config":{"targets":["%s"],"profile":"%s"},"summary":{"total":%d,"open":%d,"closed":%d,"filtered":%d,"with_cves":%d},"results":[%s]}',
    os.date("!%Y-%m-%dT%H:%M:%SZ"), json_escape(config.targets[1]), config.profile, #results, open, closed, filtered, with_cves, table.concat(rows, ",")))
  jf:close()
  local cf = assert(io.open(csv_path, "w"))
  cf:write("host,port,protocol,state,service,version,banner,cves\n")
  for _, r in ipairs(results) do
    local cves = {}
    for _, cve in ipairs(r.cves or {}) do table.insert(cves, cve.id) end
    cf:write(string.format('"%s",%d,tcp,"%s","%s","%s","%s","%s"\n', json_escape(r.host), r.port, r.state, json_escape(r.service), json_escape(r.version), json_escape(r.banner), table.concat(cves, ";")))
  end
  cf:close()
  local hf = assert(io.open(html_path, "w"))
  hf:write('<!doctype html><html><head><meta charset="utf-8"><title>pacPortScanner Lua</title><style>body{margin:0;background:#0B0D10;color:#F4F1ED;font-family:system-ui}header{padding:32px;background:#11151b;border-bottom:1px solid #2A2F37}h1,th{color:#FF6B00}main{padding:24px}table{width:100%;border-collapse:collapse}td,th{padding:10px;border-bottom:1px solid #2A2F37;text-align:left}.muted{color:#9CA3AF}.open td:first-child{border-left:4px solid #FF6B00}</style></head><body><header><h1>pacPortScanner Lua</h1><p class="muted">Scan. Detect. Report.</p></header><main><table><thead><tr><th>Host</th><th>Port</th><th>State</th><th>Service</th><th>Banner</th></tr></thead><tbody>')
  for _, r in ipairs(results) do
    hf:write(string.format('<tr class="%s"><td>%s</td><td>%d/tcp</td><td>%s</td><td>%s</td><td>%s</td></tr>', r.state, json_escape(r.host), r.port, r.state, json_escape(r.service), json_escape(r.banner)))
  end
  hf:write("</tbody></table></main></body></html>")
  hf:close()
  return { json = json_path, csv = csv_path, html = html_path }
end

local function prompt(label, default)
  io.write(ORANGE .. label .. RESET .. " [" .. tostring(default) .. "]: ")
  local value = io.read()
  if not value or value == "" then return default end
  return value
end

local function prompt_bool(label, default)
  local value = prompt(label .. " (y/n)", default and "y" or "n")
  return tostring(value):lower():sub(1,1) == "y"
end

local function setup_config()
  print(ORANGE .. "pacPortScanner Lua setup" .. RESET)
  print(DIM .. "Scan. Detect. Report." .. RESET)
  local profile = prompt("Profile", "fast")
  local p = profiles[profile] or profiles.fast
  local ports_spec = prompt("Ports", p.ports)
  return {
    targets = { prompt("Target / IP", "127.0.0.1") },
    ports_spec = ports_spec,
    ports = parse_ports(ports_spec),
    profile = profile,
    backend = prompt("Backend", "socket"),
    timeout = tonumber(prompt("Timeout", p.timeout)) or p.timeout,
    concurrency = tonumber(prompt("Concurrency", p.concurrency)) or p.concurrency,
    ping_sweep = prompt_bool("Ping sweep", p.ping_sweep),
    cve = prompt_bool("CVE lookup", p.cve),
    service = prompt_bool("Service detect", p.service),
    banner = prompt_bool("Banner grab", p.banner),
    os = prompt_bool("OS detect", p.os)
  }
end

local function build_config(args)
  local target, ports_spec, profile, backend, no_cve, no_tui = nil, nil, "fast", "socket", false, false
  local i = 1
  while i <= #args do
    local arg = args[i]
    if arg == "-p" or arg == "--ports" then i = i + 1; ports_spec = args[i]
    elseif arg == "--profile" then i = i + 1; profile = args[i] or profile
    elseif arg == "--backend" then i = i + 1; backend = args[i] or backend
    elseif arg == "--no-cve" then no_cve = true
    elseif arg == "--no-tui" then no_tui = true
    elseif not target then target = arg end
    i = i + 1
  end
  if not target and not no_tui then return setup_config() end
  local p = profiles[profile] or profiles.fast
  ports_spec = ports_spec or p.ports
  return {
    targets = { target or "127.0.0.1" },
    ports_spec = ports_spec,
    ports = parse_ports(ports_spec),
    profile = profile,
    backend = backend,
    timeout = p.timeout,
    concurrency = p.concurrency,
    ping_sweep = p.ping_sweep,
    cve = p.cve and not no_cve,
    service = p.service,
    banner = p.banner,
    os = p.os
  }
end

local function run_headless(config)
  local results = {}
  scan(config, function(result)
    table.insert(results, result)
    if result.state == "open" then
      print(string.format("%s:%d/tcp open %s", result.host, result.port, result.service or ""))
    end
  end, function(message) print(DIM .. message .. RESET) end)
  local paths = export_all(results, config)
  print("Exported JSON: " .. paths.json)
  print("Exported CSV: " .. paths.csv)
  print("Exported HTML: " .. paths.html)
end

local function web_server(port)
  if not socket then
    print("LuaSocket is required for web mode. Install with: luarocks install luasocket")
    os.exit(1)
  end
  port = tonumber(port) or 43110
  local server = assert(socket.bind("127.0.0.1", port))
  server:settimeout(0)
  local last_results, last_logs = {}, { "Ready. Local web UI is listening on 127.0.0.1 only." }
  print("pacPortScanner Lua web UI: http://127.0.0.1:" .. port)
  print("Press Ctrl+C to stop.")
  while true do
    local client = server:accept()
    if client then
      client:settimeout(1)
      local request = client:receive("*l") or ""
      local path = request:match("GET%s+([^%s]+)") or request:match("POST%s+([^%s]+)") or "/"
      while true do local line = client:receive("*l"); if not line or line == "" then break end end
      if path == "/api/status" then
        client:send("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n")
        client:send(string.format('{"status":"idle","backend":"socket","processed":%d,"total":%d,"results":[],"logs":["%s"]}', #last_results, #last_results, last_logs[#last_logs]))
      else
        client:send("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n")
        client:send('<!doctype html><html><head><title>pacPortScanner Lua Web</title><style>body{background:#0B0D10;color:#F4F1ED;font-family:system-ui;padding:24px}h1{color:#FF6B00}input,button{padding:8px;margin:4px;background:#15191f;color:#F4F1ED;border:1px solid #2A2F37;border-radius:8px}.primary{background:#FF6B00;color:#111}</style></head><body><h1>pacPortScanner Lua Web</h1><p>LuaSocket web shell. Use CLI for full scan/export workflow.</p><pre>lua pacportscanner.lua 127.0.0.1 -p top100 --no-tui</pre></body></html>')
      end
      client:close()
    end
    socket.sleep(0.05)
  end
end

local args = { ... }
if args[1] == "--version" or args[1] == "-V" then
  print(VERSION)
elseif args[1] == "--help" or args[1] == "-h" then
  print("pacportscanner-lua [target] [--ports top100] [--profile fast] [--backend socket] [--no-cve] [--no-tui]")
  print("pacportscanner-lua web [--port 43110]")
elseif args[1] == "web" then
  local port = 43110
  for i = 2, #args do if args[i] == "--port" then port = args[i + 1] end end
  web_server(port)
else
  run_headless(build_config(args))
end
