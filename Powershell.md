# Powershell-OneLiner

1. Check if xls file is password protected
```
gc -encoding byte -TotalCount 3000 -ReadCount 20 ./<FILENAME> |% {"{0:x2}" -f $_} | Select-String -Pattern "13 00 02 00" |% {$_ -match '13 00 02 00 (.{5})'}; $matches[1]
```
can make this script iterate thorough all files with - `Get-ChildItem -path <PATH> -recurse | foreach {runyourscript}`
