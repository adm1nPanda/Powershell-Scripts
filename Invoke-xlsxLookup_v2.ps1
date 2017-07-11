<#
.SYNOPSIS
This is a Powershell script to look for xlsx files.

.DESCRIPTION
This Powershell script will find all xlsx files in directory and checks if file is password protected.

.PARAMETER SourceFilePath
The path of the file/directory.

#>

Param(
    [Parameter(Mandatory=$true)]
    [string]$SourcePath
)


$files = Get-ChildItem -path $SourcePath -ea silentlycontinue -recurse

foreach ($file in $files) {
	$extn = [IO.Path]::GetExtension($file)
	if ($extn -eq ".xlsx"){
		$header_nopass = Get-Content $file -TotalCount 4 -ReadCount 4 -Encoding byte
		$header_nopass = "{0:x2}" -f $header_nopass
		if ($header_nopass -eq "50 4B 03 04") {
			$file; "No Password"
		}
		else{
			$header_pass1 = Get-Content $file -TotalCount 8 -ReadCount 8 -Encoding byte
			$header_pass1 = "{0:x2}" -f $header_pass1
			$header_pass2 = Get-Content $file -TotalCount 608 -ReadCount 608 -Encoding byte
			$header_pass2 = "{0:x2}" -f $header_pass2

			if ($header_pass1 -eq "D0 CF 11 E0 A1 B1 1A E1" -and $header_pass2 -match "FD FF FF FF 04"){
				$file; "Password Exists"
			}
		}
	}
	
}
