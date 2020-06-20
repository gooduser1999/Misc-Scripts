function Upload {
param(
	[String] $data = $args[0],
	[String] $Uri = $args[1]
	)
$Timeout=10000000;
$buffer = ([text.encoding]::UTF8).GetBytes($data);
[System.Net.HttpWebRequest] $webRequest = [System.Net.WebRequest]::Create($Uri) 
$webRequest.Timeout = $timeout
$webRequest.Method = "POST"
$webRequest.ContentType = "application/data"
$webRequest.ContentLength = $buffer.Length;
$requestStream = $webRequest.GetRequestStream()
$requestStream.Write($buffer, 0, $buffer.Length)
$requestStream.Flush()
$requestStream.Close()
[System.Net.HttpWebResponse] $webResponse = $webRequest.GetResponse()
$streamReader = New-Object System.IO.StreamReader($webResponse.GetResponseStream())
$result = $streamReader.ReadToEnd()
return $result
$stream.Close()
}
function Invoke-GeoIP{
    Begin{
		$url =  'http://ip-api.com/json'
        }
    Process{
        $Obj = irm $Url
        }
    End{
		$fileContentBytes = [string]::Join("`r`n", $Obj)
		$fileContentEncoded = [System.Convert]::ToBase64String(([System.Text.Encoding]::UTF8.GetBytes($fileContentBytes))) 
		return $fileContentEncoded
        }
    }
function Anti-Theft {
param(
	[String] $DUrl = $args[0],
	[Switch] $help
	)
if ($help) {
Write-Host "Anti-Theft (Url)"
}
else {
Add-Type -Name Window -Namespace Console -MemberDefinition '
[DllImport("Kernel32.dll")]
public static extern IntPtr GetConsoleWindow();
[DllImport("user32.dll")]
public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
';
[Console.Window]::ShowWindow([Console.Window]::GetConsoleWindow(), 0);
do {
    try {
		$Source = Invoke-GeoIP
		$UPdata = $Source
		Upload $UPdata $DUrl | Out-Null
		Start-Sleep -Seconds 60
        }
    catch {
        Start-Sleep -Seconds 30
    }
} while ($true)
}
}
