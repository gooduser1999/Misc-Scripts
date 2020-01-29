Add-Type -Name Window -Namespace Console -MemberDefinition '
[DllImport("Kernel32.dll")]
public static extern IntPtr GetConsoleWindow();
[DllImport("user32.dll")]
public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
';
[Console.Window]::ShowWindow([Console.Window]::GetConsoleWindow(), 0);
function Upload {
param(
	[String] $data = $args[0],
	[String] $Uri = $args[1]
	)

$Timeout=10000000;
$buffer64 = [System.Convert]::ToBase64String(([System.Text.Encoding]::UTF8.GetBytes($data))) 
$buffer = ([text.encoding]::UTF8).GetBytes($buffer64);
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
function Anti-Theft {
param(
	[String] $Url = $args[0]
	)
do {
    try {
    		## The post server will date  each post in a better format than if i used Get-Date, When uploaded, Get-Date for
		## for some reason would automatically turn it into a string format.
		$Source = (Invoke-WebRequest -UseBasicParsing -Uri "http://ifconfig.me/ip").Content
		$UPdata = $Source
		Upload $UPdata $Url | Out-Null
		Start-Sleep -Seconds 60
        }
    catch {
        Start-Sleep -Seconds 30
    }
} while ($true)
}
