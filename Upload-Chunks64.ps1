param(
	[String] $Uri = $args[0],
	[String] $data $args[1] 
	)
$Timeout=10000000;
$fileName = [System.IO.Path]::GetFileName($args[0])
$url = ($Uri + '/' + $fileName);
$content = Get-Content -LiteralPath ($data) -Encoding UTF8 -ErrorAction SilentlyContinue
$scriptInp = [string]::Join("`r`n", $content)
$buffer64 = [System.Convert]::ToBase64String(([System.Text.Encoding]::UTF8.GetBytes($scriptInp))) 
buffer = ([text.encoding]::UTF8).GetBytes($buffer64);
[System.Net.HttpWebRequest] $webRequest = [System.Net.WebRequest]::Create($url)
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
