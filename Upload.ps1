function Upload {
param(
	[String] $data = $args[0],
	[String] $Uri = $args[1],
	[Switch] $String,
	[Switch] $Byte
	)

if ($String) {
$Timeout=10000000;
$buffer64 = deflate($data)
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
if ($Byte) {
$Timeout=10000000;
$fileName = [System.IO.Path]::GetFileName($data)
$url = ($Uri + '/' + $fileName);
$content = Get-Content -LiteralPath ($data) -Encoding byte -ErrorAction SilentlyContinue
$buffer64 = deflate($content)
$buffer = ([text.encoding]::UTF8).GetBytes($buffer64);
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
}
else {
$Timeout=10000000;
$fileName = [System.IO.Path]::GetFileName($data)
$url = ($Uri + '/' + $fileName);
$content = Get-Content -LiteralPath ($data) -Encoding UTF8 -ErrorAction SilentlyContinue
$scriptInp = [string]::Join("`r`n", $content)
$buffer64 = deflate($scriptInp) 
$buffer = ([text.encoding]::UTF8).GetBytes($buffer64);
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
}
}
function deflate($data) {
	$s = $data
	$ms = New-Object System.IO.MemoryStream
	$cs = New-Object System.IO.Compression.DeflateStream($ms, [System.IO.Compression.CompressionMode]::Compress)
	$sw = New-Object System.IO.StreamWriter($cs)
	$sw.Write($s)
	$sw.Close();
	$s = [System.Convert]::ToBase64String($ms.ToArray())
	return $s
}
function inflate($data) {
	$data = [System.Convert]::FromBase64String($data)
	$ms = New-Object System.IO.MemoryStream
	$ms.Write($data, 0, $data.Length)
	$ms.Seek(0,0) | Out-Null
	$sr = New-Object System.IO.StreamReader(New-Object System.IO.Compression.DeflateStream($ms, [System.IO.Compression.CompressionMode]::Decompress))
	return $sr.ReadToEnd()
}
