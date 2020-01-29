function Aes {
[CmdletBinding()]
Param( [Parameter(Position = 0, Mandatory = $False)]
		[String]
		$Data,  
		[Switch]
		$String,
		[Switch]
		$File,
		[Switch]
		$Encrypt,
		[Switch]
		$Decrypt,
		[Switch]
		$Random,
		[Switch]
		$Help
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
	Write-Host "Aes blahblah|.\blah.ps1 -String|-File -Encrypt|-Decrypt -Random|(empty)"
}
if ($Encrypt) {
	if ($String) {
		if ($Random) {
			$key = Create-AesKey
			Write-Host "Key:"$key
			$unencryptedString = $Data
			Encrypt-String $key $unencryptedString
		}
		else {	
			$key = '10lbKOHL62zy4XBfd7XoFkZR+YId6k5fT8BHR9HTZlw='
			$unencryptedString = $Data
			Encrypt-String $key $unencryptedString
		}
	}
	elseif ($File) {
		if ($Random) {
			$key = Create-AesKey
			Write-Host $key
			$fileContent = Get-Content -LiteralPath ($Data) -Encoding UTF8 -ErrorAction SilentlyContinue
			$fileContentBytes = [string]::Join("`r`n", $fileContent)
			$fileContentEncoded = [System.Convert]::ToBase64String(([System.Text.Encoding]::UTF8.GetBytes($fileContentBytes))) 
			$unencryptedString = $fileContentEncoded 
			$THY = $key
			$THE = Encrypt-String $key $unencryptedString
			OutFileAes $THE $THY
		}
		else {
			$key = '10lbKOHL62zy4XBfd7XoFkZR+YId6k5fT8BHR9HTZlw='
			$fileContent = Get-Content -LiteralPath ($Data) -Encoding UTF8 -ErrorAction SilentlyContinue
			$fileContentBytes = [string]::Join("`r`n", $fileContent)
			$fileContentEncoded = [System.Convert]::ToBase64String(([System.Text.Encoding]::UTF8.GetBytes($fileContentBytes))) 
			$unencryptedString = $fileContentEncoded 
			$THY = $key
			$THE = Encrypt-String $key $unencryptedString
			OutFileAes $THE $THY
		}
	}
}
if ($Decrypt) {
	if ($String) {
		if ($Random) {
			$key = Read-Host "Input Key:"
			$encryptedString = $Data
			Decrypt-String $key $encryptedString
		}
		else {
			$key = '10lbKOHL62zy4XBfd7XoFkZR+YId6k5fT8BHR9HTZlw='
			$encryptedString = $Data
			Decrypt-String $key $encryptedString
		}
	}
	elseif ($File) {
		if ($Random) {
			$key = Read-Host "Input Key:"
			$encryptedString = get-content -raw $Data
			$backToPlainText = Decrypt-String $key $encryptedString
			[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($backToPlainText))
		}	
		else {
		$key = '10lbKOHL62zy4XBfd7XoFkZR+YId6k5fT8BHR9HTZlw='
		$encryptedString = get-content -raw $Data
		$backToPlainText = Decrypt-String $key $encryptedString
		[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($backToPlainText))
		}
	}
}
}
function OutFileAes {
Param(
	[String]
	$DCode = $args[0],
	[String]
	$DKey = $args[1]
	)
$Suffix = [System.IO.Path]::GetExtension($Data)
$Path = [System.IO.Path]::GetFileNameWithoutExtension($Data)
$OutputFile = $Path + "-aes" + $Suffix
$Code = 'function Create-AesManagedObject($key, $IV) {
$aesManaged = New-Object "System.Security.Cryptography.AesManaged"
$aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
$aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
$aesManaged.BlockSize = 128
$aesManaged.KeySize = 128
if ($IV) { if ($IV.getType().Name -eq "String") { $aesManaged.IV = [System.Convert]::FromBase64String($IV) } else { $aesManaged.IV = $IV } }
if ($key) { if ($key.getType().Name -eq "String") { $aesManaged.Key = [System.Convert]::FromBase64String($key) } else { $aesManaged.Key = $key } }
$aesManaged }
function Decrypt-String($key, $encryptedStringWithIV) {
$bytes = [System.Convert]::FromBase64String($encryptedStringWithIV)
$IV = $bytes[0..15]
$aesManaged = Create-AesManagedObject $key $IV
$decryptor = $aesManaged.CreateDecryptor();
$unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16);
$aesManaged.Dispose()
[System.Text.Encoding]::UTF8.GetString($unencryptedData).Trim([char]0) }
$encryptedString =  "' + $DCode + '";
$key = "' + $DKey +'";
$backToPlainText = Decrypt-String $key $encryptedString
$Start = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($backToPlainText))
$Start | IEX
'
Write-Output $Code | Out-File $OutputFile -encoding utf8
}
