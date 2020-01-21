<#
https://github.com/danielbohannon/Invoke-Obfuscation.git
danielbohannon's Invoke-Obfuscation scripts in 1 file.
Optional switches to Obfuscate file by Reordering or Concat (h+ll+0).
#>
param (
    [Switch] $Reorder, 
    [Switch] $Concat
    )
function Invoke-Obfuscation {
    [CmdletBinding(DefaultParameterSetName = 'ScriptBlock')] Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ParameterSetName = 'ScriptBlock')]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]
        $ScriptBlock,
        [Parameter(Position = 0, ParameterSetName = 'ScriptPath')]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptPath,
        [String]
        $Command,
        [Switch]
        $NoExit,
        [Switch]
        $Quiet
    )
    $Script:CliCommands       = @()
    $Script:CompoundCommand   = @()
    $Script:QuietWasSpecified = $FALSE
    $CliWasSpecified          = $FALSE
    $NoExitWasSpecified       = $FALSE
    If($PSBoundParameters['ScriptBlock'])
    {
        $Script:CliCommands += ('set scriptblock ' + [String]$ScriptBlock)
    }
    If($PSBoundParameters['ScriptPath'])
    {
        $Script:CliCommands += ('set scriptpath ' + $ScriptPath)
    }
    If($PSBoundParameters['Command'])
    {
        $Script:CliCommands += $Command.Split(',')
        $CliWasSpecified = $TRUE
        If($PSBoundParameters['NoExit'])
        {
            $NoExitWasSpecified = $TRUE
        }
        If($PSBoundParameters['Quiet'])
        {
            Function Write-Host {}
            Function Start-Sleep {}
            $Script:QuietWasSpecified = $TRUE
        }
    }
    $Script:ScriptPath   = ''
    $Script:ScriptBlock  = ''
    $Script:CliSyntax         = @()
    $Script:ExecutionCommands = @()
    $Script:ObfuscatedCommand = ''
    $Script:ObfuscatedCommandHistory = @()
    $Script:ObfuscationLength = ''
    $Script:OptionsMenu =   @()
    $Script:OptionsMenu += , @('ScriptPath '       , $Script:ScriptPath       , $TRUE)
    $Script:OptionsMenu += , @('ScriptBlock'       , $Script:ScriptBlock      , $TRUE)
    $Script:OptionsMenu += , @('CommandLineSyntax' , $Script:CliSyntax        , $FALSE)
    $Script:OptionsMenu += , @('ExecutionCommands' , $Script:ExecutionCommands, $FALSE)
    $Script:OptionsMenu += , @('ObfuscatedCommand' , $Script:ObfuscatedCommand, $FALSE)
    $Script:OptionsMenu += , @('ObfuscationLength' , $Script:ObfuscatedCommand, $FALSE)
    $SettableInputOptions = @()
    ForEach($Option in $Script:OptionsMenu)
    {
        If($Option[2]) {$SettableInputOptions += ([String]$Option[0]).ToLower().Trim()}
    }
    $Script:LauncherApplied = $FALSE
    <#If(!(Get-Module Invoke-Obfuscation | Where-Object {$_.ModuleType -eq 'Manifest'}))
    {
        $PathTopsd1 = "$ScriptDir\Invoke-Obfuscation.psd1"
        If($PathTopsd1.Contains(' ')) {$PathTopsd1 = '"' + $PathTopsd1 + '"'}
        Write-Host "`n`nERROR: Invoke-Obfuscation module is not loaded. You must run:" -ForegroundColor Red
        Write-Host "       Import-Module $PathTopsd1`n`n" -ForegroundColor Yellow
        Start-Sleep -Seconds 3
        Exit
    } 
    #>
    $CmdMaxLength = 8190
    $LineSpacing = '[*] '
    $MenuLevel =   @()
    $MenuLevel+= , @($LineSpacing, 'TOKEN'    , 'Obfuscate PowerShell command <Tokens>')
    $MenuLevel+= , @($LineSpacing, 'AST'      , "`tObfuscate PowerShell <Ast> nodes <(PS3.0+)>")    
    $MenuLevel+= , @($LineSpacing, 'STRING'   , 'Obfuscate entire command as a <String>')
    $MenuLevel+= , @($LineSpacing, 'ENCODING' , 'Obfuscate entire command via <Encoding>')
    $MenuLevel+= , @($LineSpacing, 'COMPRESS'       , 'Convert entire command to one-liner and <Compress>')
    $MenuLevel+= , @($LineSpacing, 'LAUNCHER'       , 'Obfuscate command args w/<Launcher> techniques (run once at end)')
    $MenuLevel_Token                 =   @()
    $MenuLevel_Token                += , @($LineSpacing, 'STRING'     , 'Obfuscate <String> tokens (suggested to run first)')
    $MenuLevel_Token                += , @($LineSpacing, 'COMMAND'    , 'Obfuscate <Command> tokens')
    $MenuLevel_Token                += , @($LineSpacing, 'ARGUMENT'   , 'Obfuscate <Argument> tokens')
    $MenuLevel_Token                += , @($LineSpacing, 'MEMBER'     , 'Obfuscate <Member> tokens')
    $MenuLevel_Token                += , @($LineSpacing, 'VARIABLE'   , 'Obfuscate <Variable> tokens')
    $MenuLevel_Token                += , @($LineSpacing, 'TYPE  '     , 'Obfuscate <Type> tokens')
    $MenuLevel_Token                += , @($LineSpacing, 'COMMENT'    , 'Remove all <Comment> tokens')
    $MenuLevel_Token                += , @($LineSpacing, 'WHITESPACE' , 'Insert random <Whitespace> (suggested to run last)')
    $MenuLevel_Token                += , @($LineSpacing, 'ALL   '     , 'Select <All> choices from above (random order)')
    $MenuLevel_Token_String          =   @()
    $MenuLevel_Token_String         += , @($LineSpacing, '1' , "Concatenate --> e.g. <('co'+'ffe'+'e')>"                           , @('Out-ObfuscatedTokenCommand', 'String', 1))
    $MenuLevel_Token_String         += , @($LineSpacing, '2' , "Reorder     --> e.g. <('{1}{0}'-f'ffee','co')>"                    , @('Out-ObfuscatedTokenCommand', 'String', 2))
    $MenuLevel_Token_Command         =   @()
    $MenuLevel_Token_Command        += , @($LineSpacing, '1' , 'Ticks                   --> e.g. <Ne`w-O`Bject>'                   , @('Out-ObfuscatedTokenCommand', 'Command', 1))
    $MenuLevel_Token_Command        += , @($LineSpacing, '2' , "Splatting + Concatenate --> e.g. <&('Ne'+'w-Ob'+'ject')>"          , @('Out-ObfuscatedTokenCommand', 'Command', 2))
    $MenuLevel_Token_Command        += , @($LineSpacing, '3' , "Splatting + Reorder     --> e.g. <&('{1}{0}'-f'bject','New-O')>"   , @('Out-ObfuscatedTokenCommand', 'Command', 3))
    $MenuLevel_Token_Argument        =   @()
    $MenuLevel_Token_Argument       += , @($LineSpacing, '1' , 'Random Case --> e.g. <nEt.weBclIenT>'                              , @('Out-ObfuscatedTokenCommand', 'CommandArgument', 1))
    $MenuLevel_Token_Argument       += , @($LineSpacing, '2' , 'Ticks       --> e.g. <nE`T.we`Bc`lIe`NT>'                          , @('Out-ObfuscatedTokenCommand', 'CommandArgument', 2))
    $MenuLevel_Token_Argument       += , @($LineSpacing, '3' , "Concatenate --> e.g. <('Ne'+'t.We'+'bClient')>"                    , @('Out-ObfuscatedTokenCommand', 'CommandArgument', 3))
    $MenuLevel_Token_Argument       += , @($LineSpacing, '4' , "Reorder     --> e.g. <('{1}{0}'-f'bClient','Net.We')>"             , @('Out-ObfuscatedTokenCommand', 'CommandArgument', 4))
    $MenuLevel_Token_Member          =   @()
    $MenuLevel_Token_Member         += , @($LineSpacing, '1' , 'Random Case --> e.g. <dOwnLoAdsTRing>'                             , @('Out-ObfuscatedTokenCommand', 'Member', 1))
    $MenuLevel_Token_Member         += , @($LineSpacing, '2' , 'Ticks       --> e.g. <d`Ow`NLoAd`STRin`g>'                         , @('Out-ObfuscatedTokenCommand', 'Member', 2))
    $MenuLevel_Token_Member         += , @($LineSpacing, '3' , "Concatenate --> e.g. <('dOwnLo'+'AdsT'+'Ring').Invoke()>"          , @('Out-ObfuscatedTokenCommand', 'Member', 3))
    $MenuLevel_Token_Member         += , @($LineSpacing, '4' , "Reorder     --> e.g. <('{1}{0}'-f'dString','Downloa').Invoke()>"   , @('Out-ObfuscatedTokenCommand', 'Member', 4))
    $MenuLevel_Token_Variable        =   @()
    $MenuLevel_Token_Variable       += , @($LineSpacing, '1' , 'Random Case + {} + Ticks --> e.g. <${c`hEm`eX}>'                   , @('Out-ObfuscatedTokenCommand', 'Variable', 1))
    $MenuLevel_Token_Type            =   @()
    $MenuLevel_Token_Type           += , @($LineSpacing, '1' , "Type Cast + Concatenate --> e.g. <[Type]('Con'+'sole')>"           , @('Out-ObfuscatedTokenCommand', 'Type', 1))
    $MenuLevel_Token_Type           += , @($LineSpacing, '2' , "Type Cast + Reordered   --> e.g. <[Type]('{1}{0}'-f'sole','Con')>" , @('Out-ObfuscatedTokenCommand', 'Type', 2))
    $MenuLevel_Token_Whitespace      =   @()
    $MenuLevel_Token_Whitespace     += , @($LineSpacing, '1' , "`tRandom Whitespace --> e.g. <.( 'Ne'  +'w-Ob' +  'ject')>"        , @('Out-ObfuscatedTokenCommand', 'RandomWhitespace', 1))
    $MenuLevel_Token_Comment         =   @()#Invoke-Obfuscation
    $MenuLevel_Token_Comment        += , @($LineSpacing, '1' , "Remove Comments   --> e.g. self-explanatory"                       , @('Out-ObfuscatedTokenCommand', 'Comment', 1))
    $MenuLevel_Token_All             =   @()
    $MenuLevel_Token_All            += , @($LineSpacing, '1' , "`tExecute <ALL> Token obfuscation techniques (random order)"       , @('Out-ObfuscatedTokenCommandAll', '', ''))
    $MenuLevel_Ast                            =   @()
    $MenuLevel_Ast                           += , @($LineSpacing, 'NamedAttributeArgumentAst' , 'Obfuscate <NamedAttributeArgumentAst> nodes')
    $MenuLevel_Ast                           += , @($LineSpacing, 'ParamBlockAst'             , "`t`tObfuscate <ParamBlockAst> nodes")
    $MenuLevel_Ast                           += , @($LineSpacing, 'ScriptBlockAst'            , "`t`tObfuscate <ScriptBlockAst> nodes")
    $MenuLevel_Ast                           += , @($LineSpacing, 'AttributeAst'              , "`t`tObfuscate <AttributeAst> nodes")
    $MenuLevel_Ast                           += , @($LineSpacing, 'BinaryExpressionAst'       , "`tObfuscate <BinaryExpressionAst> nodes")
    $MenuLevel_Ast                           += , @($LineSpacing, 'HashtableAst'              , "`t`tObfuscate <HashtableAst> nodes")
    $MenuLevel_Ast                           += , @($LineSpacing, 'CommandAst'                , "`t`tObfuscate <CommandAst> nodes")
    $MenuLevel_Ast                           += , @($LineSpacing, 'AssignmentStatementAst'    , "`tObfuscate <AssignmentStatementAst> nodes")
    $MenuLevel_Ast                           += , @($LineSpacing, 'TypeExpressionAst'         , "`tObfuscate <TypeExpressionAst> nodes")
    $MenuLevel_Ast                           += , @($LineSpacing, 'TypeConstraintAst'         , "`tObfuscate <TypeConstraintAst> nodes")
    $MenuLevel_Ast                           += , @($LineSpacing, 'ALL'                       , "`t`t`tSelect <All> choices from above")
    $MenuLevel_Ast_NamedAttributeArgumentAst  =   @()
    $MenuLevel_Ast_NamedAttributeArgumentAst += , @($LineSpacing, '1' , 'Reorder e.g. <[Parameter(Mandatory, ValueFromPipeline = $True)]> --> <[Parameter(Mandatory = $True, ValueFromPipeline)]>'                     , @('Out-ObfuscatedAst', @('System.Management.Automation.Language.NamedAttributeArgumentAst'), 1))
    $MenuLevel_Ast_ParamBlockAst              =   @()
    $MenuLevel_Ast_ParamBlockAst             += , @($LineSpacing, '1' , 'Reorder e.g. <Param([Int]$One, [Int]$Two)> --> <Param([Int]$Two, [Int]$One)>'                                                                 , @('Out-ObfuscatedAst', @('System.Management.Automation.Language.ParamBlockAst'), 1))
    $MenuLevel_Ast_ScriptBlockAst             =   @()
    $MenuLevel_Ast_ScriptBlockAst            += , @($LineSpacing, '1' , 'Reorder e.g. <{ Begin {} Process {} End {} }> --> <{ End {} Begin {} Process {} }>'                                                           , @('Out-ObfuscatedAst', @('System.Management.Automation.Language.ScriptBlockAst'), 1))
    $MenuLevel_Ast_AttributeAst               =   @()
    $MenuLevel_Ast_AttributeAst              += , @($LineSpacing, '1' , 'Reorder e.g. <[Parameter(Position = 0, Mandatory)]> --> <[Parameter(Mandatory, Position = 0)]>'                                               , @('Out-ObfuscatedAst', @('System.Management.Automation.Language.AttributeAst'), 1))
    $MenuLevel_Ast_BinaryExpressionAst        =   @()
    $MenuLevel_Ast_BinaryExpressionAst       += , @($LineSpacing, '1' , 'Reorder e.g. <(2 + 3) * 4> --> <4 * (3 + 2)>'                                                                                                 , @('Out-ObfuscatedAst', @('System.Management.Automation.Language.BinaryExpressionAst'), 1))
    $MenuLevel_Ast_HashtableAst               =   @()
    $MenuLevel_Ast_HashtableAst              += , @($LineSpacing, '1' , "Reorder e.g. <@{ProviderName = 'Microsoft-Windows-PowerShell'; Id = 4104}> --> <@{Id = 4104; ProviderName = 'Microsoft-Windows-PowerShell'}>" , @('Out-ObfuscatedAst', @('System.Management.Automation.Language.HashtableAst'), 1))
    $MenuLevel_Ast_CommandAst                 =   @()
    $MenuLevel_Ast_CommandAst                += , @($LineSpacing, '1' , 'Reorder e.g. <Get-Random -Min 1 -Max 100> --> <Get-Random -Max 100 -Min 1>'                                                                   , @('Out-ObfuscatedAst', @('System.Management.Automation.Language.CommandAst'), 1))
    $MenuLevel_Ast_AssignmentStatementAst     =   @()
    $MenuLevel_Ast_AssignmentStatementAst    += , @($LineSpacing, '1' , 'Rename e.g. <$Example = "Example"> --> <Set-Variable -Name Example -Value ("Example")>'                                                       , @('Out-ObfuscatedAst', @('System.Management.Automation.Language.AssignmentStatementAst'), 1))
    $MenuLevel_Ast_TypeExpressionAst          =   @()
    $MenuLevel_Ast_TypeExpressionAst         += , @($LineSpacing, '1' , 'Rename e.g. <[ScriptBlock]> --> <[Management.Automation.ScriptBlock]>'                                                                        , @('Out-ObfuscatedAst', @('System.Management.Automation.Language.TypeExpressionAst'), 1))
    $MenuLevel_Ast_TypeConstraintAst          =   @()
    $MenuLevel_Ast_TypeConstraintAst         += , @($LineSpacing, '1' , 'Rename e.g. <[Int] $Integer = 1> --> <[System.Int32] $Integer = 1>'                                                                             , @('Out-ObfuscatedAst', @('System.Management.Automation.Language.TypeConstraintAst'), 1))
    $MenuLevel_Ast_All                        =   @()
    $MenuLevel_Ast_All                       += , @($LineSpacing, '1' , "`tExecute <ALL> Ast obfuscation techniques"                                                                                                   , @('Out-ObfuscatedAst', @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'), ''))
    $MenuLevel_String                =   @()
    $MenuLevel_String               += , @($LineSpacing, '1' , '<Concatenate> entire command'                                      , @('Out-ObfuscatedStringCommand', '', 1))
    $MenuLevel_String               += , @($LineSpacing, '2' , '<Reorder> entire command after concatenating'                      , @('Out-ObfuscatedStringCommand', '', 2))
    $MenuLevel_String               += , @($LineSpacing, '3' , '<Reverse> entire command after concatenating'                      , @('Out-ObfuscatedStringCommand', '', 3))
    $MenuLevel_Encoding              =   @()
    $MenuLevel_Encoding             += , @($LineSpacing, '1' , "`tEncode entire command as <ASCII>"                                , @('Out-EncodedAsciiCommand'           , '', ''))
    $MenuLevel_Encoding             += , @($LineSpacing, '2' , "`tEncode entire command as <Hex>"                                  , @('Out-EncodedHexCommand'             , '', ''))
    $MenuLevel_Encoding             += , @($LineSpacing, '3' , "`tEncode entire command as <Octal>"                                , @('Out-EncodedOctalCommand'           , '', ''))
    $MenuLevel_Encoding             += , @($LineSpacing, '4' , "`tEncode entire command as <Binary>"                               , @('Out-EncodedBinaryCommand'          , '', ''))
    $MenuLevel_Encoding             += , @($LineSpacing, '5' , "`tEncrypt entire command as <SecureString> (AES)"                  , @('Out-SecureStringCommand'           , '', ''))
    $MenuLevel_Encoding             += , @($LineSpacing, '6' , "`tEncode entire command as <BXOR>"                                 , @('Out-EncodedBXORCommand'            , '', ''))
    $MenuLevel_Encoding             += , @($LineSpacing, '7' , "`tEncode entire command as <Special Characters>"                   , @('Out-EncodedSpecialCharOnlyCommand' , '', ''))
    $MenuLevel_Encoding             += , @($LineSpacing, '8' , "`tEncode entire command as <Whitespace>"                           , @('Out-EncodedWhitespaceCommand'      , '', ''))
    $MenuLevel_Compress              =   @()
    $MenuLevel_Compress             += , @($LineSpacing, '1' , "Convert entire command to one-liner and <compress>"                , @('Out-CompressedCommand'             , '', ''))
    $MenuLevel_Launcher              =   @()
    $MenuLevel_Launcher             += , @($LineSpacing, 'PS'            , "`t<PowerShell>")
    $MenuLevel_Launcher             += , @($LineSpacing, 'CMD'           , '<Cmd> + PowerShell')
    $MenuLevel_Launcher             += , @($LineSpacing, 'WMIC'          , '<Wmic> + PowerShell')
    $MenuLevel_Launcher             += , @($LineSpacing, 'RUNDLL'        , '<Rundll32> + PowerShell')
    $MenuLevel_Launcher             += , @($LineSpacing, 'VAR+'          , 'Cmd + set <Var> && PowerShell iex <Var>')
    $MenuLevel_Launcher             += , @($LineSpacing, 'STDIN+'        , 'Cmd + <Echo> | PowerShell - (stdin)')
    $MenuLevel_Launcher             += , @($LineSpacing, 'CLIP+'         , 'Cmd + <Echo> | Clip && PowerShell iex <clipboard>')
    $MenuLevel_Launcher             += , @($LineSpacing, 'VAR++'         , 'Cmd + set <Var> && Cmd && PowerShell iex <Var>')
    $MenuLevel_Launcher             += , @($LineSpacing, 'STDIN++'       , 'Cmd + set <Var> && Cmd <Echo> | PowerShell - (stdin)')
    $MenuLevel_Launcher             += , @($LineSpacing, 'CLIP++'        , 'Cmd + <Echo> | Clip && Cmd && PowerShell iex <clipboard>')
    $MenuLevel_Launcher             += , @($LineSpacing, 'RUNDLL++'      , 'Cmd + set Var && <Rundll32> && PowerShell iex Var')
    $MenuLevel_Launcher             += , @($LineSpacing, 'MSHTA++'       , 'Cmd + set Var && <Mshta> && PowerShell iex Var')
    $MenuLevel_Launcher_PS           =   @()
    $MenuLevel_Launcher_PS          += , @("Enter string of numbers with all desired flags to pass to function. (e.g. 23459)`n", ''  , ''   , @('', '', ''))
    $MenuLevel_Launcher_PS          += , @($LineSpacing, '0' , 'NO EXECUTION FLAGS'                                          , @('Out-PowerShellLauncher', '', '1'))
    $MenuLevel_Launcher_PS          += , @($LineSpacing, '1' , '-NoExit'                                                     , @('Out-PowerShellLauncher', '', '1'))
    $MenuLevel_Launcher_PS          += , @($LineSpacing, '2' , '-NonInteractive'                                             , @('Out-PowerShellLauncher', '', '1'))
    $MenuLevel_Launcher_PS          += , @($LineSpacing, '3' , '-NoLogo'                                                     , @('Out-PowerShellLauncher', '', '1'))
    $MenuLevel_Launcher_PS          += , @($LineSpacing, '4' , '-NoProfile'                                                  , @('Out-PowerShellLauncher', '', '1'))
    $MenuLevel_Launcher_PS          += , @($LineSpacing, '5' , '-Command'                                                    , @('Out-PowerShellLauncher', '', '1'))
    $MenuLevel_Launcher_PS          += , @($LineSpacing, '6' , '-WindowStyle Hidden'                                         , @('Out-PowerShellLauncher', '', '1'))
    $MenuLevel_Launcher_PS          += , @($LineSpacing, '7' , '-ExecutionPolicy Bypass'                                     , @('Out-PowerShellLauncher', '', '1'))
    $MenuLevel_Launcher_PS          += , @($LineSpacing, '8' , '-Wow64 (to path 32-bit powershell.exe)'                      , @('Out-PowerShellLauncher', '', '1'))
    $MenuLevel_Launcher_CMD          =   @()
    $MenuLevel_Launcher_CMD         += , @("Enter string of numbers with all desired flags to pass to function. (e.g. 23459)`n", ''  , ''   , @('', '', ''))
    $MenuLevel_Launcher_CMD         += , @($LineSpacing, '0' , 'NO EXECUTION FLAGS'                                          , @('Out-PowerShellLauncher', '', '2'))
    $MenuLevel_Launcher_CMD         += , @($LineSpacing, '1' , '-NoExit'                                                     , @('Out-PowerShellLauncher', '', '2'))
    $MenuLevel_Launcher_CMD         += , @($LineSpacing, '2' , '-NonInteractive'                                             , @('Out-PowerShellLauncher', '', '2'))
    $MenuLevel_Launcher_CMD         += , @($LineSpacing, '3' , '-NoLogo'                                                     , @('Out-PowerShellLauncher', '', '2'))
    $MenuLevel_Launcher_CMD         += , @($LineSpacing, '4' , '-NoProfile'                                                  , @('Out-PowerShellLauncher', '', '2'))
    $MenuLevel_Launcher_CMD         += , @($LineSpacing, '5' , '-Command'                                                    , @('Out-PowerShellLauncher', '', '2'))
    $MenuLevel_Launcher_CMD         += , @($LineSpacing, '6' , '-WindowStyle Hidden'                                         , @('Out-PowerShellLauncher', '', '2'))
    $MenuLevel_Launcher_CMD         += , @($LineSpacing, '7' , '-ExecutionPolicy Bypass'                                     , @('Out-PowerShellLauncher', '', '2'))
    $MenuLevel_Launcher_CMD         += , @($LineSpacing, '8' , '-Wow64 (to path 32-bit powershell.exe)'                      , @('Out-PowerShellLauncher', '', '2'))
    $MenuLevel_Launcher_WMIC         =   @()
    $MenuLevel_Launcher_WMIC        += , @("Enter string of numbers with all desired flags to pass to function. (e.g. 23459)`n", ''  , ''   , @('', '', ''))
    $MenuLevel_Launcher_WMIC        += , @($LineSpacing, '0' , 'NO EXECUTION FLAGS'                                          , @('Out-PowerShellLauncher', '', '3'))
    $MenuLevel_Launcher_WMIC        += , @($LineSpacing, '1' , '-NoExit'                                                     , @('Out-PowerShellLauncher', '', '3'))
    $MenuLevel_Launcher_WMIC        += , @($LineSpacing, '2' , '-NonInteractive'                                             , @('Out-PowerShellLauncher', '', '3'))
    $MenuLevel_Launcher_WMIC        += , @($LineSpacing, '3' , '-NoLogo'                                                     , @('Out-PowerShellLauncher', '', '3'))
    $MenuLevel_Launcher_WMIC        += , @($LineSpacing, '4' , '-NoProfile'                                                  , @('Out-PowerShellLauncher', '', '3'))
    $MenuLevel_Launcher_WMIC        += , @($LineSpacing, '5' , '-Command'                                                    , @('Out-PowerShellLauncher', '', '3'))
    $MenuLevel_Launcher_WMIC        += , @($LineSpacing, '6' , '-WindowStyle Hidden'                                         , @('Out-PowerShellLauncher', '', '3'))
    $MenuLevel_Launcher_WMIC        += , @($LineSpacing, '7' , '-ExecutionPolicy Bypass'                                     , @('Out-PowerShellLauncher', '', '3'))
    $MenuLevel_Launcher_WMIC        += , @($LineSpacing, '8' , '-Wow64 (to path 32-bit powershell.exe)'                      , @('Out-PowerShellLauncher', '', '3'))
    $MenuLevel_Launcher_RUNDLL       =   @()
    $MenuLevel_Launcher_RUNDLL      += , @("Enter string of numbers with all desired flags to pass to function. (e.g. 23459)`n", ''  , ''   , @('', '', ''))
    $MenuLevel_Launcher_RUNDLL      += , @($LineSpacing, '0' , 'NO EXECUTION FLAGS'                                          , @('Out-PowerShellLauncher', '', '4'))
    $MenuLevel_Launcher_RUNDLL      += , @($LineSpacing, '1' , '-NoExit'                                                     , @('Out-PowerShellLauncher', '', '4'))
    $MenuLevel_Launcher_RUNDLL      += , @($LineSpacing, '2' , '-NonInteractive'                                             , @('Out-PowerShellLauncher', '', '4'))
    $MenuLevel_Launcher_RUNDLL      += , @($LineSpacing, '3' , '-NoLogo'                                                     , @('Out-PowerShellLauncher', '', '4'))
    $MenuLevel_Launcher_RUNDLL      += , @($LineSpacing, '4' , '-NoProfile'                                                  , @('Out-PowerShellLauncher', '', '4'))
    $MenuLevel_Launcher_RUNDLL      += , @($LineSpacing, '5' , '-Command'                                                    , @('Out-PowerShellLauncher', '', '4'))
    $MenuLevel_Launcher_RUNDLL      += , @($LineSpacing, '6' , '-WindowStyle Hidden'                                         , @('Out-PowerShellLauncher', '', '4'))
    $MenuLevel_Launcher_RUNDLL      += , @($LineSpacing, '7' , '-ExecutionPolicy Bypass'                                     , @('Out-PowerShellLauncher', '', '4'))
    $MenuLevel_Launcher_RUNDLL      += , @($LineSpacing, '8' , '-Wow64 (to path 32-bit powershell.exe)'                      , @('Out-PowerShellLauncher', '', '4'))
    ${MenuLevel_Launcher_VAR+}       =   @()
    ${MenuLevel_Launcher_VAR+}      += , @("Enter string of numbers with all desired flags to pass to function. (e.g. 23459)`n", ''  , ''   , @('', '', ''))
    ${MenuLevel_Launcher_VAR+}      += , @($LineSpacing, '0' , 'NO EXECUTION FLAGS'                                          , @('Out-PowerShellLauncher', '', '5'))
    ${MenuLevel_Launcher_VAR+}      += , @($LineSpacing, '1' , '-NoExit'                                                     , @('Out-PowerShellLauncher', '', '5'))
    ${MenuLevel_Launcher_VAR+}      += , @($LineSpacing, '2' , '-NonInteractive'                                             , @('Out-PowerShellLauncher', '', '5'))
    ${MenuLevel_Launcher_VAR+}      += , @($LineSpacing, '3' , '-NoLogo'                                                     , @('Out-PowerShellLauncher', '', '5'))
    ${MenuLevel_Launcher_VAR+}      += , @($LineSpacing, '4' , '-NoProfile'                                                  , @('Out-PowerShellLauncher', '', '5'))
    ${MenuLevel_Launcher_VAR+}      += , @($LineSpacing, '5' , '-Command'                                                    , @('Out-PowerShellLauncher', '', '5'))
    ${MenuLevel_Launcher_VAR+}      += , @($LineSpacing, '6' , '-WindowStyle Hidden'                                         , @('Out-PowerShellLauncher', '', '5'))
    ${MenuLevel_Launcher_VAR+}      += , @($LineSpacing, '7' , '-ExecutionPolicy Bypass'                                     , @('Out-PowerShellLauncher', '', '5'))
    ${MenuLevel_Launcher_VAR+}      += , @($LineSpacing, '8' , '-Wow64 (to path 32-bit powershell.exe)'                      , @('Out-PowerShellLauncher', '', '5'))
    ${MenuLevel_Launcher_STDIN+}     =   @()
    ${MenuLevel_Launcher_STDIN+}    += , @("Enter string of numbers with all desired flags to pass to function. (e.g. 23459)`n", ''  , ''   , @('', '', ''))
    ${MenuLevel_Launcher_STDIN+}    += , @($LineSpacing, '0' , 'NO EXECUTION FLAGS'                                          , @('Out-PowerShellLauncher', '', '6'))
    ${MenuLevel_Launcher_STDIN+}    += , @($LineSpacing, '1' , '-NoExit'                                                     , @('Out-PowerShellLauncher', '', '6'))
    ${MenuLevel_Launcher_STDIN+}    += , @($LineSpacing, '2' , '-NonInteractive'                                             , @('Out-PowerShellLauncher', '', '6'))
    ${MenuLevel_Launcher_STDIN+}    += , @($LineSpacing, '3' , '-NoLogo'                                                     , @('Out-PowerShellLauncher', '', '6'))
    ${MenuLevel_Launcher_STDIN+}    += , @($LineSpacing, '4' , '-NoProfile'                                                  , @('Out-PowerShellLauncher', '', '6'))
    ${MenuLevel_Launcher_STDIN+}    += , @($LineSpacing, '5' , '-Command'                                                    , @('Out-PowerShellLauncher', '', '6'))
    ${MenuLevel_Launcher_STDIN+}    += , @($LineSpacing, '6' , '-WindowStyle Hidden'                                         , @('Out-PowerShellLauncher', '', '6'))
    ${MenuLevel_Launcher_STDIN+}    += , @($LineSpacing, '7' , '-ExecutionPolicy Bypass'                                     , @('Out-PowerShellLauncher', '', '6'))
    ${MenuLevel_Launcher_STDIN+}    += , @($LineSpacing, '8' , '-Wow64 (to path 32-bit powershell.exe)'                      , @('Out-PowerShellLauncher', '', '6'))
    ${MenuLevel_Launcher_CLIP+}      =   @()
    ${MenuLevel_Launcher_CLIP+}     += , @("Enter string of numbers with all desired flags to pass to function. (e.g. 23459)`n", ''  , ''   , @('', '', ''))
    ${MenuLevel_Launcher_CLIP+}     += , @($LineSpacing, '0' , 'NO EXECUTION FLAGS'                                          , @('Out-PowerShellLauncher', '', '7'))
    ${MenuLevel_Launcher_CLIP+}     += , @($LineSpacing, '1' , '-NoExit'                                                     , @('Out-PowerShellLauncher', '', '7'))
    ${MenuLevel_Launcher_CLIP+}     += , @($LineSpacing, '2' , '-NonInteractive'                                             , @('Out-PowerShellLauncher', '', '7'))
    ${MenuLevel_Launcher_CLIP+}     += , @($LineSpacing, '3' , '-NoLogo'                                                     , @('Out-PowerShellLauncher', '', '7'))
    ${MenuLevel_Launcher_CLIP+}     += , @($LineSpacing, '4' , '-NoProfile'                                                  , @('Out-PowerShellLauncher', '', '7'))
    ${MenuLevel_Launcher_CLIP+}     += , @($LineSpacing, '5' , '-Command'                                                    , @('Out-PowerShellLauncher', '', '7'))
    ${MenuLevel_Launcher_CLIP+}     += , @($LineSpacing, '6' , '-WindowStyle Hidden'                                         , @('Out-PowerShellLauncher', '', '7'))
    ${MenuLevel_Launcher_CLIP+}     += , @($LineSpacing, '7' , '-ExecutionPolicy Bypass'                                     , @('Out-PowerShellLauncher', '', '7'))
    ${MenuLevel_Launcher_CLIP+}     += , @($LineSpacing, '8' , '-Wow64 (to path 32-bit powershell.exe)'                      , @('Out-PowerShellLauncher', '', '7'))
    ${MenuLevel_Launcher_VAR++}      =   @()
    ${MenuLevel_Launcher_VAR++}     += , @("Enter string of numbers with all desired flags to pass to function. (e.g. 23459)`n", ''  , ''   , @('', '', ''))
    ${MenuLevel_Launcher_VAR++}     += , @($LineSpacing, '0' , 'NO EXECUTION FLAGS'                                          , @('Out-PowerShellLauncher', '', '8'))
    ${MenuLevel_Launcher_VAR++}     += , @($LineSpacing, '1' , '-NoExit'                                                     , @('Out-PowerShellLauncher', '', '8'))
    ${MenuLevel_Launcher_VAR++}     += , @($LineSpacing, '2' , '-NonInteractive'                                             , @('Out-PowerShellLauncher', '', '8'))
    ${MenuLevel_Launcher_VAR++}     += , @($LineSpacing, '3' , '-NoLogo'                                                     , @('Out-PowerShellLauncher', '', '8'))
    ${MenuLevel_Launcher_VAR++}     += , @($LineSpacing, '4' , '-NoProfile'                                                  , @('Out-PowerShellLauncher', '', '8'))
    ${MenuLevel_Launcher_VAR++}     += , @($LineSpacing, '5' , '-Command'                                                    , @('Out-PowerShellLauncher', '', '8'))
    ${MenuLevel_Launcher_VAR++}     += , @($LineSpacing, '6' , '-WindowStyle Hidden'                                         , @('Out-PowerShellLauncher', '', '8'))
    ${MenuLevel_Launcher_VAR++}     += , @($LineSpacing, '7' , '-ExecutionPolicy Bypass'                                     , @('Out-PowerShellLauncher', '', '8'))
    ${MenuLevel_Launcher_VAR++}     += , @($LineSpacing, '8' , '-Wow64 (to path 32-bit powershell.exe)'                      , @('Out-PowerShellLauncher', '', '8'))
    ${MenuLevel_Launcher_STDIN++}    =   @()
    ${MenuLevel_Launcher_STDIN++}   += , @("Enter string of numbers with all desired flags to pass to function. (e.g. 23459)`n", ''  , ''   , @('', '', ''))
    ${MenuLevel_Launcher_STDIN++}   += , @($LineSpacing, '0' , "`tNO EXECUTION FLAGS"                                        , @('Out-PowerShellLauncher', '', '9'))
    ${MenuLevel_Launcher_STDIN++}   += , @($LineSpacing, '1' , "`t-NoExit"                                                   , @('Out-PowerShellLauncher', '', '9'))
    ${MenuLevel_Launcher_STDIN++}   += , @($LineSpacing, '2' , "`t-NonInteractive"                                           , @('Out-PowerShellLauncher', '', '9'))
    ${MenuLevel_Launcher_STDIN++}   += , @($LineSpacing, '3' , "`t-NoLogo"                                                   , @('Out-PowerShellLauncher', '', '9'))
    ${MenuLevel_Launcher_STDIN++}   += , @($LineSpacing, '4' , "`t-NoProfile"                                                , @('Out-PowerShellLauncher', '', '9'))
    ${MenuLevel_Launcher_STDIN++}   += , @($LineSpacing, '5' , "`t-Command"                                                  , @('Out-PowerShellLauncher', '', '9'))
    ${MenuLevel_Launcher_STDIN++}   += , @($LineSpacing, '6' , "`t-WindowStyle Hidden"                                       , @('Out-PowerShellLauncher', '', '9'))
    ${MenuLevel_Launcher_STDIN++}   += , @($LineSpacing, '7' , "`t-ExecutionPolicy Bypass"                                   , @('Out-PowerShellLauncher', '', '9'))
    ${MenuLevel_Launcher_STDIN++}   += , @($LineSpacing, '8' , "`t-Wow64 (to path 32-bit powershell.exe)"                    , @('Out-PowerShellLauncher', '', '9'))
    ${MenuLevel_Launcher_CLIP++}     =   @()
    ${MenuLevel_Launcher_CLIP++}    += , @("Enter string of numbers with all desired flags to pass to function. (e.g. 23459)`n", ''  , ''   , @('', '', ''))
    ${MenuLevel_Launcher_CLIP++}    += , @($LineSpacing, '0' , 'NO EXECUTION FLAGS'                                          , @('Out-PowerShellLauncher', '', '10'))
    ${MenuLevel_Launcher_CLIP++}    += , @($LineSpacing, '1' , '-NoExit'                                                     , @('Out-PowerShellLauncher', '', '10'))
    ${MenuLevel_Launcher_CLIP++}    += , @($LineSpacing, '2' , '-NonInteractive'                                             , @('Out-PowerShellLauncher', '', '10'))
    ${MenuLevel_Launcher_CLIP++}    += , @($LineSpacing, '3' , '-NoLogo'                                                     , @('Out-PowerShellLauncher', '', '10'))
    ${MenuLevel_Launcher_CLIP++}    += , @($LineSpacing, '4' , '-NoProfile'                                                  , @('Out-PowerShellLauncher', '', '10'))
    ${MenuLevel_Launcher_CLIP++}    += , @($LineSpacing, '5' , '-Command'                                                    , @('Out-PowerShellLauncher', '', '10'))
    ${MenuLevel_Launcher_CLIP++}    += , @($LineSpacing, '6' , '-WindowStyle Hidden'                                         , @('Out-PowerShellLauncher', '', '10'))
    ${MenuLevel_Launcher_CLIP++}    += , @($LineSpacing, '7' , '-ExecutionPolicy Bypass'                                     , @('Out-PowerShellLauncher', '', '10'))
    ${MenuLevel_Launcher_CLIP++}    += , @($LineSpacing, '8' , '-Wow64 (to path 32-bit powershell.exe)'                      , @('Out-PowerShellLauncher', '', '10'))
    ${MenuLevel_Launcher_RUNDLL++}   =   @()
    ${MenuLevel_Launcher_RUNDLL++}  += , @("Enter string of numbers with all desired flags to pass to function. (e.g. 23459)`n", ''  , ''   , @('', '', ''))
    ${MenuLevel_Launcher_RUNDLL++}  += , @($LineSpacing, '0' , 'NO EXECUTION FLAGS'                                          , @('Out-PowerShellLauncher', '', '11'))
    ${MenuLevel_Launcher_RUNDLL++}  += , @($LineSpacing, '1' , '-NoExit'                                                     , @('Out-PowerShellLauncher', '', '11'))
    ${MenuLevel_Launcher_RUNDLL++}  += , @($LineSpacing, '2' , '-NonInteractive'                                             , @('Out-PowerShellLauncher', '', '11'))
    ${MenuLevel_Launcher_RUNDLL++}  += , @($LineSpacing, '3' , '-NoLogo'                                                     , @('Out-PowerShellLauncher', '', '11'))
    ${MenuLevel_Launcher_RUNDLL++}  += , @($LineSpacing, '4' , '-NoProfile'                                                  , @('Out-PowerShellLauncher', '', '11'))
    ${MenuLevel_Launcher_RUNDLL++}  += , @($LineSpacing, '5' , '-Command'                                                    , @('Out-PowerShellLauncher', '', '11'))
    ${MenuLevel_Launcher_RUNDLL++}  += , @($LineSpacing, '6' , '-WindowStyle Hidden'                                         , @('Out-PowerShellLauncher', '', '11'))
    ${MenuLevel_Launcher_RUNDLL++}  += , @($LineSpacing, '7' , '-ExecutionPolicy Bypass'                                     , @('Out-PowerShellLauncher', '', '11'))
    ${MenuLevel_Launcher_RUNDLL++}  += , @($LineSpacing, '8' , '-Wow64 (to path 32-bit powershell.exe)'                      , @('Out-PowerShellLauncher', '', '11'))
    ${MenuLevel_Launcher_MSHTA++}    =   @()
    ${MenuLevel_Launcher_MSHTA++}   += , @("Enter string of numbers with all desired flags to pass to function. (e.g. 23459)`n", ''  , ''   , @('', '', ''))
    ${MenuLevel_Launcher_MSHTA++}   += , @($LineSpacing, '0' , 'NO EXECUTION FLAGS'                                          , @('Out-PowerShellLauncher', '', '12'))
    ${MenuLevel_Launcher_MSHTA++}   += , @($LineSpacing, '1' , '-NoExit'                                                     , @('Out-PowerShellLauncher', '', '12'))
    ${MenuLevel_Launcher_MSHTA++}   += , @($LineSpacing, '2' , '-NonInteractive'                                             , @('Out-PowerShellLauncher', '', '12'))
    ${MenuLevel_Launcher_MSHTA++}   += , @($LineSpacing, '3' , '-NoLogo'                                                     , @('Out-PowerShellLauncher', '', '12'))
    ${MenuLevel_Launcher_MSHTA++}   += , @($LineSpacing, '4' , '-NoProfile'                                                  , @('Out-PowerShellLauncher', '', '12'))
    ${MenuLevel_Launcher_MSHTA++}   += , @($LineSpacing, '5' , '-Command'                                                    , @('Out-PowerShellLauncher', '', '12'))
    ${MenuLevel_Launcher_MSHTA++}   += , @($LineSpacing, '6' , '-WindowStyle Hidden'                                         , @('Out-PowerShellLauncher', '', '12'))
    ${MenuLevel_Launcher_MSHTA++}   += , @($LineSpacing, '7' , '-ExecutionPolicy Bypass'                                     , @('Out-PowerShellLauncher', '', '12'))
    ${MenuLevel_Launcher_MSHTA++}   += , @($LineSpacing, '8' , '-Wow64 (to path 32-bit powershell.exe)'                      , @('Out-PowerShellLauncher', '', '12'))
    $TutorialInputOptions         = @(@('tutorial')                            , "<Tutorial> of how to use this tool        `t  " )
    $MenuInputOptionsShowHelp     = @(@('help','get-help','?','-?','/?','menu'), "Show this <Help> Menu                     `t  " )
    $MenuInputOptionsShowOptions  = @(@('show options','show','options')       , "<Show options> for payload to obfuscate   `t  " )
    $ClearScreenInputOptions      = @(@('clear','clear-host','cls')            , "<Clear> screen                            `t  " )
    $CopyToClipboardInputOptions  = @(@('copy','clip','clipboard')             , "<Copy> ObfuscatedCommand to clipboard     `t  " )
    $OutputToDiskInputOptions     = @(@('out')                                 , "Write ObfuscatedCommand <Out> to disk     `t  " )
    $ExecutionInputOptions        = @(@('exec','execute','test','run')         , "<Execute> ObfuscatedCommand locally       `t  " )
    $ResetObfuscationInputOptions = @(@('reset')                               , "<Reset> ALL obfuscation for ObfuscatedCommand  ")
    $UndoObfuscationInputOptions  = @(@('undo')                                , "<Undo> LAST obfuscation for ObfuscatedCommand  ")
    $BackCommandInputOptions      = @(@('back','cd ..')                        , "Go <Back> to previous obfuscation menu    `t  " )
    $ExitCommandInputOptions      = @(@('quit','exit')                         , "<Quit> Invoke-Obfuscation                 `t  " )
    $HomeMenuInputOptions         = @(@('home','main')                         , "Return to <Home> Menu                     `t  " )
    $AllAvailableInputOptionsLists   = @()
    $AllAvailableInputOptionsLists  += , $TutorialInputOptions
    $AllAvailableInputOptionsLists  += , $MenuInputOptionsShowHelp
    $AllAvailableInputOptionsLists  += , $MenuInputOptionsShowOptions
    $AllAvailableInputOptionsLists  += , $ClearScreenInputOptions
    $AllAvailableInputOptionsLists  += , $ExecutionInputOptions
    $AllAvailableInputOptionsLists  += , $CopyToClipboardInputOptions
    $AllAvailableInputOptionsLists  += , $OutputToDiskInputOptions
    $AllAvailableInputOptionsLists  += , $ResetObfuscationInputOptions
    $AllAvailableInputOptionsLists  += , $UndoObfuscationInputOptions
    $AllAvailableInputOptionsLists  += , $BackCommandInputOptions    
    $AllAvailableInputOptionsLists  += , $ExitCommandInputOptions
    $AllAvailableInputOptionsLists  += , $HomeMenuInputOptions
    $ExitInputOptions = $ExitCommandInputOptions[0]
    $MenuInputOptions = $BackCommandInputOptions[0]
    Show-AsciiArt
    Start-Sleep -Seconds 2
    Show-HelpMenu
    $UserResponse = ''
    While($ExitInputOptions -NotContains ([String]$UserResponse).ToLower())
    {
        $UserResponse = ([String]$UserResponse).Trim()
        If($HomeMenuInputOptions[0] -Contains ([String]$UserResponse).ToLower())
        {
            $UserResponse = ''
        }
        If(Test-Path ('Variable:' + "MenuLevel$UserResponse"))
        {
            $UserResponse = Show-Menu (Get-Variable "MenuLevel$UserResponse").Value $UserResponse $Script:OptionsMenu
        }
        Else
        {
            Write-Error "The variable MenuLevel$UserResponse does not exist."
            $UserResponse = 'quit'
        }
        If(($UserResponse -eq 'quit') -AND $CliWasSpecified -AND !$NoExitWasSpecified)
        {
            Write-Output $Script:ObfuscatedCommand.Trim("`n")
            $UserInput = 'quit'
        }
    }
}
$ScriptDir = [System.IO.Path]::GetDirectoryName($myInvocation.MyCommand.Definition) 
function Show-Menu
{
    Param(
        [Parameter(ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [Object[]]
        $Menu,
        [String]
        $MenuName,
        [Object[]]
        $Script:OptionsMenu
    )
    $AcceptableInput = @()
    $SelectionContainsCommand = $FALSE
    ForEach($Line in $Menu)
    {
        If($Line.Count -eq 4)
        {
            $SelectionContainsCommand = $TRUE
        }
        $AcceptableInput += ($Line[1]).Trim(' ')
    }
    $UserInput = $NULL
    While($AcceptableInput -NotContains $UserInput)
    {
        Write-Host "`n"
        $BreadCrumb = $MenuName.Trim('_')
        If($BreadCrumb.Length -gt 1)
        {
            If($BreadCrumb.ToLower() -eq 'show options')
            {
                $BreadCrumb = 'Show Options'
            }
            If($MenuName -ne '')
            {
                $BreadCrumbOCD  =   @()
                $BreadCrumbOCD += , @('ps'      ,'PS')
                $BreadCrumbOCD += , @('cmd'     ,'Cmd')
                $BreadCrumbOCD += , @('wmic'    ,'Wmic')
                $BreadCrumbOCD += , @('rundll'  ,'RunDll')
                $BreadCrumbOCD += , @('var+'    ,'Var+')
                $BreadCrumbOCD += , @('stdin+'  ,'StdIn+')
                $BreadCrumbOCD += , @('clip+'   ,'Clip+')
                $BreadCrumbOCD += , @('var++'   ,'Var++')
                $BreadCrumbOCD += , @('stdin++' ,'StdIn++')
                $BreadCrumbOCD += , @('clip++'  ,'Clip++')
                $BreadCrumbOCD += , @('rundll++','RunDll++')
                $BreadCrumbOCD += , @('mshta++' ,'Mshta++')
                $BreadCrumbOCD += , @('ast', 'AST')
                $BreadCrumbArray = @()
                ForEach($Crumb in $BreadCrumb.Split('_'))
                {
                    $StillLookingForSubstitution = $TRUE
                    ForEach($Substitution in $BreadCrumbOCD)
                    {
                        If($Crumb.ToLower() -eq $Substitution[0])
                        {
                            $BreadCrumbArray += $Substitution[1]
                            $StillLookingForSubstitution = $FALSE
                        }
                    }
                    If($StillLookingForSubstitution)
                    {
                        $BreadCrumbArray += $Crumb.SubString(0,1).ToUpper() + $Crumb.SubString(1).ToLower()
                        If(($BreadCrumb.Split('_').Count -eq 2) -AND ($BreadCrumb.StartsWith('Launcher_')) -AND ($Crumb -ne 'Launcher'))
                        {
                            Write-Warning "No substituion pair was found for `$Crumb=$Crumb in `$BreadCrumb=$BreadCrumb. Add this `$Crumb substitution pair to `$BreadCrumbOCD array in Invoke-Obfuscation."
                        }
                    }
                }
                $BreadCrumb = $BreadCrumbArray -Join '\'
            }
            $BreadCrumb = '\' + $BreadCrumb
        }
        $FirstLine = "Choose one of the below "
        If($BreadCrumb -ne '')
        {
            $FirstLine = $FirstLine + $BreadCrumb.Trim('\') + ' '
        }
        Write-Host "$FirstLine" -NoNewLine
        If($SelectionContainsCommand)
        {
            Write-Host "options" -NoNewLine -ForegroundColor Green
            Write-Host " to" -NoNewLine
            Write-Host " APPLY" -NoNewLine -ForegroundColor Green
            Write-Host " to current payload" -NoNewLine
        }
        Else
        {
            Write-Host "options" -NoNewLine -ForegroundColor Yellow
        }
        Write-Host ":`n"
        ForEach($Line in $Menu)
        {
            $LineSpace  = $Line[0]
            $LineOption = $Line[1]
            $LineValue  = $Line[2]
            Write-Host $LineSpace -NoNewLine
            If(($BreadCrumb -ne '') -AND ($LineSpace.StartsWith('[')))
            {
                Write-Host ($BreadCrumb.ToUpper().Trim('\') + '\') -NoNewLine
            }
            If($SelectionContainsCommand)
            {
                Write-Host $LineOption -NoNewLine -ForegroundColor Green
            }
            Else
            {
                Write-Host $LineOption -NoNewLine -ForegroundColor Yellow
            }
            If($LineValue.Contains('<') -AND $LineValue.Contains('>'))
            {
                $FirstPart  = $LineValue.SubString(0,$LineValue.IndexOf('<'))
                $MiddlePart = $LineValue.SubString($FirstPart.Length+1)
                $MiddlePart = $MiddlePart.SubString(0,$MiddlePart.IndexOf('>'))
                $LastPart   = $LineValue.SubString($FirstPart.Length+$MiddlePart.Length+2)
                Write-Host "`t$FirstPart" -NoNewLine
                Write-Host $MiddlePart -NoNewLine -ForegroundColor Cyan
                If($LastPart.Contains('<') -AND $LastPart.Contains('>'))
                {
                    $LineValue  = $LastPart
                    $FirstPart  = $LineValue.SubString(0,$LineValue.IndexOf('<'))
                    $MiddlePart = $LineValue.SubString($FirstPart.Length+1)
                    $MiddlePart = $MiddlePart.SubString(0,$MiddlePart.IndexOf('>'))
                    $LastPart   = $LineValue.SubString($FirstPart.Length+$MiddlePart.Length+2)
                    Write-Host "$FirstPart" -NoNewLine
                    If($MiddlePart.EndsWith("(PS3.0+)"))
                    {
                        Write-Host $MiddlePart -NoNewline -ForegroundColor Red
                    }
                    Else
                    {
                        Write-Host $MiddlePart -NoNewLine -ForegroundColor Cyan
                    }
                }
                Write-Host $LastPart
            }
            Else
            {
                Write-Host "`t$LineValue"
            }
        }
        Write-Host ''
        If($UserInput -ne '') {Write-Host ''}
        $UserInput = ''
        While(($UserInput -eq '') -AND ($Script:CompoundCommand.Count -eq 0))
        {
            Write-Host "Invoke-Obfuscation$BreadCrumb> " -NoNewLine -ForegroundColor Magenta
            If(($Script:CliCommands.Count -gt 0) -OR ($Script:CliCommands -ne $NULL))
            {
                If($Script:CliCommands.GetType().Name -eq 'String')
                {
                    $NextCliCommand = $Script:CliCommands.Trim()
                    $Script:CliCommands = @()
                }
                Else
                {
                    $NextCliCommand = ([String]$Script:CliCommands[0]).Trim()
                    $Script:CliCommands = For($i=1; $i -lt $Script:CliCommands.Count; $i++) {$Script:CliCommands[$i]}
                }
                $UserInput = $NextCliCommand
            }
            Else
            {
                If($CliWasSpecified -AND ($Script:CliCommands.Count -lt 1) -AND ($Script:CompoundCommand.Count -lt 1) -AND ($Script:QuietWasSpecified -OR !$NoExitWasSpecified))
                {
                    If($Script:QuietWasSpecified)
                    {
                        Remove-Item -Path Function:Write-Host
                        Remove-Item -Path Function:Start-Sleep
                        $Script:QuietWasSpecified = $FALSE
                        $UserInput  = 'show options'
                        $BreadCrumb = 'Show Options'
                    }
                    If(!$NoExitWasSpecified)
                    {
                        $UserInput = 'quit'
                    }
                }
                Else
                {
                    $UserInput = (Read-Host).Trim()
                }
                If(($Script:CliCommands.Count -eq 0) -AND !$UserInput.ToLower().StartsWith('set ') -AND $UserInput.Contains(','))
                {
                    $Script:CliCommands = $UserInput.Split(',')
                    $UserInput = ''
                }
            }
        }
        $UserInput = $UserInput.Trim('/\')
        If((($MenuLevel | ForEach-Object {$_[1].Trim()}) -Contains $UserInput.Split('/\')[0]) -AND !(('string' -Contains $UserInput.Split('/\')[0]) -AND ($MenuName -eq '_token')) -AND ($MenuName -ne ''))
        {
            $UserInput = 'home/' + $UserInput.Trim()
        }
        If(($Script:CompoundCommand.Count -eq 0) -AND !$UserInput.ToLower().StartsWith('set ') -AND !$UserInput.ToLower().StartsWith('out ') -AND ($UserInput.Contains('\') -OR $UserInput.Contains('/')))
        {
            $Script:CompoundCommand = $UserInput.Split('/\')
        }
        If($Script:CompoundCommand.Count -gt 0)
        {
            $UserInput = ''
            While(($UserInput -eq '') -AND ($Script:CompoundCommand.Count -gt 0))
            {
                If($Script:CompoundCommand.GetType().Name -eq 'String')
                {
                    $NextCompoundCommand = $Script:CompoundCommand.Trim()
                    $Script:CompoundCommand = @()
                }
                Else
                {
                    $NextCompoundCommand = ([String]$Script:CompoundCommand[0]).Trim()
                    $Temp = $Script:CompoundCommand
                    $Script:CompoundCommand = @()
                    For($i=1; $i -lt $Temp.Count; $i++)
                    {
                        $Script:CompoundCommand += $Temp[$i]
                    }
                }
                $UserInput = $NextCompoundCommand
            }
        }
        $TempUserInput = $UserInput.ToLower()
        @(97..122) | ForEach-Object {$TempUserInput = $TempUserInput.Replace([String]([Char]$_),'')}
        @(0..9)    | ForEach-Object {$TempUserInput = $TempUserInput.Replace($_,'')}
        $TempUserInput = $TempUserInput.Replace(' ','').Replace('+','').Replace('#','').Replace('\','').Replace('/','').Replace('-','').Replace('?','')
        If(($TempUserInput.Length -gt 0) -AND !($UserInput.Trim().ToLower().StartsWith('set ')) -AND !($UserInput.Trim().ToLower().StartsWith('out ')))
        {
            $UserInput = $UserInput.Replace('.*','_____').Replace('*','.*').Replace('_____','.*')
            If(!$UserInput.Trim().StartsWith('^') -AND !$UserInput.Trim().StartsWith('.*'))
            {
                $UserInput = '^' + $UserInput
            }
            If(!$UserInput.Trim().EndsWith('$') -AND !$UserInput.Trim().EndsWith('.*'))
            {
                $UserInput = $UserInput + '$'
            }
            Try
            {
                $MenuFiltered = ($Menu | Where-Object {($_[1].Trim() -Match $UserInput) -AND ($_[1].Trim().Length -gt 0)} | ForEach-Object {$_[1].Trim()})
            }
            Catch
            {
                Write-Host "`n`nERROR:" -NoNewLine -ForegroundColor Red
                Write-Host ' The current Regular Expression caused the following error:'
                write-host "       $_" -ForegroundColor Red
            }
            If($MenuFiltered -ne $NULL)
            {
                $UserInput = (Get-Random -Input $MenuFiltered).Trim()
                If($MenuFiltered.Count -gt 1)
                {
                    If($SelectionContainsCommand)
                    {
                        $ColorToOutput = 'Green'
                    }
                    Else
                    {
                        $ColorToOutput = 'Yellow'
                    }
                    Write-Host "`n`nRandomly selected " -NoNewline
                    Write-Host $UserInput -NoNewline -ForegroundColor $ColorToOutput
                    write-host " from the following filtered options: " -NoNewline
                    For($i=0; $i -lt $MenuFiltered.Count-1; $i++)
                    {
                        Write-Host $MenuFiltered[$i].Trim() -NoNewLine -ForegroundColor $ColorToOutput
                        Write-Host ', ' -NoNewLine
                    }
                    Write-Host $MenuFiltered[$MenuFiltered.Count-1].Trim() -NoNewLine -ForegroundColor $ColorToOutput
                }
            }
        }
        $OverrideAcceptableInput = $FALSE
        $MenusWithMultiSelectNumbers = @('\Launcher')
        If(($UserInput.Trim(' 0123456789').Length -eq 0) -AND $BreadCrumb.Contains('\') -AND ($MenusWithMultiSelectNumbers -Contains $BreadCrumb.SubString(0,$BreadCrumb.LastIndexOf('\'))))
        {
            $OverrideAcceptableInput = $TRUE
        }
        If($ExitInputOptions -Contains $UserInput.ToLower())
        {
            Return $ExitInputOptions[0]
        }
        ElseIf($MenuInputOptions -Contains $UserInput.ToLower())
        {
            If($BreadCrumb.Contains('\')) {$UserInput = $BreadCrumb.SubString(0,$BreadCrumb.LastIndexOf('\')).Replace('\','_')}
            Else {$UserInput = ''}
            Return $UserInput.ToLower()
        }
        ElseIf($HomeMenuInputOptions[0] -Contains $UserInput.ToLower())
        {
            Return $UserInput.ToLower()
        }
        ElseIf($UserInput.ToLower().StartsWith('set '))
        {
            $UserInputOptionName  = $NULL
            $UserInputOptionValue = $NULL
            $HasError = $FALSE
            $UserInputMinusSet = $UserInput.SubString(4).Trim()
            If($UserInputMinusSet.IndexOf(' ') -eq -1)
            {
                $HasError = $TRUE
                $UserInputOptionName  = $UserInputMinusSet.Trim()
            }
            Else
            {
                $UserInputOptionName  = $UserInputMinusSet.SubString(0,$UserInputMinusSet.IndexOf(' ')).Trim().ToLower()
                $UserInputOptionValue = $UserInputMinusSet.SubString($UserInputMinusSet.IndexOf(' ')).Trim()
            }
            If($SettableInputOptions -Contains $UserInputOptionName)
            {
                If($UserInputOptionValue.Length -eq 0) {$UserInputOptionName = 'emptyvalue'}
                Switch($UserInputOptionName.ToLower())
                {
                    'scriptpath' {
                        If($UserInputOptionValue -AND ((Test-Path $UserInputOptionValue) -OR ($UserInputOptionValue -Match '(http|https)://')))
                        {
                            $Script:ScriptBlock = ''
                            If($UserInputOptionValue -Match '(http|https)://')
                            {
                                $Script:ScriptBlock = (New-Object Net.WebClient).DownloadString($UserInputOptionValue)
                                $Script:ScriptPath                = $UserInputOptionValue
                                $Script:ObfuscatedCommand         = $Script:ScriptBlock
                                $Script:ObfuscatedCommandHistory  = @()
                                $Script:ObfuscatedCommandHistory += $Script:ScriptBlock
                                $Script:CliSyntax                 = @()
                                $Script:ExecutionCommands         = @()
                                $Script:LauncherApplied           = $FALSE
                                Write-Host "`n`nSuccessfully set ScriptPath (as URL):" -ForegroundColor Cyan
                                Write-Host $Script:ScriptPath -ForegroundColor Magenta
                            }
                            ElseIf ((Get-Item $UserInputOptionValue) -is [System.IO.DirectoryInfo])
                            {
                                Write-Host "`n`nERROR:" -NoNewLine -ForegroundColor Red
                                Write-Host ' Path is a directory instead of a file (' -NoNewLine
                                Write-Host "$UserInputOptionValue" -NoNewLine -ForegroundColor Cyan
                                Write-Host ").`n" -NoNewLine
                            }
                            Else
                            {
                                Get-ChildItem $UserInputOptionValue -ErrorAction Stop | Out-Null
                                $Script:ScriptBlock = [IO.File]::ReadAllText((Resolve-Path $UserInputOptionValue))
                                $Script:ScriptPath                = $UserInputOptionValue
                                $Script:ObfuscatedCommand         = $Script:ScriptBlock
                                $Script:ObfuscatedCommandHistory  = @()
                                $Script:ObfuscatedCommandHistory += $Script:ScriptBlock
                                $Script:CliSyntax                 = @()
                                $Script:ExecutionCommands         = @()
                                $Script:LauncherApplied           = $FALSE
                                Write-Host "`n`nSuccessfully set ScriptPath:" -ForegroundColor Cyan
                                Write-Host $Script:ScriptPath -ForegroundColor Magenta
                            }
                        }
                        Else
                        {
                            Write-Host "`n`nERROR:" -NoNewLine -ForegroundColor Red
                            Write-Host ' Path not found (' -NoNewLine
                            Write-Host "$UserInputOptionValue" -NoNewLine -ForegroundColor Cyan
                            Write-Host ").`n" -NoNewLine
                        }
                    }
                    'scriptblock' {
                        ForEach($Char in @(@('{','}'),@('"','"'),@("'","'")))
                        {
                            While($UserInputOptionValue.StartsWith($Char[0]) -AND $UserInputOptionValue.EndsWith($Char[1]))
                            {
                                $UserInputOptionValue = $UserInputOptionValue.SubString(1,$UserInputOptionValue.Length-2).Trim()
                            }
                        }
                        If($UserInputOptionValue -Match 'powershell(.exe | )\s*-(e |ec |en |enc |enco |encod |encode)\s*["'']*[a-z=]')
                        {
                            $EncodedCommand = $UserInputOptionValue.SubString($UserInputOptionValue.ToLower().IndexOf(' -e')+3)
                            $EncodedCommand = $EncodedCommand.SubString($EncodedCommand.IndexOf(' ')).Trim(" '`"")
                            $UserInputOptionValue = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($EncodedCommand))
                        }
                        $Script:ScriptPath                = 'N/A'
                        $Script:ScriptBlock               = $UserInputOptionValue
                        $Script:ObfuscatedCommand         = $UserInputOptionValue
                        $Script:ObfuscatedCommandHistory  = @()
                        $Script:ObfuscatedCommandHistory += $UserInputOptionValue
                        $Script:CliSyntax                 = @()
                        $Script:ExecutionCommands         = @()
                        $Script:LauncherApplied           = $FALSE
                        Write-Host "`n`nSuccessfully set ScriptBlock:" -ForegroundColor Cyan
                        Write-Host $Script:ScriptBlock -ForegroundColor Magenta
                    }
                    'emptyvalue' {
                        $HasError = $TRUE
                        Write-Host "`n`nERROR:" -NoNewLine -ForegroundColor Red
                        Write-Host ' No value was entered after' -NoNewLine
                        Write-Host ' SCRIPTBLOCK/SCRIPTPATH' -NoNewLine -ForegroundColor Cyan
                        Write-Host '.' -NoNewLine
                    }
                    default {Write-Error "An invalid OPTIONNAME ($UserInputOptionName) was passed to switch block."; Exit}
                }
            }
            Else
            {
                $HasError = $TRUE
                Write-Host "`n`nERROR:" -NoNewLine -ForegroundColor Red
                Write-Host ' OPTIONNAME' -NoNewLine
                Write-Host " $UserInputOptionName" -NoNewLine -ForegroundColor Cyan
                Write-Host " is not a settable option." -NoNewLine
            }
            If($HasError)
            {
                Write-Host "`n       Correct syntax is" -NoNewLine
                Write-Host ' SET OPTIONNAME VALUE' -NoNewLine -ForegroundColor Green
                Write-Host '.' -NoNewLine
                Write-Host "`n       Enter" -NoNewLine
                Write-Host ' SHOW OPTIONS' -NoNewLine -ForegroundColor Yellow
                Write-Host ' for more details.'
            }
        }
        ElseIf(($AcceptableInput -Contains $UserInput) -OR ($OverrideAcceptableInput))
        {
            $UserInput = $BreadCrumb.Trim('\').Replace('\','_') + '_' + $UserInput
            If($BreadCrumb.StartsWith('\')) {$UserInput = '_' + $UserInput}
            If($SelectionContainsCommand)
            {
                If($Script:ObfuscatedCommand -ne $NULL)
                {
                    ForEach($Line in $Menu)
                    {
                        If($Line[1].Trim(' ') -eq $UserInput.SubString($UserInput.LastIndexOf('_')+1)) {$CommandToExec = $Line[3]; Continue}
                    }
                    If(!$OverrideAcceptableInput)
                    {
                        $Function = $CommandToExec[0]
                        $Token    = $CommandToExec[1]
                        $ObfLevel = $CommandToExec[2]
                    }
                    Else
                    {
                        Switch($BreadCrumb.ToLower())
                        {
                            '\launcher\ps'       {$Function = 'Out-PowerShellLauncher'; $ObfLevel = 1}
                            '\launcher\cmd'      {$Function = 'Out-PowerShellLauncher'; $ObfLevel = 2}
                            '\launcher\wmic'     {$Function = 'Out-PowerShellLauncher'; $ObfLevel = 3}
                            '\launcher\rundll'   {$Function = 'Out-PowerShellLauncher'; $ObfLevel = 4}
                            '\launcher\var+'     {$Function = 'Out-PowerShellLauncher'; $ObfLevel = 5}
                            '\launcher\stdin+'   {$Function = 'Out-PowerShellLauncher'; $ObfLevel = 6}
                            '\launcher\clip+'    {$Function = 'Out-PowerShellLauncher'; $ObfLevel = 7}
                            '\launcher\var++'    {$Function = 'Out-PowerShellLauncher'; $ObfLevel = 8}
                            '\launcher\stdin++'  {$Function = 'Out-PowerShellLauncher'; $ObfLevel = 9}
                            '\launcher\clip++'   {$Function = 'Out-PowerShellLauncher'; $ObfLevel = 10}
                            '\launcher\rundll++' {$Function = 'Out-PowerShellLauncher'; $ObfLevel = 11}
                            '\launcher\mshta++'  {$Function = 'Out-PowerShellLauncher'; $ObfLevel = 12}
                            default {Write-Error "An invalid value ($($BreadCrumb.ToLower())) was passed to switch block for setting `$Function when `$OverrideAcceptableInput -eq `$TRUE."; Exit}
                        }
                        $ObfLevel = $Menu[1][3][2]
                        $Token = $UserInput.SubString($UserInput.LastIndexOf('_')+1)
                    }
                    If(!($Script:LauncherApplied))
                    {
                        $ObfCommandScriptBlock = $ExecutionContext.InvokeCommand.NewScriptBlock($Script:ObfuscatedCommand)
                    }
                    If($Script:ObfuscatedCommand -eq '')
                    {
                        Write-Host "`n`nERROR:" -NoNewLine -ForegroundColor Red
                        Write-Host " Cannot execute obfuscation commands without setting ScriptPath or ScriptBlock values in SHOW OPTIONS menu. Set these by executing" -NoNewLine
                        Write-Host ' SET SCRIPTBLOCK script_block_or_command' -NoNewLine -ForegroundColor Green
                        Write-Host ' or' -NoNewLine
                        Write-Host ' SET SCRIPTPATH path_to_script_or_URL' -NoNewLine -ForegroundColor Green
                        Write-Host '.'
                        Continue
                    }
                    $ObfuscatedCommandBefore = $Script:ObfuscatedCommand
                    $CmdToPrint = $NULL
                    If($Function -eq 'Out-ObfuscatedAst' -AND $PSVersionTable.PSVersion.Major -lt 3)
                    {
                        $AstPS3ErrorMessage = "AST obfuscation can only be used with PS3.0+. Update to PS3.0 or higher to use AST obfuscation."
                        If ($Script:QuietWasSpecified)
                        {
                            Write-Error $AstPS3ErrorMessage
                        }
                        Else
                        {
                            Write-Host "`n`nERROR: " -NoNewLine -ForegroundColor Red
                            Write-Host $AstPS3ErrorMessage -NoNewLine
                        }
                    }
                    ElseIf($Script:LauncherApplied)
                    {
                        If($Function -eq 'Out-PowerShellLauncher')
                        {
                            $ErrorMessage = ' You have already applied a launcher to ObfuscatedCommand.'
                        }
                        Else
                        {
                            $ErrorMessage = ' You cannot obfuscate after applying a Launcher to ObfuscatedCommand.'
                        }
                        Write-Host "`n`nERROR:" -NoNewLine -ForegroundColor Red
                        Write-Host $ErrorMessage -NoNewLine
                        Write-Host "`n       Enter" -NoNewLine
                        Write-Host ' UNDO' -NoNewLine -ForegroundColor Yellow
                        Write-Host " to remove the launcher from ObfuscatedCommand.`n" -NoNewLine
                    }
                    Else
                    {
                        Switch($Function)
                        {
                            'Out-ObfuscatedTokenCommand'        {
                                $Script:ObfuscatedCommand = Out-ObfuscatedTokenCommand        -ScriptBlock $ObfCommandScriptBlock $Token $ObfLevel
                                $CmdToPrint = @("Out-ObfuscatedTokenCommand -ScriptBlock "," '$Token' $ObfLevel")
                            }
                            'Out-ObfuscatedTokenCommandAll'     {
                                $Script:ObfuscatedCommand = Out-ObfuscatedTokenCommand        -ScriptBlock $ObfCommandScriptBlock
                                $CmdToPrint = @("Out-ObfuscatedTokenCommand -ScriptBlock ","")
                            }
                            'Out-ObfuscatedAst'                 {
                                $Script:ObfuscatedCommand = Out-ObfuscatedAst                 -ScriptBlock $ObfCommandScriptBlock -AstTypesToObfuscate $Token
                                $CmdToPrint = @("Out-ObfuscatedAst -ScriptBlock ","")
                            }
                            'Out-ObfuscatedStringCommand'       {
                                $Script:ObfuscatedCommand = Out-ObfuscatedStringCommand       -ScriptBlock $ObfCommandScriptBlock $ObfLevel
                                $CmdToPrint = @("Out-ObfuscatedStringCommand -ScriptBlock "," $ObfLevel")
                            }
                            'Out-EncodedAsciiCommand'           {
                                $Script:ObfuscatedCommand = Out-EncodedAsciiCommand           -ScriptBlock $ObfCommandScriptBlock -PassThru
                                $CmdToPrint = @("Out-EncodedAsciiCommand -ScriptBlock "," -PassThru")
                            }
                            'Out-EncodedHexCommand'             {
                                $Script:ObfuscatedCommand = Out-EncodedHexCommand             -ScriptBlock $ObfCommandScriptBlock -PassThru
                                $CmdToPrint = @("Out-EncodedHexCommand -ScriptBlock "," -PassThru")
                            }
                            'Out-EncodedOctalCommand'           {
                                $Script:ObfuscatedCommand = Out-EncodedOctalCommand           -ScriptBlock $ObfCommandScriptBlock -PassThru
                                $CmdToPrint = @("Out-EncodedOctalCommand -ScriptBlock "," -PassThru")
                            }
                            'Out-EncodedBinaryCommand'          {
                                $Script:ObfuscatedCommand = Out-EncodedBinaryCommand          -ScriptBlock $ObfCommandScriptBlock -PassThru
                                $CmdToPrint = @("Out-EncodedBinaryCommand -ScriptBlock "," -PassThru")
                            }
                            'Out-SecureStringCommand'           {
                                $Script:ObfuscatedCommand = Out-SecureStringCommand           -ScriptBlock $ObfCommandScriptBlock -PassThru
                                $CmdToPrint = @("Out-SecureStringCommand -ScriptBlock "," -PassThru")
                            }
                            'Out-EncodedBXORCommand'            {
                                $Script:ObfuscatedCommand = Out-EncodedBXORCommand            -ScriptBlock $ObfCommandScriptBlock -PassThru
                                $CmdToPrint = @("Out-EncodedBXORCommand -ScriptBlock "," -PassThru")
                            }
                            'Out-EncodedSpecialCharOnlyCommand' {
                                $Script:ObfuscatedCommand = Out-EncodedSpecialCharOnlyCommand -ScriptBlock $ObfCommandScriptBlock -PassThru
                                $CmdToPrint = @("Out-EncodedSpecialCharOnlyCommand -ScriptBlock "," -PassThru")
                            }
                            'Out-EncodedWhitespaceCommand' {
                                $Script:ObfuscatedCommand = Out-EncodedWhitespaceCommand      -ScriptBlock $ObfCommandScriptBlock -PassThru
                                $CmdToPrint = @("Out-EncodedWhitespaceCommand -ScriptBlock "," -PassThru")
                            }
                            'Out-CompressedCommand' {
                                $Script:ObfuscatedCommand = Out-CompressedCommand             -ScriptBlock $ObfCommandScriptBlock -PassThru
                                $CmdToPrint = @("Out-CompressedCommand -ScriptBlock "," -PassThru")
                            }
                            'Out-PowerShellLauncher'            {
                                $SwitchesAsStringArray = [char[]]$Token | Sort-Object -Unique | Where-Object {$_ -ne ' '}
                                If($SwitchesAsStringArray -Contains '0')
                                {
                                    $CmdToPrint = @("Out-PowerShellLauncher -ScriptBlock "," $ObfLevel")
                                }
                                Else
                                {
                                    $HasWindowStyle = $FALSE
                                    $SwitchesToPrint = @()
                                    ForEach($Value in $SwitchesAsStringArray)
                                    {
                                        Switch($Value)
                                        {
                                            1 {$SwitchesToPrint += '-NoExit'}
                                            2 {$SwitchesToPrint += '-NonInteractive'}
                                            3 {$SwitchesToPrint += '-NoLogo'}
                                            4 {$SwitchesToPrint += '-NoProfile'}
                                            5 {$SwitchesToPrint += '-Command'}
                                            6 {If(!$HasWindowStyle) {$SwitchesToPrint += '-WindowStyle Hidden'; $HasWindowStyle = $TRUE}}
                                            7 {$SwitchesToPrint += '-ExecutionPolicy Bypass'}
                                            8 {$SwitchesToPrint += '-Wow64'}
                                            default {Write-Error "An invalid `$SwitchesAsString value ($Value) was passed to switch block."; Exit;}
                                        }
                                    }
                                    $SwitchesToPrint =  $SwitchesToPrint -Join ' '
                                    $CmdToPrint = @("Out-PowerShellLauncher -ScriptBlock "," $SwitchesToPrint $ObfLevel")
                                }
                                $Script:ObfuscatedCommand = Out-PowerShellLauncher -ScriptBlock $ObfCommandScriptBlock -SwitchesAsString $Token $ObfLevel
                                If($ObfuscatedCommandBefore -ne $Script:ObfuscatedCommand)
                                {
                                    $Script:LauncherApplied = $TRUE
                                }
                            }
                            default {Write-Error "An invalid `$Function value ($Function) was passed to switch block."; Exit;}
                        }
                        If(($Script:ObfuscatedCommand -ceq $ObfuscatedCommandBefore) -AND ($MenuName.StartsWith('_Token_')))
                        {
                            Write-Host "`nWARNING:" -NoNewLine -ForegroundColor Red
                            Write-Host " There were not any" -NoNewLine
                            If($BreadCrumb.SubString($BreadCrumb.LastIndexOf('\')+1).ToLower() -ne 'all') {Write-Host " $($BreadCrumb.SubString($BreadCrumb.LastIndexOf('\')+1))" -NoNewLine -ForegroundColor Yellow}
                            Write-Host " tokens to further obfuscate, so nothing changed."
                        }
                        Else
                        {
                            $Script:ObfuscatedCommandHistory += , $Script:ObfuscatedCommand
                            $CliSyntaxCurrentCommand = $UserInput.Trim('_ ').Replace('_','\')
                            $Script:CliSyntax += $CliSyntaxCurrentCommand
                            $Script:ExecutionCommands += ($CmdToPrint[0] + '$ScriptBlock' + $CmdToPrint[1])
                            Write-Host "`nExecuted:`t"
                            Write-Host "  CLI:  " -NoNewline
                            Write-Host $CliSyntaxCurrentCommand -ForegroundColor Cyan
                            Write-Host "  FULL: " -NoNewline
                            Write-Host $CmdToPrint[0] -NoNewLine -ForegroundColor Cyan
                            Write-Host '$ScriptBlock' -NoNewLine -ForegroundColor Magenta
                            Write-Host $CmdToPrint[1] -ForegroundColor Cyan
                            Write-Host "`nResult:`t"
                            Out-ScriptContents $Script:ObfuscatedCommand -PrintWarning
                        }
                    }
                }
            }
            Else
            {
                Return $UserInput
            }
        }
        Else
        {
            If    ($MenuInputOptionsShowHelp[0]     -Contains $UserInput) {Show-HelpMenu}
            ElseIf($MenuInputOptionsShowOptions[0]  -Contains $UserInput) {Show-OptionsMenu}
            ElseIf($TutorialInputOptions[0]         -Contains $UserInput) {Show-Tutorial}
            ElseIf($ClearScreenInputOptions[0]      -Contains $UserInput) {Clear-Host}
            ElseIf($ResetObfuscationInputOptions[0] -Contains $UserInput)
            {
                If(($Script:ObfuscatedCommand -ne $NULL) -AND ($Script:ObfuscatedCommand.Length -eq 0))
                {
                    Write-Host "`n`nWARNING:" -NoNewLine -ForegroundColor Red
                    Write-Host " ObfuscatedCommand has not been set. There is nothing to reset."
                }
                ElseIf($Script:ObfuscatedCommand -ceq $Script:ScriptBlock)
                {
                    Write-Host "`n`nWARNING:" -NoNewLine -ForegroundColor Red
                    Write-Host " No obfuscation has been applied to ObfuscatedCommand. There is nothing to reset."
                }
                Else
                {
                    $Script:LauncherApplied = $FALSE
                    $Script:ObfuscatedCommand = $Script:ScriptBlock
                    $Script:ObfuscatedCommandHistory = @($Script:ScriptBlock)
                    $Script:CliSyntax         = @()
                    $Script:ExecutionCommands = @()
                    Write-Host "`n`nSuccessfully reset ObfuscatedCommand." -ForegroundColor Cyan
                }
            }
            ElseIf($UndoObfuscationInputOptions[0] -Contains $UserInput)
            {
                If(($Script:ObfuscatedCommand -ne $NULL) -AND ($Script:ObfuscatedCommand.Length -eq 0))
                {
                    Write-Host "`n`nWARNING:" -NoNewLine -ForegroundColor Red
                    Write-Host " ObfuscatedCommand has not been set. There is nothing to undo."
                }
                ElseIf($Script:ObfuscatedCommand -ceq $Script:ScriptBlock)
                {
                    Write-Host "`n`nWARNING:" -NoNewLine -ForegroundColor Red
                    Write-Host " No obfuscation has been applied to ObfuscatedCommand. There is nothing to undo."
                }
                Else
                {
                    $Script:ObfuscatedCommand = $Script:ObfuscatedCommandHistory[$Script:ObfuscatedCommandHistory.Count-2]
                    $Temp = $Script:ObfuscatedCommandHistory
                    $Script:ObfuscatedCommandHistory = @()
                    For($i=0; $i -lt $Temp.Count-1; $i++)
                    {
                        $Script:ObfuscatedCommandHistory += $Temp[$i]
                    }
                    $CliSyntaxCount = $Script:CliSyntax.Count
                    While(($Script:CliSyntax[$CliSyntaxCount-1] -Match '^(clip|out )') -AND ($CliSyntaxCount -gt 0))
                    {
                        $CliSyntaxCount--
                    }
                    $Temp = $Script:CliSyntax
                    $Script:CliSyntax = @()
                    For($i=0; $i -lt $CliSyntaxCount-1; $i++)
                    {
                        $Script:CliSyntax += $Temp[$i]
                    }
                    $Temp = $Script:ExecutionCommands
                    $Script:ExecutionCommands = @()
                    For($i=0; $i -lt $Temp.Count-1; $i++)
                    {
                        $Script:ExecutionCommands += $Temp[$i]
                    }
                    If($Script:LauncherApplied)
                    {
                        $Script:LauncherApplied = $FALSE
                        Write-Host "`n`nSuccessfully removed launcher from ObfuscatedCommand." -ForegroundColor Cyan
                    }
                    Else
                    {
                        Write-Host "`n`nSuccessfully removed last obfuscation from ObfuscatedCommand." -ForegroundColor Cyan
                    }
                }
            }
            ElseIf(($OutputToDiskInputOptions[0] -Contains $UserInput) -OR ($OutputToDiskInputOptions[0] -Contains $UserInput.Trim().Split(' ')[0]))
            {
                If(($Script:ObfuscatedCommand -ne '') -AND ($Script:ObfuscatedCommand -ceq $Script:ScriptBlock))
                {
                    Write-Host "`n`nWARNING:" -NoNewLine -ForegroundColor Red
                    Write-Host " You haven't applied any obfuscation.`n         Just enter" -NoNewLine
                    Write-Host " SHOW OPTIONS" -NoNewLine -ForegroundColor Yellow
                    Write-Host " and look at ObfuscatedCommand."
                }
                ElseIf($Script:ObfuscatedCommand -ne '')
                {
                    If($UserInput.Trim().Split(' ').Count -gt 1)
                    {
                        $UserInputOutputFilePath = $UserInput.Trim().SubString(4).Trim()
                        Write-Host ''
                    }
                    Else
                    {
                        $UserInputOutputFilePath = Read-Host "`n`nEnter path for output file (or leave blank for default)"
                    }                    
                    If($UserInputOutputFilePath.Trim() -eq '')
                    {
                        $OutputFilePath = "$ScriptDir\Obfuscated_Command.txt"
                    }
                    ElseIf(!($UserInputOutputFilePath.Contains('\')) -AND !($UserInputOutputFilePath.Contains('/')))
                    {
                        $OutputFilePath = "$ScriptDir\$($UserInputOutputFilePath.Trim())"
                    }
                    Else
                    {
                        $OutputFilePath = $UserInputOutputFilePath
                    }
                    $Script:ObfuscatedCommand | Out-File $OutputFilePath -Encoding ASCII
                    If($Script:LauncherApplied -AND (Test-Path $OutputFilePath))
                    {
                        $Script:CliSyntax += "out $OutputFilePath"
                        Write-Host "`nSuccessfully output ObfuscatedCommand to" -NoNewLine -ForegroundColor Cyan
                        Write-Host " $OutputFilePath" -NoNewLine -ForegroundColor Yellow
                        Write-Host ".`nA Launcher has been applied so this script cannot be run as a standalone .ps1 file." -ForegroundColor Cyan
                        If($Env:windir) { C:\Windows\Notepad.exe $OutputFilePath }
                    }
                    ElseIf(!$Script:LauncherApplied -AND (Test-Path $OutputFilePath))
                    {
                        $Script:CliSyntax += "out $OutputFilePath"
                        Write-Host "`nSuccessfully output ObfuscatedCommand to" -NoNewLine -ForegroundColor Cyan
                        Write-Host " $OutputFilePath" -NoNewLine -ForegroundColor Yellow
                        Write-Host "." -ForegroundColor Cyan
                        If($Env:windir) { C:\Windows\Notepad.exe $OutputFilePath }
                    }
                    Else
                    {
                        Write-Host "`nERROR: Unable to write ObfuscatedCommand out to" -NoNewLine -ForegroundColor Red
                        Write-Host " $OutputFilePath" -NoNewLine -ForegroundColor Yellow
                    }
                }
                ElseIf($Script:ObfuscatedCommand -eq '')
                {
                    Write-Host "`n`nERROR:" -NoNewLine -ForegroundColor Red
                    Write-Host " There isn't anything to write out to disk.`n       Just enter" -NoNewLine
                    Write-Host " SHOW OPTIONS" -NoNewLine -ForegroundColor Yellow
                    Write-Host " and look at ObfuscatedCommand."
                }
            }
            ElseIf($CopyToClipboardInputOptions[0] -Contains $UserInput)
            {
                If(($Script:ObfuscatedCommand -ne '') -AND ($Script:ObfuscatedCommand -ceq $Script:ScriptBlock))
                {
                    Write-Host "`n`nWARNING:" -NoNewLine -ForegroundColor Red
                    Write-Host " You haven't applied any obfuscation.`n         Just enter" -NoNewLine
                    Write-Host " SHOW OPTIONS" -NoNewLine -ForegroundColor Yellow
                    Write-Host " and look at ObfuscatedCommand."
                }
                ElseIf($Script:ObfuscatedCommand -ne '')
                {
                    Try
                    {
                        $Null = [Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
                        [Windows.Forms.Clipboard]::SetText($Script:ObfuscatedCommand)
                        If($Script:LauncherApplied)
                        {
                            Write-Host "`n`nSuccessfully copied ObfuscatedCommand to clipboard." -ForegroundColor Cyan
                        }
                        Else
                        {
                            Write-Host "`n`nSuccessfully copied ObfuscatedCommand to clipboard.`nNo Launcher has been applied, so command can only be pasted into powershell.exe." -ForegroundColor Cyan
                        }
                    }
                    Catch
                    {
                        $ErrorMessage = "Clipboard functionality will not work in PowerShell version $($PsVersionTable.PsVersion.Major) unless you add -STA (Single-Threaded Apartment) execution flag to powershell.exe."
                        If((Get-Command Write-Host).CommandType -ne 'Cmdlet')
                        {
                            . ((Get-Command Write-Host)  | Where-Object {$_.CommandType -eq 'Cmdlet'}) "`n`nWARNING: " -NoNewLine -ForegroundColor Red
                            . ((Get-Command Write-Host)  | Where-Object {$_.CommandType -eq 'Cmdlet'}) $ErrorMessage -NoNewLine
                            . ((Get-Command Start-Sleep) | Where-Object {$_.CommandType -eq 'Cmdlet'}) 2
                        }
                        Else
                        {
                            Write-Host "`n`nWARNING: " -NoNewLine -ForegroundColor Red
                            Write-Host $ErrorMessage
                            If($Script:CliSyntax -gt 0) {Start-Sleep 2}
                        }
                    }
                    $Script:CliSyntax += 'clip'
                }
                ElseIf($Script:ObfuscatedCommand -eq '')
                {
                    Write-Host "`n`nERROR:" -NoNewLine -ForegroundColor Red
                    Write-Host " There isn't anything to copy to your clipboard.`n       Just enter" -NoNewLine
                    Write-Host " SHOW OPTIONS" -NoNewLine -ForegroundColor Yellow
                    Write-Host " and look at ObfuscatedCommand." -NoNewLine
                }
            }
            ElseIf($ExecutionInputOptions[0] -Contains $UserInput)
            {
                If($Script:LauncherApplied)
                {
                    Write-Host "`n`nERROR:" -NoNewLine -ForegroundColor Red
                    Write-Host " Cannot execute because you have applied a Launcher.`n       Enter" -NoNewLine
                    Write-Host " COPY" -NoNewLine -ForeGroundColor Yellow
                    Write-Host "/" -NoNewLine
                    Write-Host "CLIP" -NoNewLine -ForeGroundColor Yellow
                    Write-Host " and paste into cmd.exe.`n       Or enter" -NoNewLine
                    Write-Host " UNDO" -NoNewLine -ForeGroundColor Yellow
                    Write-Host " to remove the Launcher from ObfuscatedCommand."
                }
                ElseIf($Script:ObfuscatedCommand -ne '')
                {
                    If($Script:ObfuscatedCommand -ceq $Script:ScriptBlock) {Write-Host "`n`nInvoking (though you haven't obfuscated anything yet):"}
                    Else {Write-Host "`n`nInvoking:"}
                    Out-ScriptContents $Script:ObfuscatedCommand
                    Write-Host ''
                    $null = Invoke-Expression $Script:ObfuscatedCommand
                }
                Else {
                    Write-Host "`n`nERROR:" -NoNewLine -ForegroundColor Red
                    Write-Host " Cannot execute because you have not set ScriptPath or ScriptBlock.`n       Enter" -NoNewline
                    Write-Host " SHOW OPTIONS" -NoNewLine -ForegroundColor Yellow
                    Write-Host " to set ScriptPath or ScriptBlock."
                }
            }
            Else
            {
                Write-Host "`n`nERROR:" -NoNewLine -ForegroundColor Red
                Write-Host " You entered an invalid option. Enter" -NoNewLine
                Write-Host " HELP" -NoNewLine -ForegroundColor Yellow
                Write-Host " for more information."
                If($Script:CompoundCommand.Count -gt 0)
                {
                    $Script:CompoundCommand = @()
                }
                If($AcceptableInput.Count -gt 1)
                {
                    $Message = 'Valid options for current menu include:'
                }
                Else
                {
                    $Message = 'Valid option for current menu includes:'
                }
                Write-Host "       $Message " -NoNewLine
                $Counter=0
                ForEach($AcceptableOption in $AcceptableInput)
                {
                    $Counter++
                    If($SelectionContainsCommand)
                    {
                        $ColorToOutput = 'Green'
                    }
                    Else
                    {
                        $ColorToOutput = 'Yellow'
                    }
                    Write-Host $AcceptableOption -NoNewLine -ForegroundColor $ColorToOutput
                    If(($Counter -lt $AcceptableInput.Length) -AND ($AcceptableOption.Length -gt 0))
                    {
                        Write-Host ', ' -NoNewLine
                    }
                }
                Write-Host ''
            }
        }
    }
    Return $UserInput.ToLower()
}
function Show-OptionsMenu
{
    $Counter = 0
    ForEach($Line in $Script:OptionsMenu)
    {
        If($Line[0].ToLower().Trim() -eq 'scriptpath')            {$Script:OptionsMenu[$Counter][1] = $Script:ScriptPath}
        If($Line[0].ToLower().Trim() -eq 'scriptblock')           {$Script:OptionsMenu[$Counter][1] = $Script:ScriptBlock}
        If($Line[0].ToLower().Trim() -eq 'commandlinesyntax')     {$Script:OptionsMenu[$Counter][1] = $Script:CliSyntax}
        If($Line[0].ToLower().Trim() -eq 'executioncommands')     {$Script:OptionsMenu[$Counter][1] = $Script:ExecutionCommands}
        If($Line[0].ToLower().Trim() -eq 'obfuscatedcommand')
        {
            If($Script:ObfuscatedCommand -cne $Script:ScriptBlock) {$Script:OptionsMenu[$Counter][1] = $Script:ObfuscatedCommand}
            Else {$Script:OptionsMenu[$Counter][1] = ''}
        }
        If($Line[0].ToLower().Trim() -eq 'obfuscationlength')
        {
            If(($Script:ObfuscatedCommand.Length -gt 0) -AND ($Script:ObfuscatedCommand -cne $Script:ScriptBlock)) {$Script:OptionsMenu[$Counter][1] = $Script:ObfuscatedCommand.Length}
            Else {$Script:OptionsMenu[$Counter][1] = ''}
        }
        $Counter++
    }
    Write-Host "`n`nSHOW OPTIONS" -NoNewLine -ForegroundColor Cyan
    Write-Host " ::" -NoNewLine
    Write-Host " Yellow" -NoNewLine -ForegroundColor Yellow
    Write-Host " options can be set by entering" -NoNewLine
    Write-Host " SET OPTIONNAME VALUE" -NoNewLine -ForegroundColor Green
    Write-Host ".`n"
    ForEach($Option in $Script:OptionsMenu)
    {
        $OptionTitle = $Option[0]
        $OptionValue = $Option[1]
        $CanSetValue = $Option[2]
        Write-Host $LineSpacing -NoNewLine
        If($CanSetValue) {Write-Host $OptionTitle -NoNewLine -ForegroundColor Yellow}
        Else {Write-Host $OptionTitle -NoNewLine}
        Write-Host ": " -NoNewLine
        If($OptionTitle -eq 'ObfuscationLength')
        {
            Write-Host $OptionValue -ForegroundColor Cyan
        }
        ElseIf($OptionTitle -eq 'ScriptBlock')
        {
            Out-ScriptContents $OptionValue
        }
        ElseIf($OptionTitle -eq 'CommandLineSyntax')
        {
            $SetSyntax = ''
            If(($Script:ScriptPath.Length -gt 0) -AND ($Script:ScriptPath -ne 'N/A'))
            {
                $SetSyntax = " -ScriptPath '$Script:ScriptPath'"
            }
            ElseIf(($Script:ScriptBlock.Length -gt 0) -AND ($Script:ScriptPath -eq 'N/A'))
            {
                $SetSyntax = " -ScriptBlock {$Script:ScriptBlock}"
            }
            $CommandSyntax = ''
            If($OptionValue.Count -gt 0)
            {
                $CommandSyntax = " -Command '" + ($OptionValue -Join ',') + "' -Quiet"
            }
            If(($SetSyntax -ne '') -OR ($CommandSyntax -ne ''))
            {
                $CliSyntaxToOutput = "Invoke-Obfuscation" + $SetSyntax + $CommandSyntax
                Write-Host $CliSyntaxToOutput -ForegroundColor Cyan
            }
            Else
            {
                Write-Host ''
            }
        }
        ElseIf($OptionTitle -eq 'ExecutionCommands')
        {
            If($OptionValue.Count -gt 0) {Write-Host ''}
            $Counter = 0
            ForEach($ExecutionCommand in $OptionValue)
            {
                $Counter++
                If($ExecutionCommand.Length -eq 0) {Write-Host ''; Continue}
                $ExecutionCommand = $ExecutionCommand.Replace('$ScriptBlock','~').Split('~')
                Write-Host "    $($ExecutionCommand[0])" -NoNewLine -ForegroundColor Cyan
                Write-Host '$ScriptBlock' -NoNewLine -ForegroundColor Magenta
                If(($OptionValue.Count -gt 0) -AND ($Counter -lt $OptionValue.Count))
                {
                    Write-Host $ExecutionCommand[1] -ForegroundColor Cyan
                }
                Else
                {
                    Write-Host $ExecutionCommand[1] -NoNewLine -ForegroundColor Cyan
                }
            }
            Write-Host ''
        }
        ElseIf($OptionTitle -eq 'ObfuscatedCommand')
        {
            Out-ScriptContents $OptionValue
        }
        Else
        {
            Write-Host $OptionValue -ForegroundColor Magenta
        }
    }
}
function Show-HelpMenu
{
    Write-Host "`n`nHELP MENU" -NoNewLine -ForegroundColor Cyan
    Write-Host " :: Available" -NoNewLine
    Write-Host " options" -NoNewLine -ForegroundColor Yellow
    Write-Host " shown below:`n"
    ForEach($InputOptionsList in $AllAvailableInputOptionsLists)
    {
        $InputOptionsCommands    = $InputOptionsList[0]
        $InputOptionsDescription = $InputOptionsList[1]
        If($InputOptionsDescription.Contains('<') -AND $InputOptionsDescription.Contains('>'))
        {
            $FirstPart  = $InputOptionsDescription.SubString(0,$InputOptionsDescription.IndexOf('<'))
            $MiddlePart = $InputOptionsDescription.SubString($FirstPart.Length+1)
            $MiddlePart = $MiddlePart.SubString(0,$MiddlePart.IndexOf('>'))
            $LastPart   = $InputOptionsDescription.SubString($FirstPart.Length+$MiddlePart.Length+2)
            Write-Host "$LineSpacing $FirstPart" -NoNewLine
            Write-Host $MiddlePart -NoNewLine -ForegroundColor Cyan
            Write-Host $LastPart -NoNewLine
        }
        Else
        {
            Write-Host "$LineSpacing $InputOptionsDescription" -NoNewLine
        }
        $Counter = 0
        ForEach($Command in $InputOptionsCommands)
        {
            $Counter++
            Write-Host $Command.ToUpper() -NoNewLine -ForegroundColor Yellow
            If($Counter -lt $InputOptionsCommands.Count) {Write-Host ',' -NoNewLine}
        }
        Write-Host ''
    }
}
function Show-Tutorial
{
    Write-Host "`n`nTUTORIAL" -NoNewLine -ForegroundColor Cyan
    Write-Host " :: Here is a quick tutorial showing you how to get your obfuscation on:"
    Write-Host "`n1) " -NoNewLine -ForegroundColor Cyan
    Write-Host "Load a scriptblock (SET SCRIPTBLOCK) or a script path/URL (SET SCRIPTPATH)."
    Write-Host "   SET SCRIPTBLOCK Write-Host 'This is my test command' -ForegroundColor Green" -ForegroundColor Green
    Write-Host "`n2) " -NoNewLine -ForegroundColor Cyan
    Write-Host "Navigate through the obfuscation menus where the options are in" -NoNewLine
    Write-Host " YELLOW" -NoNewLine -ForegroundColor Yellow
    Write-Host "."
    Write-Host "   GREEN" -NoNewLine -ForegroundColor Green
    Write-Host " options apply obfuscation."
    Write-Host "   Enter" -NoNewLine
    Write-Host " BACK" -NoNewLine -ForegroundColor Yellow
    Write-Host "/" -NoNewLine
    Write-Host "CD .." -NoNewLine -ForegroundColor Yellow
    Write-Host " to go to previous menu and" -NoNewLineInvoke-Obfuscation
    Write-Host " HOME" -NoNewline -ForegroundColor Yellow
    Write-Host "/" -NoNewline
    Write-Host "MAIN" -NoNewline -ForegroundColor Yellow
    Write-Host " to go to home menu.`n   E.g. Enter" -NoNewLine
    Write-Host " ENCODING" -NoNewLine -ForegroundColor Yellow
    Write-Host " & then" -NoNewLine
    Write-Host " 5" -NoNewLine -ForegroundColor Green
    Write-Host " to apply SecureString obfuscation."
    Write-Host "`n3) " -NoNewLine -ForegroundColor Cyan
    Write-Host "Enter" -NoNewLine
    Write-Host " TEST" -NoNewLine -ForegroundColor Yellow
    Write-Host "/" -NoNewLine
    Write-Host "EXEC" -NoNewLine -ForegroundColor Yellow
    Write-Host " to test the obfuscated command locally.`n   Enter" -NoNewLine
    Write-Host " SHOW" -NoNewLine -ForegroundColor Yellow
    Write-Host " to see the currently obfuscated command."
    Write-Host "`n4) " -NoNewLine -ForegroundColor Cyan
    Write-Host "Enter" -NoNewLine
    Write-Host " COPY" -NoNewLine -ForegroundColor Yellow
    Write-Host "/" -NoNewLine
    Write-Host "CLIP" -NoNewLine -ForegroundColor Yellow
    Write-Host " to copy obfuscated command out to your clipboard."
    Write-Host "   Enter" -NoNewLine
    Write-Host " OUT" -NoNewLine -ForegroundColor Yellow
    Write-Host " to write obfuscated command out to disk."
    Write-Host "`n5) " -NoNewLine -ForegroundColor Cyan
    Write-Host "Enter" -NoNewLine
    Write-Host " RESET" -NoNewLine -ForegroundColor Yellow
    Write-Host " to remove all obfuscation and start over.`n   Enter" -NoNewLine
    Write-Host " UNDO" -NoNewLine -ForegroundColor Yellow
    Write-Host " to undo last obfuscation.`n   Enter" -NoNewLine
    Write-Host " HELP" -NoNewLine -ForegroundColor Yellow
    Write-Host "/" -NoNewLine
    Write-Host "?" -NoNewLine -ForegroundColor Yellow
    Write-Host " for help menu."
    Write-Host "`nAnd finally the obligatory `"Don't use this for evil, please`"" -NoNewLine -ForegroundColor Cyan
    Write-Host " :)" -ForegroundColor Green
}
function Out-ScriptContents
{
    Param(
        [Parameter(ValueFromPipeline = $true)]
        [String]
        $ScriptContents,
        [Switch]
        $PrintWarning
    )
    If($ScriptContents.Length -gt $CmdMaxLength)
    {
        $RedactedPrintLength = $CmdMaxLength/5
        $CmdLineWidth = (Get-Host).UI.RawUI.BufferSize.Width
        $RedactionMessage = "<REDACTED: ObfuscatedLength = $($ScriptContents.Length)>"
        $CenteredRedactionMessageStartIndex = (($CmdLineWidth-$RedactionMessage.Length)/2) - "[*] ObfuscatedCommand: ".Length
        $CurrentRedactionMessageStartIndex = ($RedactedPrintLength % $CmdLineWidth)
        If($CurrentRedactionMessageStartIndex -gt $CenteredRedactionMessageStartIndex)
        {
            $RedactedPrintLength = $RedactedPrintLength-($CurrentRedactionMessageStartIndex-$CenteredRedactionMessageStartIndex)
        }
        Else
        {
            $RedactedPrintLength = $RedactedPrintLength+($CenteredRedactionMessageStartIndex-$CurrentRedactionMessageStartIndex)
        }
        Write-Host $ScriptContents.SubString(0,$RedactedPrintLength) -NoNewLine -ForegroundColor Magenta
        Write-Host $RedactionMessage -NoNewLine -ForegroundColor Yellow
        Write-Host $ScriptContents.SubString($ScriptContents.Length-$RedactedPrintLength) -ForegroundColor Magenta
    }
    Else
    {
        Write-Host $ScriptContents -ForegroundColor Magenta
    }
    If($ScriptContents.Length -gt $CmdMaxLength)
    {
        If($PSBoundParameters['PrintWarning'])
        {
            Write-Host "`nWARNING: This command exceeds the cmd.exe maximum length of $CmdMaxLength." -ForegroundColor Red
            Write-Host "         Its length is" -NoNewLine -ForegroundColor Red
            Write-Host " $($ScriptContents.Length)" -NoNewLine -ForegroundColor Yellow
            Write-Host " characters." -ForegroundColor Red
        }
    }
}          
function Show-AsciiArt
{
    [CmdletBinding()] Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Switch]
        $Random
    )
    $Spacing = "`t"
    $InvokeObfuscationAscii  = @()
    $InvokeObfuscationAscii += $Spacing + '    ____                 __                              '
    $InvokeObfuscationAscii += $Spacing + '   /  _/___ _   ______  / /_____                         '
    $InvokeObfuscationAscii += $Spacing + '   / // __ \ | / / __ \/ //_/ _ \______                  '
    $InvokeObfuscationAscii += $Spacing + ' _/ // / / / |/ / /_/ / ,< /  __/_____/                  '
    $InvokeObfuscationAscii += $Spacing + '/______ /__|_________/_/|_|\___/         __  _           '
    $InvokeObfuscationAscii += $Spacing + '  / __ \/ /_  / __/_  ________________ _/ /_(_)___  ____ '
    $InvokeObfuscationAscii += $Spacing + ' / / / / __ \/ /_/ / / / ___/ ___/ __ `/ __/ / __ \/ __ \'
    $InvokeObfuscationAscii += $Spacing + '/ /_/ / /_/ / __/ /_/ (__  ) /__/ /_/ / /_/ / /_/ / / / /'
    $InvokeObfuscationAscii += $Spacing + '\____/_.___/_/  \__,_/____/\___/\__,_/\__/_/\____/_/ /_/ '
    If(!$PSBoundParameters['Random'])
    {
        $ArrowAscii  = @()
        $ArrowAscii += '  |  '
        $ArrowAscii += '  |  '
        $ArrowAscii += ' \ / '
        $ArrowAscii += '  V  '
        Write-Host "`nIEX( ( '36{78Q55@32t61_91{99@104X97{114Q91-32t93}32t93}32t34@110m111@105}115X115-101m114_112@120@69-45{101@107X111m118m110-73Q124Q32X41Q57@51-93Q114_97_104t67t91{44V39Q112_81t109@39}101{99@97}108{112}101}82_45m32_32X52{51Q93m114@97-104{67t91t44t39V98t103V48t39-101}99}97V108}112t101_82_45{32@41X39{41_112t81_109_39m43{39-110t101@112{81t39X43@39t109_43t112_81Q109t101X39Q43m39}114Q71_112{81m109m39@43X39V32Q40}32m39_43_39{114-111m108t111t67{100m110{117Q39_43m39-111-114Q103_101t114@39m43-39{111t70-45}32m41}98{103V48V110Q98t103{48@39{43{39-43{32t98m103_48{111@105t98@103V48-39@43{39_32-32V43V32}32t98t103@48X116m97V99t98X103t48_39V43m39@43-39X43Q39_98@103@48}115V117V102Q98V79m45@98m39Q43{39X103_39X43Q39V48}43-39}43t39}98-103{48V101_107Q39t43X39_111X118X110V39X43}39t98_103{48@43}32_98{103}48{73{98-39@43t39m103_39}43{39{48Q32t39X43X39-32{40V32t41{39Q43V39m98X103{39_43V39{48-116{115Q79{39_43_39}98}103m48{39Q43t39X32X43{32_98@103-39@43m39X48_72-39_43t39V45m39t43Q39_101Q98}103_48-32_39Q43V39V32t39V43}39m43Q32V98X39Q43_39@103_48V39@43Q39@116X73t82V119m98-39{43_39}103Q48X40_46_32m39}40_40{34t59m91@65V114V114@97_121}93Q58Q58V82Q101Q118Q101{114}115_101m40_36_78m55@32t41t32-59{32}73{69V88m32{40t36V78t55}45Q74m111@105-110m32X39V39-32}41'.SpLiT( '{_Q-@t}mXV' ) |ForEach-Object { ([Int]`$_ -AS [Char]) } ) -Join'' )" -ForegroundColor Cyan
        Start-Sleep -Milliseconds 650
        ForEach($Line in $ArrowAscii) {Write-Host $Line -NoNewline; Write-Host $Line -NoNewline; Write-Host $Line -NoNewline; Write-Host $Line}
        Start-Sleep -Milliseconds 100
        Write-Host "`$N7 =[char[ ] ] `"noisserpxE-ekovnI| )93]rahC[,'pQm'ecalpeR-  43]rahC[,'bg0'ecalpeR- )')pQm'+'nepQ'+'m+pQme'+'rGpQm'+' ( '+'roloCdnu'+'orger'+'oF- )bg0nbg0'+'+ bg0oibg0'+'  +  bg0tacbg0'+'+'+'bg0sufbO-b'+'g'+'0+'+'bg0ek'+'ovn'+'bg0+ bg0Ib'+'g'+'0 '+' ( )'+'bg'+'0tsO'+'bg0'+' + bg'+'0H'+'-'+'ebg0 '+' '+'+ b'+'g0'+'tIRwb'+'g0(. '((`";[Array]::Reverse(`$N7 ) ; IEX (`$N7-Join '' )" -ForegroundColor Magenta
        Start-Sleep -Milliseconds 650
        ForEach($Line in $ArrowAscii) {Write-Host $Line -NoNewline; Write-Host $Line -NoNewline; Write-Host $Line}
        Start-Sleep -Milliseconds 100
        Write-Host ".(`"wRIt`" +  `"e-H`" + `"Ost`") (  `"I`" +`"nvoke`"+`"-Obfus`"+`"cat`"  +  `"io`" +`"n`") -ForegroundColor ( 'Gre'+'en')" -ForegroundColor Yellow
        Start-Sleep -Milliseconds 650
        ForEach($Line in $ArrowAscii) {Write-Host $Line -NoNewline;  Write-Host $Line}
        Start-Sleep -Milliseconds 100
        Write-Host "Write-Host `"Invoke-Obfuscation`" -ForegroundColor Green" -ForegroundColor White
        Start-Sleep -Milliseconds 650
        ForEach($Line in $ArrowAscii) {Write-Host $Line}
        Start-Sleep -Milliseconds 100
        Start-Sleep -Milliseconds 100
        ForEach($Char in [Char[]]'Invoke-Obfuscation')
        {
            Start-Sleep -Milliseconds (Get-Random -Input @(25..200))
            Write-Host $Char -NoNewline -ForegroundColor Green
        }
        Start-Sleep -Milliseconds 900
        Write-Host ""
        Start-Sleep -Milliseconds 300
        Write-Host
        $RandomColor = (Get-Random -Input @('Green','Cyan','Yellow'))
        ForEach($Line in $InvokeObfuscationAscii)
        {
            Write-Host $Line -ForegroundColor $RandomColor
        }
    }
    Else
    {
    }
    Write-Host ""
    Write-Host "`tTool    :: Invoke-Obfuscation" -ForegroundColor Magenta
    Write-Host "`tAuthor  :: Daniel Bohannon (DBO)" -ForegroundColor Magenta
    Write-Host "`tTwitter :: @danielhbohannon" -ForegroundColor Magenta
    Write-Host "`tBlog    :: http://danielbohannon.com" -ForegroundColor Magenta
    Write-Host "`tGithub  :: https://github.com/danielbohannon/Invoke-Obfuscation" -ForegroundColor Magenta
    Write-Host "`tVersion :: 1.8" -ForegroundColor Magenta
    Write-Host "`tLicense :: Apache License, Version 2.0" -ForegroundColor Magenta
    Write-Host "`tNotes   :: If(!`$Caffeinated) {Exit}" -ForegroundColor Magenta
}
#}
#function Out-CompressedCommand {
function Out-CompressedCommand
{
    [CmdletBinding(DefaultParameterSetName = 'FilePath')] Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ParameterSetName = 'ScriptBlock')]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]
        $ScriptBlock,
        [Parameter(Position = 0, ParameterSetName = 'FilePath')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,
        [Switch]
        $NoExit,
        [Switch]
        $NoProfile,
        [Switch]
        $NonInteractive,
        [Switch]
        $NoLogo,
        [Switch]
        $Wow64,
        [Switch]
        $Command,
        [ValidateSet('Normal', 'Minimized', 'Maximized', 'Hidden')]
        [String]
        $WindowStyle,
        [ValidateSet('Bypass', 'Unrestricted', 'RemoteSigned', 'AllSigned', 'Restricted')]
        [String]
        $ExecutionPolicy,
        [Switch]
        $PassThru
    )
    If($PSBoundParameters['Path'])
    {
        Get-ChildItem $Path -ErrorAction Stop | Out-Null
        $ScriptString = [IO.File]::ReadAllBytes((Resolve-Path $Path))
    }
    Else
    {
        $ScriptString = ([Text.Encoding]::ASCII).GetBytes($ScriptBlock)
    }
    $CompressedStream = New-Object IO.MemoryStream
    $DeflateStream = New-Object IO.Compression.DeflateStream ($CompressedStream, [IO.Compression.CompressionMode]::Compress)
    $DeflateStream.Write($ScriptString, 0, $ScriptString.Length)
    $DeflateStream.Dispose()
    $CompressedScriptBytes = $CompressedStream.ToArray()
    $CompressedStream.Dispose()
    $EncodedCompressedScript = [Convert]::ToBase64String($CompressedScriptBytes)
    $StreamReader     = Get-Random -Input @('IO.StreamReader','System.IO.StreamReader')
    $DeflateStream    = Get-Random -Input @('IO.Compression.DeflateStream','System.IO.Compression.DeflateStream')
    $MemoryStream     = Get-Random -Input @('IO.MemoryStream','System.IO.MemoryStream')
    $Convert          = Get-Random -Input @('Convert','System.Convert')
    $CompressionMode  = Get-Random -Input @('IO.Compression.CompressionMode','System.IO.Compression.CompressionMode')
    $Encoding         = Get-Random -Input @('Text.Encoding','System.Text.Encoding')
    $ForEachObject    = Get-Random -Input @('ForEach','ForEach-Object','%')
    $StreamReader     = ([Char[]]$StreamReader      | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $DeflateStream    = ([Char[]]$DeflateStream     | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $MemoryStream     = ([Char[]]$MemoryStream      | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $Convert          = ([Char[]]$Convert           | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $CompressionMode  = ([Char[]]$CompressionMode   | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $Encoding         = ([Char[]]$Encoding          | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $NewObject        = ([Char[]]'New-Object'       | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $FromBase64       = ([Char[]]'FromBase64String' | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $Decompress       = ([Char[]]'Decompress'       | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $Ascii            = ([Char[]]'Ascii'            | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $ReadToEnd        = ([Char[]]'ReadToEnd'        | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $ForEachObject    = ([Char[]]$ForEachObject     | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $ForEachObject2   = ([Char[]]$ForEachObject     | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $Base64 = ' '*(Get-Random -Input @(0,1)) + "[$Convert]::$FromBase64(" + ' '*(Get-Random -Input @(0,1)) + "'$EncodedCompressedScript'" + ' '*(Get-Random -Input @(0,1)) + ")" + ' '*(Get-Random -Input @(0,1))
    $DeflateStreamSyntax = ' '*(Get-Random -Input @(0,1)) + "$DeflateStream(" + ' '*(Get-Random -Input @(0,1)) + "[$MemoryStream]$Base64," + ' '*(Get-Random -Input @(0,1)) + "[$CompressionMode]::$Decompress" + ' '*(Get-Random -Input @(0,1)) + ")" + ' '*(Get-Random -Input @(0,1))
    $NewScriptArray   = @()
    $NewScriptArray  += "(" + ' '*(Get-Random -Input @(0,1)) + "$NewObject " + ' '*(Get-Random -Input @(0,1)) + "$StreamReader(" + ' '*(Get-Random -Input @(0,1)) + "(" + ' '*(Get-Random -Input @(0,1)) + "$NewObject $DeflateStreamSyntax)" + ' '*(Get-Random -Input @(0,1)) + "," + ' '*(Get-Random -Input @(0,1)) + "[$Encoding]::$Ascii)" + ' '*(Get-Random -Input @(0,1)) + ").$ReadToEnd(" + ' '*(Get-Random -Input @(0,1)) + ")"
    $NewScriptArray  += "(" + ' '*(Get-Random -Input @(0,1)) + "$NewObject $DeflateStreamSyntax|" + ' '*(Get-Random -Input @(0,1)) + "$ForEachObject" + ' '*(Get-Random -Input @(0,1)) + "{" + ' '*(Get-Random -Input @(0,1)) + "$NewObject " + ' '*(Get-Random -Input @(0,1)) + "$StreamReader(" + ' '*(Get-Random -Input @(0,1)) + "`$_" + ' '*(Get-Random -Input @(0,1)) + "," + ' '*(Get-Random -Input @(0,1)) + "[$Encoding]::$Ascii" + ' '*(Get-Random -Input @(0,1)) + ")" + ' '*(Get-Random -Input @(0,1)) + "}" + ' '*(Get-Random -Input @(0,1)) + ").$ReadToEnd(" + ' '*(Get-Random -Input @(0,1)) + ")"
    $NewScriptArray  += "(" + ' '*(Get-Random -Input @(0,1)) + "$NewObject $DeflateStreamSyntax|" + ' '*(Get-Random -Input @(0,1)) + "$ForEachObject" + ' '*(Get-Random -Input @(0,1)) + "{" + ' '*(Get-Random -Input @(0,1)) + "$NewObject " + ' '*(Get-Random -Input @(0,1)) + "$StreamReader(" + ' '*(Get-Random -Input @(0,1)) + "`$_" + ' '*(Get-Random -Input @(0,1)) + "," + ' '*(Get-Random -Input @(0,1)) + "[$Encoding]::$Ascii" + ' '*(Get-Random -Input @(0,1)) + ")" + ' '*(Get-Random -Input @(0,1)) + "}" + ' '*(Get-Random -Input @(0,1)) + "|" + ' '*(Get-Random -Input @(0,1)) + "$ForEachObject2" + ' '*(Get-Random -Input @(0,1)) + "{" + ' '*(Get-Random -Input @(0,1)) + "`$_.$ReadToEnd(" + ' '*(Get-Random -Input @(0,1)) + ")" + ' '*(Get-Random -Input @(0,1)) + "}" + ' '*(Get-Random -Input @(0,1)) + ")"
    $NewScript = (Get-Random -Input $NewScriptArray)
    $InvokeExpressionSyntax  = @()
    $InvokeExpressionSyntax += (Get-Random -Input @('IEX','Invoke-Expression'))
    $InvocationOperator = (Get-Random -Input @('.','&')) + ' '*(Get-Random -Input @(0,1))
    $InvokeExpressionSyntax += $InvocationOperator + "( `$ShellId[1]+`$ShellId[13]+'x')"
    $InvokeExpressionSyntax += $InvocationOperator + "( `$PSHome[" + (Get-Random -Input @(4,21)) + "]+`$PSHome[" + (Get-Random -Input @(30,34)) + "]+'x')"
    $InvokeExpressionSyntax += $InvocationOperator + "( `$env:ComSpec[4," + (Get-Random -Input @(15,24,26)) + ",25]-Join'')"
    $InvokeExpressionSyntax += $InvocationOperator + "((" + (Get-Random -Input @('Get-Variable','GV','Variable')) + " '*mdr*').Name[3,11,2]-Join'')"
    $InvokeExpressionSyntax += $InvocationOperator + "( " + (Get-Random -Input @('$VerbosePreference.ToString()','([String]$VerbosePreference)')) + "[1,3]+'x'-Join'')"
    $InvokeExpression = (Get-Random -Input $InvokeExpressionSyntax)
    $InvokeExpression = ([Char[]]$InvokeExpression | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $InvokeOptions  = @()
    $InvokeOptions += ' '*(Get-Random -Input @(0,1)) + $InvokeExpression + ' '*(Get-Random -Input @(0,1)) + $NewScript + ' '*(Get-Random -Input @(0,1))
    $InvokeOptions += ' '*(Get-Random -Input @(0,1)) + $NewScript + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $InvokeExpression
    $NewScript = (Get-Random -Input $InvokeOptions)
    If(!$PSBoundParameters['PassThru'])
    {
        $PowerShellFlags = @()
        $CommandlineOptions = New-Object String[](0)
        If($PSBoundParameters['NoExit'])
        {
          $FullArgument = "-NoExit";
          $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 4 -Maximum ($FullArgument.Length+1)))
        }
        If($PSBoundParameters['NoProfile'])
        {
          $FullArgument = "-NoProfile";
          $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 4 -Maximum ($FullArgument.Length+1)))
        }
        If($PSBoundParameters['NonInteractive'])
        {
          $FullArgument = "-NonInteractive";
          $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 5 -Maximum ($FullArgument.Length+1)))
        }
        If($PSBoundParameters['NoLogo'])
        {
          $FullArgument = "-NoLogo";
          $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 4 -Maximum ($FullArgument.Length+1)))
        }
        If($PSBoundParameters['WindowStyle'] -OR $WindowsStyle)
        {
            $FullArgument = "-WindowStyle"
            If($WindowsStyle) {$ArgumentValue = $WindowsStyle}
            Else {$ArgumentValue = $PSBoundParameters['WindowStyle']}
            Switch($ArgumentValue.ToLower())
            {
                'normal'    {If(Get-Random -Input @(0..1)) {$ArgumentValue = 0}}
                'hidden'    {If(Get-Random -Input @(0..1)) {$ArgumentValue = 1}}
                'minimized' {If(Get-Random -Input @(0..1)) {$ArgumentValue = 2}}
                'maximized' {If(Get-Random -Input @(0..1)) {$ArgumentValue = 3}}
                default {Write-Error "An invalid `$ArgumentValue value ($ArgumentValue) was passed to switch block for Out-PowerShellLauncher."; Exit;}
            }
            $PowerShellFlags += $FullArgument.SubString(0,(Get-Random -Minimum 2 -Maximum ($FullArgument.Length+1))) + ' '*(Get-Random -Minimum 1 -Maximum 3) + $ArgumentValue
        }
        If($PSBoundParameters['ExecutionPolicy'] -OR $ExecutionPolicy)
        {
            $FullArgument = "-ExecutionPolicy"
            If($ExecutionPolicy) {$ArgumentValue = $ExecutionPolicy}
            Else {$ArgumentValue = $PSBoundParameters['ExecutionPolicy']}
            $ExecutionPolicyFlags = @()
            $ExecutionPolicyFlags += '-EP'
            For($Index=3; $Index -le $FullArgument.Length; $Index++)
            {
                $ExecutionPolicyFlags += $FullArgument.SubString(0,$Index)
            }
            $ExecutionPolicyFlag = Get-Random -Input $ExecutionPolicyFlags
            $PowerShellFlags += $ExecutionPolicyFlag + ' '*(Get-Random -Minimum 1 -Maximum 3) + $ArgumentValue
        }
        If($CommandlineOptions.Count -gt 1)
        {
            $CommandlineOptions = Get-Random -InputObject $CommandlineOptions -Count $CommandlineOptions.Count
        }
        If($PSBoundParameters['Command'])
        {
            $FullArgument = "-Command"
            $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 2 -Maximum ($FullArgument.Length+1)))
        }
        For($i=0; $i -lt $PowerShellFlags.Count; $i++)
        {
            $PowerShellFlags[$i] = ([Char[]]$PowerShellFlags[$i] | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
        }
        $CommandlineOptions = ($CommandlineOptions | ForEach-Object {$_ + " "*(Get-Random -Minimum 1 -Maximum 3)}) -Join ''
        $CommandlineOptions = " "*(Get-Random -Minimum 0 -Maximum 3) + $CommandlineOptions + " "*(Get-Random -Minimum 0 -Maximum 3)
        If($PSBoundParameters['Wow64'])
        {
            $CommandLineOutput = "$($Env:windir)\SysWOW64\WindowsPowerShell\v1.0\powershell.exe $($CommandlineOptions) `"$NewScript`""
        }
        Else
        {
            $CommandLineOutput = "powershell $($CommandlineOptions) `"$NewScript`""
        }
        $CmdMaxLength = 8190
        If($CommandLineOutput.Length -gt $CmdMaxLength)
        {
            Write-Warning "This command exceeds the cmd.exe maximum allowed length of $CmdMaxLength characters! Its length is $($CmdLineOutput.Length) characters."
        }
        $NewScript = $CommandLineOutput
    }
    Return $NewScript
}
#}
#function Out-SecureStringCommand {
function Out-SecureStringCommand
{
    [CmdletBinding(DefaultParameterSetName = 'FilePath')] Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ParameterSetName = 'ScriptBlock')]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]
        $ScriptBlock,
        [Parameter(Position = 0, ParameterSetName = 'FilePath')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,
        [Switch]
        $NoExit,
        [Switch]
        $NoProfile,
        [Switch]
        $NonInteractive,
        [Switch]
        $NoLogo,
        [Switch]
        $Wow64,
        [Switch]
        $Command,
        [ValidateSet('Normal', 'Minimized', 'Maximized', 'Hidden')]
        [String]
        $WindowStyle,
        [ValidateSet('Bypass', 'Unrestricted', 'RemoteSigned', 'AllSigned', 'Restricted')]
        [String]
        $ExecutionPolicy,
        [Switch]
        $PassThru
    )
    If($PSBoundParameters['Path'])
    {
        Get-ChildItem $Path -ErrorAction Stop | Out-Null
        $ScriptString = [IO.File]::ReadAllText((Resolve-Path $Path))
    }
    Else
    {
        $ScriptString = [String]$ScriptBlock
    }
    $SecureString = ConvertTo-SecureString $ScriptString -AsPlainText -Force
    $KeyLength = Get-Random @(16,24,32)
    Switch(Get-Random -Minimum 1 -Maximum 3)
    { 
        1 {
            $SecureStringKey = @()
            For($i=0; $i -lt $KeyLength; $i++) {
                $SecureStringKey += Get-Random -Minimum 0 -Maximum 256
            }
            $SecureStringKeyStr = $SecureStringKey -Join ','
          }
        2 {
            $LowerBound = (Get-Random -Minimum 0 -Maximum (256-$KeyLength))
            $UpperBound = $LowerBound + ($KeyLength - 1)
            Switch(Get-Random @('Ascending','Descending'))
            {
                'Ascending'  {$SecureStringKey = ($LowerBound..$UpperBound); $SecureStringKeyStr = "($LowerBound..$UpperBound)"}
                'Descending' {$SecureStringKey = ($UpperBound..$LowerBound); $SecureStringKeyStr = "($UpperBound..$LowerBound)"}
                default {Write-Error "An invalid array ordering option was generated for switch block."; Exit;}
            }
          }
        default {Write-Error "An invalid random number was generated for switch block."; Exit;}
    }
    $SecureStringText = $SecureString | ConvertFrom-SecureString -Key $SecureStringKey
    $Key = (Get-Random -Input @(' -Key ',' -Ke ',' -K '))
    $PtrToStringAuto = (Get-Random -Input @('PtrToStringAuto',('([Runtime.InteropServices.Marshal].GetMembers()[' + (Get-Random -Input @(3,5)) + '].Name).Invoke')))
    $PtrToStringUni  = (Get-Random -Input @('PtrToStringUni' ,('([Runtime.InteropServices.Marshal].GetMembers()[' + (Get-Random -Input @(2,4)) + '].Name).Invoke')))
    $PtrToStringAnsi = (Get-Random -Input @('PtrToStringAnsi',('([Runtime.InteropServices.Marshal].GetMembers()[' + (Get-Random -Input @(0,1)) + '].Name).Invoke')))
    $PtrToStringAuto                  = ([Char[]]"[Runtime.InteropServices.Marshal]::$PtrToStringAuto("                 | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $PtrToStringUni                   = ([Char[]]"[Runtime.InteropServices.Marshal]::$PtrToStringUni("                  | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $PtrToStringAnsi                  = ([Char[]]"[Runtime.InteropServices.Marshal]::$PtrToStringAnsi("                 | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $PtrToStringBSTR                  = ([Char[]]'[Runtime.InteropServices.Marshal]::PtrToStringBSTR('                  | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $SecureStringToBSTR               = ([Char[]]'[Runtime.InteropServices.Marshal]::SecureStringToBSTR('               | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $SecureStringToGlobalAllocUnicode = ([Char[]]'[Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode(' | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $SecureStringToGlobalAllocAnsi    = ([Char[]]'[Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocAnsi('    | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $NewObject                        = ([Char[]]'New-Object '                                                          | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $PSCredential                     = ([Char[]]'Management.Automation.PSCredential '                                  | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $ConvertToSecureString            = ([Char[]]'ConvertTo-SecureString'                                               | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $Key                              = ([Char[]]$Key                                                                   | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $GetNetworkCredential             = ([Char[]]').GetNetworkCredential().Password'                                    | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $ConvertToSecureStringSyntax = '$(' + "'$SecureStringText'" + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $ConvertToSecureString + ' '*(Get-Random -Input @(0,1)) + $Key + ' '*(Get-Random -Input @(0,1)) + $SecureStringKeyStr + ')' + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + ')'
    $NewScriptArray = @()
    $NewScriptArray += '(' + ' '*(Get-Random -Input @(0,1)) + $PtrToStringAuto + ' '*(Get-Random -Input @(0,1)) + $SecureStringToBSTR               + ' '*(Get-Random -Input @(0,1)) + $ConvertToSecureStringSyntax
    $NewScriptArray += '(' + ' '*(Get-Random -Input @(0,1)) + $PtrToStringUni  + ' '*(Get-Random -Input @(0,1)) + $SecureStringToGlobalAllocUnicode + ' '*(Get-Random -Input @(0,1)) + $ConvertToSecureStringSyntax
    $NewScriptArray += '(' + ' '*(Get-Random -Input @(0,1)) + $PtrToStringAnsi + ' '*(Get-Random -Input @(0,1)) + $SecureStringToGlobalAllocAnsi    + ' '*(Get-Random -Input @(0,1)) + $ConvertToSecureStringSyntax
    $NewScriptArray += '(' + ' '*(Get-Random -Input @(0,1)) + $PtrToStringBSTR + ' '*(Get-Random -Input @(0,1)) + $SecureStringToBSTR               + ' '*(Get-Random -Input @(0,1)) + $ConvertToSecureStringSyntax
    $NewScriptArray += '(' + ' '*(Get-Random -Input @(0,1)) + $NewObject + ' '*(Get-Random -Input @(0,1)) + $PSCredential + ' '*(Get-Random -Input @(0,1)) + "' '" + ',' + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + "'$SecureStringText'" + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $ConvertToSecureString + ' '*(Get-Random -Input @(0,1)) + $Key + ' '*(Get-Random -Input @(0,1)) + $SecureStringKeyStr + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + $GetNetworkCredential
    $NewScript = (Get-Random -Input $NewScriptArray)
    $InvokeExpressionSyntax  = @()
    $InvokeExpressionSyntax += (Get-Random -Input @('IEX','Invoke-Expression'))
    $InvocationOperator = (Get-Random -Input @('.','&')) + ' '*(Get-Random -Input @(0,1))
    $InvokeExpressionSyntax += $InvocationOperator + "( `$ShellId[1]+`$ShellId[13]+'x')"
    $InvokeExpressionSyntax += $InvocationOperator + "( `$PSHome[" + (Get-Random -Input @(4,21)) + "]+`$PSHome[" + (Get-Random -Input @(30,34)) + "]+'x')"
    $InvokeExpressionSyntax += $InvocationOperator + "( `$env:ComSpec[4," + (Get-Random -Input @(15,24,26)) + ",25]-Join'')"
    $InvokeExpressionSyntax += $InvocationOperator + "((" + (Get-Random -Input @('Get-Variable','GV','Variable')) + " '*mdr*').Name[3,11,2]-Join'')"
    $InvokeExpressionSyntax += $InvocationOperator + "( " + (Get-Random -Input @('$VerbosePreference.ToString()','([String]$VerbosePreference)')) + "[1,3]+'x'-Join'')"
    $InvokeExpression = (Get-Random -Input $InvokeExpressionSyntax)
    $InvokeExpression = ([Char[]]$InvokeExpression | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $InvokeOptions  = @()
    $InvokeOptions += ' '*(Get-Random -Input @(0,1)) + $InvokeExpression + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $NewScript + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1))
    $InvokeOptions += ' '*(Get-Random -Input @(0,1)) + $NewScript + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $InvokeExpression
    $NewScript = (Get-Random -Input $InvokeOptions)
    If(!$PSBoundParameters['PassThru'])
    {
        $PowerShellFlags = @()
        $CommandlineOptions = New-Object String[](0)
        If($PSBoundParameters['NoExit'])
        {
          $FullArgument = "-NoExit";
          $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 4 -Maximum ($FullArgument.Length+1)))
        }
        If($PSBoundParameters['NoProfile'])
        {
          $FullArgument = "-NoProfile";
          $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 4 -Maximum ($FullArgument.Length+1)))
        }
        If($PSBoundParameters['NonInteractive'])
        {
          $FullArgument = "-NonInteractive";
          $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 5 -Maximum ($FullArgument.Length+1)))
        }
        If($PSBoundParameters['NoLogo'])
        {
          $FullArgument = "-NoLogo";
          $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 4 -Maximum ($FullArgument.Length+1)))
        }
        If($PSBoundParameters['WindowStyle'] -OR $WindowsStyle)
        {
            $FullArgument = "-WindowStyle"
            If($WindowsStyle) {$ArgumentValue = $WindowsStyle}
            Else {$ArgumentValue = $PSBoundParameters['WindowStyle']}
            Switch($ArgumentValue.ToLower())
            {
                'normal'    {If(Get-Random -Input @(0..1)) {$ArgumentValue = (Get-Random -Input @('0','n','no','nor','norm','norma'))}}
                'hidden'    {If(Get-Random -Input @(0..1)) {$ArgumentValue = (Get-Random -Input @('1','h','hi','hid','hidd','hidde'))}}
                'minimized' {If(Get-Random -Input @(0..1)) {$ArgumentValue = (Get-Random -Input @('2','mi','min','mini','minim','minimi','minimiz','minimize'))}}
                'maximized' {If(Get-Random -Input @(0..1)) {$ArgumentValue = (Get-Random -Input @('3','ma','max','maxi','maxim','maximi','maximiz','maximize'))}}
                default {Write-Error "An invalid `$ArgumentValue value ($ArgumentValue) was passed to switch block for Out-PowerShellLauncher."; Exit;}
            }
            $PowerShellFlags += $FullArgument.SubString(0,(Get-Random -Minimum 2 -Maximum ($FullArgument.Length+1))) + ' '*(Get-Random -Minimum 1 -Maximum 3) + $ArgumentValue
        }
        If($PSBoundParameters['ExecutionPolicy'] -OR $ExecutionPolicy)
        {
            $FullArgument = "-ExecutionPolicy"
            If($ExecutionPolicy) {$ArgumentValue = $ExecutionPolicy}
            Else {$ArgumentValue = $PSBoundParameters['ExecutionPolicy']}
            $ExecutionPolicyFlags = @()
            $ExecutionPolicyFlags += '-EP'
            For($Index=3; $Index -le $FullArgument.Length; $Index++)
            {
                $ExecutionPolicyFlags += $FullArgument.SubString(0,$Index)
            }
            $ExecutionPolicyFlag = Get-Random -Input $ExecutionPolicyFlags
            $PowerShellFlags += $ExecutionPolicyFlag + ' '*(Get-Random -Minimum 1 -Maximum 3) + $ArgumentValue
        }
        If($CommandlineOptions.Count -gt 1)
        {
            $CommandlineOptions = Get-Random -InputObject $CommandlineOptions -Count $CommandlineOptions.Count
        }
        If($PSBoundParameters['Command'])
        {
            $FullArgument = "-Command"
            $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 2 -Maximum ($FullArgument.Length+1)))
        }
        For($i=0; $i -lt $PowerShellFlags.Count; $i++)
        {
            $PowerShellFlags[$i] = ([Char[]]$PowerShellFlags[$i] | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
        }
        $CommandlineOptions = ($CommandlineOptions | ForEach-Object {$_ + " "*(Get-Random -Minimum 1 -Maximum 3)}) -Join ''
        $CommandlineOptions = " "*(Get-Random -Minimum 0 -Maximum 3) + $CommandlineOptions + " "*(Get-Random -Minimum 0 -Maximum 3)
        If($PSBoundParameters['Wow64'])
        {
            $CommandLineOutput = "C:\WINDOWS\SysWOW64\WindowsPowerShell\v1.0\powershell.exe $($CommandlineOptions) `"$NewScript`""
        }
        Else
        {
            $CommandLineOutput = "powershell $($CommandlineOptions) `"$NewScript`""
        }
        $CmdMaxLength = 8190
        If($CommandLineOutput.Length -gt $CmdMaxLength)
        {
                Write-Warning "This command exceeds the cmd.exe maximum allowed length of $CmdMaxLength characters! Its length is $($CmdLineOutput.Length) characters."
        }
        $NewScript = $CommandLineOutput
    }
    Return $NewScript
}
#}
#function Out-PowerShellLauncher {
function Out-PowerShellLauncher
{
    [CmdletBinding(DefaultParameterSetName = 'ScriptBlock')] Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ParameterSetName = 'ScriptBlock')]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]
        $ScriptBlock,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet(1,2,3,4,5,6,7,8,9,10,11,12)]
        [Int]
        $LaunchType,
        [Switch]
        $NoExit,
        [Switch]
        $NoProfile,
        [Switch]
        $NonInteractive,
        [Switch]
        $NoLogo,
        [Switch]
        $Wow64,
        [Switch]
        $Command,
        [ValidateSet('Normal', 'Minimized', 'Maximized', 'Hidden')]
        [String]
        $WindowStyle,
        [ValidateSet('Bypass', 'Unrestricted', 'RemoteSigned', 'AllSigned', 'Restricted')]
        [String]
        $ExecutionPolicy,
        [Parameter(Position = 2)]
        [String]
        $SwitchesAsString
    )
    $ArgsDefenderWillSee = @()
    $ScriptString = [String]$ScriptBlock
    If($ScriptString.Contains([Char]13+[Char]10))
    {
        Write-Host ""
        Write-Warning "Current script content contains newline characters.`n         Applying a launcher will not work on the command line.`n         Apply ENCODING obfuscation before applying LAUNCHER."
        Start-Sleep 1
        Return $ScriptString
    }
    If($SwitchesAsString.Length -gt 0)
    {
        If(!($SwitchesAsString.Contains('0')))
        {
            $SwitchesAsString = ([Char[]]$SwitchesAsString | Sort-Object -Unique -Descending) -Join ' '
            ForEach($SwitchAsString in $SwitchesAsString.Split(' '))
            {
                Switch($SwitchAsString)
                {
                    '1' {$NoExit          = $TRUE}
                    '2' {$NonInteractive  = $TRUE}
                    '3' {$NoLogo          = $TRUE}
                    '4' {$NoProfile       = $TRUE}
                    '5' {$Command         = $TRUE}
                    '6' {$WindowsStyle    = 'Hidden'}
                    '7' {$ExecutionPolicy = 'Bypass'}
                    '8' {$Wow64           = $TRUE}
                    default {Write-Error "An invalid `$SwitchAsString value ($SwitchAsString) was passed to switch block for Out-PowerShellLauncher"; Exit;}
                }
            }
        }
    }
    $Tokens = [System.Management.Automation.PSParser]::Tokenize($ScriptString,[ref]$null)
    $CharsToEscape = @('&','|','<','>')
    For($i=$Tokens.Count-1; $i -ge 0; $i--)
    {
        $Token = $Tokens[$i]
        $PreTokenStr    = $ScriptString.SubString(0,$Token.Start)
        $ExtractedToken = $ScriptString.SubString($Token.Start,$Token.Length)
        $PostTokenStr   = $ScriptString.SubString($Token.Start+$Token.Length)
        If($Token.Type -eq 'String' -AND !($ExtractedToken.StartsWith("'") -AND $ExtractedToken.EndsWith("'")))
        {
            ForEach($Char in $CharsToEscape)
            {
                If($ExtractedToken.Contains($Char)) {$ExtractedToken = $ExtractedToken.Replace($Char,"^$Char")}
            }
            If($ExtractedToken.Contains('\')) {$ExtractedToken = $ExtractedToken.Replace('\','\\')}
            If($ExtractedToken.Contains('"')) {$ExtractedToken = '\"' + $ExtractedToken.SubString(1,$ExtractedToken.Length-1-1) + '\"'}
        }
        Else
        {
            If($ExtractedToken.Contains('^'))
            {
                $ExtractedTokenSplit = $ExtractedToken.Split('^')
                $ExtractedToken = ''
                For($j=0; $j -lt $ExtractedTokenSplit.Count; $j++)
                {
                    $ExtractedToken += $ExtractedTokenSplit[$j]
                    $FirstCharFollowingCaret = $ExtractedTokenSplit[$j+1]
                    If(!$FirstCharFollowingCaret -OR ($CharsToEscape -NotContains $FirstCharFollowingCaret.SubString(0,1)) -AND ($j -ne $ExtractedTokenSplit.Count-1))
                    {
                        $ExtractedToken += '^^^^'
                    }
                }
            }
            ForEach($Char in $CharsToEscape)
            {
                If($ExtractedToken.Contains($Char)) {$ExtractedToken = $ExtractedToken.Replace($Char,"^^^$Char")}
            }
        }
        $ScriptString = $PreTokenStr + $ExtractedToken + $PostTokenStr
    }
    $PowerShellFlags = New-Object String[](0)
    If($PSBoundParameters['NoExit'] -OR $NoExit)
    {
        $FullArgument = "-NoExit"
        $PowerShellFlags += $FullArgument.SubString(0,(Get-Random -Minimum 4 -Maximum ($FullArgument.Length+1)))
    }
    If($PSBoundParameters['NoProfile'] -OR $NoProfile)
    {
        $FullArgument = "-NoProfile"
        $PowerShellFlags += $FullArgument.SubString(0,(Get-Random -Minimum 4 -Maximum ($FullArgument.Length+1)))
    }
    If($PSBoundParameters['NonInteractive'] -OR $NonInteractive)
    {
        $FullArgument = "-NonInteractive"
        $PowerShellFlags += $FullArgument.SubString(0,(Get-Random -Minimum 5 -Maximum ($FullArgument.Length+1)))
    }
    If($PSBoundParameters['NoLogo'] -OR $NoLogo)
    {
        $FullArgument = "-NoLogo"
        $PowerShellFlags += $FullArgument.SubString(0,(Get-Random -Minimum 4 -Maximum ($FullArgument.Length+1)))
    }
    If($PSBoundParameters['WindowStyle'] -OR $WindowsStyle)
    {
        $FullArgument = "-WindowStyle"
        If($WindowsStyle) {$ArgumentValue = $WindowsStyle}
        Else {$ArgumentValue = $PSBoundParameters['WindowStyle']}
        Switch($ArgumentValue.ToLower())
        {
            'normal'    {If(Get-Random -Input @(0..1)) {$ArgumentValue = (Get-Random -Input @('0','n','no','nor','norm','norma'))}}
            'hidden'    {If(Get-Random -Input @(0..1)) {$ArgumentValue = (Get-Random -Input @('1','h','hi','hid','hidd','hidde'))}}
            'minimized' {If(Get-Random -Input @(0..1)) {$ArgumentValue = (Get-Random -Input @('2','mi','min','mini','minim','minimi','minimiz','minimize'))}}
            'maximized' {If(Get-Random -Input @(0..1)) {$ArgumentValue = (Get-Random -Input @('3','ma','max','maxi','maxim','maximi','maximiz','maximize'))}}
            default {Write-Error "An invalid `$ArgumentValue value ($ArgumentValue) was passed to switch block for Out-PowerShellLauncher."; Exit;}
        }
        $PowerShellFlags += $FullArgument.SubString(0,(Get-Random -Minimum 2 -Maximum ($FullArgument.Length+1))) + ' '*(Get-Random -Minimum 1 -Maximum 3) + $ArgumentValue
    }
    If($PSBoundParameters['ExecutionPolicy'] -OR $ExecutionPolicy)
    {
        $FullArgument = "-ExecutionPolicy"
        If($ExecutionPolicy) {$ArgumentValue = $ExecutionPolicy}
        Else {$ArgumentValue = $PSBoundParameters['ExecutionPolicy']}
        $ExecutionPolicyFlags = @()
        $ExecutionPolicyFlags += '-EP'
        For($Index=3; $Index -le $FullArgument.Length; $Index++)
        {
            $ExecutionPolicyFlags += $FullArgument.SubString(0,$Index)
        }
        $ExecutionPolicyFlag = Get-Random -Input $ExecutionPolicyFlags
        $PowerShellFlags += $ExecutionPolicyFlag + ' '*(Get-Random -Minimum 1 -Maximum 3) + $ArgumentValue
    }
    If($PowerShellFlags.Count -gt 1)
    {
        $PowerShellFlags = Get-Random -InputObject $PowerShellFlags -Count $PowerShellFlags.Count
    }
    If($PSBoundParameters['Command'] -OR $Command)
    {
        $FullArgument = "-Command"
        $PowerShellFlags += $FullArgument.SubString(0,(Get-Random -Minimum 2 -Maximum ($FullArgument.Length+1)))
    }
    For($i=0; $i -lt $PowerShellFlags.Count; $i++)
    {
        $PowerShellFlags[$i] = ([Char[]]$PowerShellFlags[$i] | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    }
    $PowerShellFlagsArray = $PowerShellFlags
    $PowerShellFlags = ($PowerShellFlags | ForEach-Object {$_ + ' '*(Get-Random -Minimum 1 -Maximum 3)}) -Join ''
    $PowerShellFlags = ' '*(Get-Random -Minimum 1 -Maximum 3) + $PowerShellFlags + ' '*(Get-Random -Minimum 1 -Maximum 3)
    $WinPath      = "C:\WINDOWS"
    $System32Path = "C:\WINDOWS\system32"
    $PathToRunDll = Get-Random -Input @("$System32Path\rundll32"  , "$System32Path\rundll32.exe"  , "rundll32" , "rundll32.exe")
    $PathToMshta  = Get-Random -Input @("$System32Path\mshta"     , "$System32Path\mshta.exe"     , "mshta"    , "mshta.exe")
    $PathToCmd    = Get-Random -Input @("$System32Path\cmd"       , "$System32Path\cmd.exe"       , "cmd.exe"  , "cmd")
    $PathToClip   = Get-Random -Input @("$System32Path\clip"      , "$System32Path\clip.exe"      , "clip"     , "clip.exe")
    $PathToWmic   = Get-Random -Input @("$System32Path\WBEM\wmic" , "$System32Path\WBEM\wmic.exe" , "wmic"     , "wmic.exe")
    If($PathToCmd.Contains('\'))
    {
        $PathToCmd = $PathToCmd + ' '*(Get-Random -Minimum 2 -Maximum 4)
    }
    Else
    {
        $PathToCmd = $PathToCmd + ' '*(Get-Random -Minimum 0 -Maximum 4)
    }
    If($PSBoundParameters['Wow64'] -OR $Wow64)
    {
        $PathToPowerShell = "$WinPath\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
    }
    Else
    {
        $PathToPowerShell = "powershell"
    }
    $PowerShellFlags  = ([Char[]]$PowerShellFlags.ToLower()  | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
    $PathToPowerShell = ([Char[]]$PathToPowerShell.ToLower() | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
    $PathToRunDll     = ([Char[]]$PathToRunDll.ToLower()     | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
    $PathToMshta      = ([Char[]]$PathToMshta.ToLower()      | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
    $PathToCmd        = ([Char[]]$PathToCmd.ToLower()        | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
    $PathToClip       = ([Char[]]$PathToClip.ToLower()       | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
    $PathToWmic       = ([Char[]]$PathToWmic.ToLower()       | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
    $SlashC           = ([Char[]]'/c'.ToLower()              | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
    $Echo             = ([Char[]]'echo'.ToLower()            | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
    $NumberOfDoubleQuotes = $ScriptString.Length-$ScriptString.Replace('"','').Length
    If($NumberOfDoubleQuotes%2 -eq 1)
    {
        Write-Host ""
        Write-Warning "This command contains an unbalanced number of double quotes ($NumberOfDoubleQuotes).`n         Try applying STRING or ENCODING obfuscation options first to encode the double quotes.`n"
        Start-Sleep 1
        Return $ScriptString
    }
    If($LaunchType -eq 0)
    {
        $LaunchType = Get-Random -Input @(3..12)
    }
    Switch($LaunchType)
    {
        1 {
              ForEach($Char in $CharsToEscape)
              {
                  If($ScriptString.Contains("^^^$Char")) {$ScriptString = $ScriptString.Replace("^^^$Char",$Char)}
              }
              If($ScriptString.Contains('^^^^'))
              {
                  $ScriptString = $ScriptString.Replace('^^^^','^')
              }
              $PSCmdSyntax = $PowerShellFlags + '"' + $ScriptString + '"'
              $ArgsDefenderWillSee += , @($PathToPowerShell, $PSCmdSyntax)
              $CmdLineOutput = $PathToPowerShell + $PSCmdSyntax
          }
        2 {
              ForEach($Char in $CharsToEscape)
              {
                  If($ScriptString.Contains("^^^$Char")) {$ScriptString = $ScriptString.Replace("^^^$Char",$Char)}
                  If($ScriptString.Contains("^$Char")) {$ScriptString = $ScriptString.Replace("^$Char","^^^$Char")}
              }
              If($ScriptString.Contains('^^^^'))
              {
                  $ScriptString = $ScriptString.Replace('^^^^','^')
              }
              $PSCmdSyntax = $PowerShellFlags + '"' + $ScriptString + '"'
              $CmdSyntax   = $SlashC + ' '*(Get-Random -Minimum 0 -Maximum 4) + $PathToPowerShell + $PSCmdSyntax
              $ArgsDefenderWillSee += , @($PathToCmd       , $CmdSyntax)
              $ArgsDefenderWillSee += , @($PathToPowerShell, $PSCmdSyntax)
              $CmdLineOutput = $PathToCmd + $CmdSyntax
          }
        3 {
              For($i=1; $i -le 12; $i++)
              {
                  $StringToReplace = '${' + ' '*$i + '}'
                  If($ScriptString.Contains($StringToReplace))
                  {
                      $ScriptString = $ScriptString.Replace($StringToReplace,$StringToReplace.Replace(' ','\ '))
                  }
              }
              ForEach($Char in $CharsToEscape)
              {
                  While($ScriptString.Contains('^' + $Char))
                  {
                      $ScriptString = $ScriptString.Replace(('^' + $Char),$Char)
                  }
              }
              If($ScriptString.Contains('^^^^'))
              {
                  $ScriptString = $ScriptString.Replace('^^^^','^')
              }
              If($ScriptString.Contains(','))
              {
                  $SetVariables = ''
                  If($ScriptString.Contains('$'))
                  {
                      $ScriptString = $ScriptString.Replace('$','`$')
                      If($ScriptString.Contains('``$'))
                      {
                          $ScriptString = $ScriptString.Replace('``$','```$')
                      }
                  }
                  If($ScriptString.Contains('`"'))
                  {
                      $ScriptString = $ScriptString.Replace('`"','``"')
                  }
                  If($ScriptString.Contains('"'))
                  {
                      While($ScriptString.Contains('\"'))
                      {
                          $ScriptString = $ScriptString.Replace('\"','"')
                      }
                      $CharCastDoubleQuote = ([Char[]](Get-Random -Input @('[String][Char]34','([Char]34).ToString()')) | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
                      If($ScriptString.Length-$ScriptString.Replace('"','').Length -le 5)
                      {
                          $SubstitutionSyntax  = ('\"' + ' '*(Get-Random -Minimum 0 -Maximum 3) + '+' + ' '*(Get-Random -Minimum 0 -Maximum 3) + $CharCastDoubleQuote + ' '*(Get-Random -Minimum 0 -Maximum 3) + '+' + ' '*(Get-Random -Minimum 0 -Maximum 3) + '\"')
                          $ScriptString        = $ScriptString.Replace('"',$SubstitutionSyntax).Replace('\"\"+','').Replace('\"\" +','').Replace('\"\"  +','').Replace('\"\"   +','')
                      }
                      Else
                      {
                          $CharsToRandomVarName  = @(0..9)
                          $CharsToRandomVarName += @('A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z')
                          $RandomVarLength = (Get-Random -Input @(1..2))
                          If($CharsToRandomVarName.Count -lt $RandomVarLength) {$RandomVarLength = $CharsToRandomVarName.Count}
                          $RandomVarName = ((Get-Random -Input $CharsToRandomVarName -Count $RandomVarLength) -Join '').Replace(' ','')
                          While($ScriptString.ToLower().Contains($RandomVarName.ToLower()))
                          {
                              $RandomVarName = ((Get-Random -Input $CharsToRandomVarName -Count $RandomVarLength) -Join '').Replace(' ','')
                              $RandomVarLength++
                          }
                          $RandomVarNameMaybeConcatenated = $RandomVarName
                          If((Get-Random -Input @(0..1)) -eq 0)
                          {
                              $RandomVarNameMaybeConcatenated = '(' + (Out-ConcatenatedString $RandomVarName "'") + ')'
                          }
                          $RandomVarSetSyntax  = @()
                          $RandomVarSetSyntax += '$' + $RandomVarName + ' '*(Get-Random @(0..2)) + '=' + ' '*(Get-Random @(0..2)) + $CharCastDoubleQuote
                          $RandomVarSetSyntax += (Get-Random -Input @('Set-Variable','SV','Set')) + ' '*(Get-Random @(1..2)) + $RandomVarNameMaybeConcatenated + ' '*(Get-Random @(1..2)) + '(' + ' '*(Get-Random @(0..2)) + $CharCastDoubleQuote + ' '*(Get-Random @(0..2)) + ')'
                          $RandomVarSet = (Get-Random -Input $RandomVarSetSyntax)
                          $SetVariables += $RandomVarSet + ' '*(Get-Random @(1..2)) + ';'
                          $ScriptString = $ScriptString.Replace('"',"`${$RandomVarName}")
                      }
                  }
                  $CharCastComma= ([Char[]](Get-Random -Input @('[String][Char]44','([Char]44).ToString()')) | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
                  If($ScriptString.Length-$ScriptString.Replace(',','').Length -le 5)
                  {
                      $SubstitutionSyntax  = ('\"' + ' '*(Get-Random -Minimum 0 -Maximum 3) + '+' + ' '*(Get-Random -Minimum 0 -Maximum 3) + $CharCastComma + ' '*(Get-Random -Minimum 0 -Maximum 3) + '+' + ' '*(Get-Random -Minimum 0 -Maximum 3) + '\"')
                      $ScriptString        = $ScriptString.Replace(',',$SubstitutionSyntax).Replace('\"\"+','').Replace('\"\" +','').Replace('\"\"  +','').Replace('\"\"   +','')
                  }
                  Else
                  {
                      $CharsToRandomVarName  = @(0..9)
                      $CharsToRandomVarName += @('A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z')
                      $RandomVarLength = (Get-Random -Input @(1..2))
                      If($CharsToRandomVarName.Count -lt $RandomVarLength) {$RandomVarLength = $CharsToRandomVarName.Count}
                      $RandomVarName = ((Get-Random -Input $CharsToRandomVarName -Count $RandomVarLength) -Join '').Replace(' ','')
                      While($ScriptString.ToLower().Contains($RandomVarName.ToLower()))
                      {
                          $RandomVarName = ((Get-Random -Input $CharsToRandomVarName -Count $RandomVarLength) -Join '').Replace(' ','')
                          $RandomVarLength++
                      }
                      $RandomVarNameMaybeConcatenated = $RandomVarName
                      If((Get-Random -Input @(0..1)) -eq 0)
                      {
                          $RandomVarNameMaybeConcatenated = '(' + (Out-ConcatenatedString $RandomVarName "'") + ')'
                      }
                      $RandomVarSetSyntax  = @()
                      $RandomVarSetSyntax += '$' + $RandomVarName + ' '*(Get-Random @(0..2)) + '=' + ' '*(Get-Random @(0..2)) + $CharCastComma
                      $RandomVarSetSyntax += (Get-Random -Input @('Set-Variable','SV','Set')) + ' '*(Get-Random @(1..2)) + $RandomVarNameMaybeConcatenated + ' '*(Get-Random @(1..2)) + '(' + ' '*(Get-Random @(0..2)) + $CharCastComma + ' '*(Get-Random @(0..2)) + ')'
                      $RandomVarSet = (Get-Random -Input $RandomVarSetSyntax)
                      $SetVariables += $RandomVarSet + ' '*(Get-Random @(1..2)) + ';'
                      $ScriptString = $ScriptString.Replace(',',"`${$RandomVarName}")
                  }
                  $ScriptString =  '\"' + $ScriptString + '\"'
                  $ScriptStringTemp = ','
                  While($ScriptStringTemp.Contains(','))
                  {
                      $ScriptStringTemp = Out-EncapsulatedInvokeExpression $ScriptString
                  }
                  $ScriptString = $ScriptStringTemp
                  $ScriptString = $SetVariables + $ScriptString
              }
              $WmicArguments = ([Char[]]'process call create' | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $WmicArguments = (($WmicArguments.Split(' ') | ForEach-Object {$RandomQuotes = (Get-Random -Input @('"',"'",' ')); $RandomQuotes + $_ + $RandomQuotes + ' '*(Get-Random -Minimum 1 -Maximum 4)}) -Join '').Trim()
              If($ScriptString.Contains('\"'))
              {
                  $ScriptString = $ScriptString.Replace('\"','"\"')
              }
              $PSCmdSyntax   = $PowerShellFlags + $ScriptString
              $WmicCmdSyntax = ' '*(Get-Random -Minimum 1 -Maximum 4) + $WmicArguments + ' '*(Get-Random -Minimum 1 -Maximum 4) + '"' + $PathToPowerShell + $PSCmdSyntax + '"'
              $ArgsDefenderWillSee += , @("[Unrelated to WMIC.EXE execution] C:\WINDOWS\system32\wbem\wmiprvse.exe", " -secured -Embedding")
              $ArgsDefenderWillSee += , @($PathToPowerShell, $PSCmdSyntax)
              $CmdLineOutput = $PathToWmic + $WmicCmdSyntax
          }
        4 {
              ForEach($Char in $CharsToEscape)
              {
                  If($ScriptString.Contains("^^^$Char")) {$ScriptString = $ScriptString.Replace("^^^$Char","$Char")}
              }
              If($ScriptString.Contains('^^^^'))
              {
                  $ScriptString = $ScriptString.Replace('^^^^','^')
              }
              $Shell32Dll = ([Char[]]'SHELL32.DLL' | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $ExecutionFlagsRunDllSyntax = ($PowerShellFlagsArray | Where-Object {$_.Trim().Length -gt 0} | ForEach-Object {'"' + ' '*(Get-Random -Minimum 0 -Maximum 3) + $_ + ' '*(Get-Random -Minimum 0 -Maximum 3) + '"' + ' '*(Get-Random -Minimum 1 -Maximum 4)}) -Join ''
              $PSCmdSyntax     = ' '*(Get-Random -Minimum 1 -Maximum 4) + $ExecutionFlagsRunDllSyntax + ' '*(Get-Random -Minimum 1 -Maximum 4) + "`"$ScriptString`""
              $RunDllCmdSyntax = ' '*(Get-Random -Minimum 1 -Maximum 4) + $Shell32Dll + (Get-Random -Input @(',',' ', ((Get-Random -Input @(',',',',',',' ',' ',' ') -Count (Get-Random -Input @(4..6)))-Join''))) + 'ShellExec_RunDLL' + ' '*(Get-Random -Minimum 1 -Maximum 4) + "`"$PathToPowerShell`"" + $PSCmdSyntax
              $ArgsDefenderWillSee += , @($PathToRunDll          , $RunDllCmdSyntax)
              $ArgsDefenderWillSee += , @("`"$PathToPowerShell`"", $PSCmdSyntax.Replace('^',''))
              $CmdLineOutput = $PathToRunDll + $RunDllCmdSyntax
          }
        5 {
              ForEach($Char in $CharsToEscape)
              {
                  If($ScriptString.Contains("^^^$Char")) {$ScriptString = $ScriptString.Replace("^^^$Char","^$Char")}
              }
              If($ScriptString.Contains('^^^^'))
              {
                  $ScriptString = $ScriptString.Replace('^^^^','^^')
              }
              If($ScriptString.Contains('\"')) {$ScriptString = $ScriptString.Replace('\"','"')}
              $CharsForVarName = @('a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z')
              $VariableName = (Get-Random -Input $CharsForVarName -Count ($CharsForVarName.Count/(Get-Random -Input @(5..10)))) -Join ''
              $VariableName = ([Char[]]$VariableName.ToLower() | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $InvokeVariableSyntax = Out-RandomInvokeRandomEnvironmentVariableSyntax $VariableName
              $SetSyntax = ([Char[]]'set' | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $SetSyntax = $SetSyntax + ' '*(Get-Random -Minimum 2 -Maximum 4) + $VariableName + '='
              $SetSyntax = ([Char[]]$SetSyntax.ToLower() | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $PSCmdSyntax = $PowerShellFlags + $InvokeVariableSyntax
              $CmdSyntax   = $SlashC + ' '*(Get-Random -Minimum 0 -Maximum 4) + '"' + $SetSyntax + $ScriptString + '&&' + ' '*(Get-Random -Minimum 0 -Maximum 4) + $PathToPowerShell + $PSCmdSyntax + '"'
              $ArgsDefenderWillSee += , @($PathToCmd       , $CmdSyntax)
              $ArgsDefenderWillSee += , @($PathToPowerShell, $PSCmdSyntax.Replace('^',''))
              $CmdLineOutput = $PathToCmd + $CmdSyntax
          }
        6 {
              If($ScriptString.Contains('\"')) {$ScriptString = $ScriptString.Replace('\"','"')}
              $PowerShellStdin = Out-RandomPowerShellStdInInvokeSyntax
              $PSCmdSyntax = $PowerShellFlags + $PowerShellStdin
              $CmdSyntax   = $SlashC + ' '*(Get-Random -Minimum 0 -Maximum 4) + '"'  + ' '*(Get-Random -Minimum 0 -Maximum 3) + $Echo + (Get-Random -Input ('/','\',' '*(Get-Random -Minimum 1 -Maximum 3))) + $ScriptString + ' '*(Get-Random -Minimum 1 -Maximum 3) + '|' + ' '*(Get-Random -Minimum 1 -Maximum 3) + $PathToPowerShell + $PSCmdSyntax + '"'
              $ArgsDefenderWillSee += , @($PathToCmd       , $CmdSyntax)
              $ArgsDefenderWillSee += , @($PathToPowerShell, $PSCmdSyntax.Replace('^',''))
              $CmdLineOutput = $PathToCmd + $CmdSyntax
          }
        7 {
              If($ScriptString.Contains('\"')) {$ScriptString = $ScriptString.Replace('\"','"')}
              $PowerShellClip = Out-RandomClipboardInvokeSyntax
              $CommandFlagValue = $NULL
              If($PSBoundParameters['Command'] -OR $Command)
              {
                  $UpperLimit = $PowerShellFlagsArray.Count-1
                  $CommandFlagValue = $PowerShellFlagsArray[$PowerShellFlagsArray.Count-1]
              }
              Else
              {
                  $UpperLimit = $PowerShellFlagsArray.Count
              }
              $PowerShellFlags = @()
              For($i=0; $i -lt $UpperLimit; $i++)
              {
                  $PowerShellFlags += $PowerShellFlagsArray[$i]
              }
              $PowerShellFlags += (Get-Random -Input @('-st','-sta'))
              If($PowerShellFlags.Count -gt 1)
              {
                  $PowerShellFlags = Get-Random -InputObject $PowerShellFlags -Count $PowerShellFlags.Count
              }
              If($CommandFlagValue)
              {
                  $PowerShellFlags += $CommandFlagValue
              }
              For($i=0; $i -lt $PowerShellFlags.Count; $i++)
              {
                  $PowerShellFlags[$i] = ([Char[]]$PowerShellFlags[$i] | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
              }
              $PowerShellFlags = ($PowerShellFlags | ForEach-Object {$_ + ' '*(Get-Random -Minimum 1 -Maximum 3)}) -Join ''
              $PowerShellFlags = ' '*(Get-Random -Minimum 1 -Maximum 3) + $PowerShellFlags + ' '*(Get-Random -Minimum 1 -Maximum 3)
              $PSCmdSyntax = $PowerShellFlags + $PowerShellClip
              $CmdSyntax   = $SlashC + ' '*(Get-Random -Minimum 0 -Maximum 4) + '"'  + ' '*(Get-Random -Minimum 0 -Maximum 3) + $Echo + (Get-Random -Input ('/','\',' '*(Get-Random -Minimum 1 -Maximum 3))) + $ScriptString + ' '*(Get-Random -Minimum 0 -Maximum 2) + '|' + ' '*(Get-Random -Minimum 0 -Maximum 2) + $PathToClip + ' '*(Get-Random -Minimum 0 -Maximum 2) + '&&' + ' '*(Get-Random -Minimum 1 -Maximum 3) + $PathToPowerShell + $PSCmdSyntax + '"'
              $ArgsDefenderWillSee += , @($PathToCmd       , $CmdSyntax)
              $ArgsDefenderWillSee += , @($PathToPowerShell, $PSCmdSyntax.Replace('^',''))
              $CmdLineOutput = $PathToCmd + $CmdSyntax
          }
        8 {
              ForEach($Char in $CharsToEscape)
              {
                  If($ScriptString.Contains("^^^$Char")) {$ScriptString = $ScriptString.Replace("^^^$Char","^$Char")}
              }
              If($ScriptString.Contains('^^^^'))
              {
                  $ScriptString = $ScriptString.Replace('^^^^','^^')
              }
              If($ScriptString.Contains('\"')) {$ScriptString = $ScriptString.Replace('\"','"')}
              $CharsForVarName = @('a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z')
              $VariableName  = (Get-Random -Input $CharsForVarName -Count ($CharsForVarName.Count/(Get-Random -Input @(5..10)))) -Join ''
              $VariableName  = ([Char[]]$VariableName.ToLower() | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $VariableName2 = (Get-Random -Input $CharsForVarName -Count ($CharsForVarName.Count/(Get-Random -Input @(5..10)))) -Join ''
              $VariableName2 = ([Char[]]$VariableName2.ToLower() | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $SetSyntax  = ([Char[]]'set' | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $SetSyntax  = $SetSyntax + ' '*(Get-Random -Minimum 2 -Maximum 4) + $VariableName + '='
              $SetSyntax2 = ([Char[]]'set' | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $SetSyntax2 = $SetSyntax2 + ' '*(Get-Random -Minimum 2 -Maximum 4) + $VariableName2 + '='
              $SetSyntax     = ([Char[]]$SetSyntax.ToLower()     | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $SetSyntax2    = ([Char[]]$SetSyntax2.ToLower()    | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $VariableName  = ([Char[]]$VariableName.ToLower()  | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $VariableName2 = ([Char[]]$VariableName2.ToLower() | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $InvokeOption = Out-RandomInvokeRandomEnvironmentVariableSyntax $VariableName
              ForEach($Char in @('<','>','|','&'))
              {
                  If($InvokeOption.Contains("^$Char"))
                  {
                      $InvokeOption = $InvokeOption.Replace("^$Char","^^^$Char")
                  }
              }
              $PSCmdSyntax = $PowerShellFlags + ' '*(Get-Random -Minimum 1 -Maximum 3) + $InvokeOption
              $CmdSyntax2  = $SlashC + ' '*(Get-Random -Minimum 0 -Maximum 2) + "%$VariableName2%"
              $CmdSyntax   = $SlashC + ' '*(Get-Random -Minimum 0 -Maximum 4) + '"' + $SetSyntax + $ScriptString + '&&' + $SetSyntax2 + $PathToPowerShell + $PSCmdSyntax + '&&' + ' '*(Get-Random -Minimum 0 -Maximum 4) + $PathToCmd + $CmdSyntax2 + '"'
              $ArgsDefenderWillSee += , @($PathToCmd       , $CmdSyntax)
              $ArgsDefenderWillSee += , @($PathToCmd       , $CmdSyntax2)
              $ArgsDefenderWillSee += , @($PathToPowerShell, $PSCmdSyntax.Replace('^',''))
              $CmdLineOutput = $PathToCmd + $CmdSyntax
          }
        9 {
              If($ScriptString.Contains('\"')) {$ScriptString = $ScriptString.Replace('\"','"')}
              $CharsForVarName = @('a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z')
              $VariableName  = (Get-Random -Input $CharsForVarName -Count ($CharsForVarName.Count/(Get-Random -Input @(5..10)))) -Join ''
              $VariableName  = ([Char[]]$VariableName.ToLower() | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $VariableName2 = (Get-Random -Input $CharsForVarName -Count ($CharsForVarName.Count/(Get-Random -Input @(5..10)))) -Join ''
              $VariableName2 = ([Char[]]$VariableName2.ToLower() | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $SetSyntax  = ([Char[]]'set' | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $SetSyntax  = $SetSyntax + ' '*(Get-Random -Minimum 2 -Maximum 4) + $VariableName + '='
              $SetSyntax2 = ([Char[]]'set' | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $SetSyntax2 = $SetSyntax2 + ' '*(Get-Random -Minimum 2 -Maximum 4) + $VariableName2 + '='
              $ExecContextVariable  = @()
              $ExecContextVariable += '(' + (Get-Random -Input @('DIR','Get-ChildItem','GCI','ChildItem','LS','Get-Item','GI','Item')) + ' ' + 'variable:' + (Get-Random -Input @('Ex*xt','E*t','*xec*t','*ecu*t','*cut*t','*cuti*t','*uti*t','E*ext','E*xt','E*Cont*','E*onte*','E*tex*','ExecutionContext')) + ').Value'
              $ExecContextVariable = Get-Random -Input $ExecContextVariable
              $GetRandomVariableSyntax  = @()
              $GetRandomVariableSyntax += '(' + (Get-Random -Input @('DIR','Get-ChildItem','GCI','ChildItem','LS','Get-Item','GI','Item')) + ' ' + 'env:' + $VariableName + ').Value'
              $GetRandomVariableSyntax += ('(' + '[Environment]::GetEnvironmentVariable(' + "'$VariableName'" + ',' + "'Process'" + ')' + ')')
              $GetRandomVariableSyntax = Get-Random -Input $GetRandomVariableSyntax
              $InvokeOptions  = @()
              $InvokeOptions += (Get-Random -Input ('IEX','Invoke-Expression')) + ' '*(Get-Random -Minimum 1 -Maximum 3) + $GetRandomVariableSyntax
              $InvokeOptions += (Get-Random -Input @('$ExecutionContext','${ExecutionContext}',$ExecContextVariable)) + '.InvokeCommand.InvokeScript(' + ' '*(Get-Random -Minimum 0 -Maximum 3) + $GetRandomVariableSyntax + ' '*(Get-Random -Minimum 0 -Maximum 3) + ')'
              $InvokeOption = Get-Random -Input $InvokeOptions
              $SetSyntax            = ([Char[]]$SetSyntax.ToLower()            | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $SetSyntax2           = ([Char[]]$SetSyntax2.ToLower()           | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $VariableName         = ([Char[]]$VariableName.ToLower()         | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $VariableName2        = ([Char[]]$VariableName2.ToLower()        | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $InvokeOption         = ([Char[]]$InvokeOption.ToLower()         | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $ExecContextVariable  = ([Char[]]$ExecContextVariable.ToLower()  | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $GetRandomVariableSyntax = ([Char[]]$GetRandomVariableSyntax.ToLower() | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $InvokeVariableSyntax = Out-RandomInvokeRandomEnvironmentVariableSyntax $VariableName
              $PowerShellStdin = Out-RandomPowerShellStdInInvokeSyntax
              ForEach($Char in $CharsToEscape)
              {
                  If($ScriptString.Contains("^^^$Char")) {$ScriptString = $ScriptString.Replace("^^^$Char","^$Char")}
                  If($PowerShellStdin.Contains("^$Char")) {$PowerShellStdin = $PowerShellStdin.Replace("^$Char","^^^$Char")}
              }
              If($ScriptString.Contains('^^^^'))
              {
                  $ScriptString = $ScriptString.Replace('^^^^','^^')
              }
              $PSCmdSyntax = $PowerShellFlags + ' '*(Get-Random -Minimum 1 -Maximum 3) + $PowerShellStdin + ' '*(Get-Random -Minimum 0 -Maximum 3)
              $CmdSyntax2  = $SlashC + ' '*(Get-Random -Minimum 0 -Maximum 2) + "%$VariableName2%"
              $CmdSyntax   = $SlashC + ' '*(Get-Random -Minimum 0 -Maximum 4) + '"' + $SetSyntax + ' '*(Get-Random -Minimum 0 -Maximum 3)+ $ScriptString + ' '*(Get-Random -Minimum 0 -Maximum 3) + '&&' + ' '*(Get-Random -Minimum 0 -Maximum 3) + $SetSyntax2 + $Echo + ' '*(Get-Random -Minimum 1 -Maximum 3) + $InvokeOption + ' '*(Get-Random -Minimum 0 -Maximum 3) + '^|' + ' '*(Get-Random -Minimum 0 -Maximum 3) + $PathToPowerShell + $PSCmdSyntax + '&&' + ' '*(Get-Random -Minimum 0 -Maximum 3) + $PathToCmd + $CmdSyntax2 + '"'
              $ArgsDefenderWillSee += , @($PathToCmd       , $CmdSyntax)
              $ArgsDefenderWillSee += , @($PathToCmd       , $CmdSyntax2)
              $ArgsDefenderWillSee += , @($PathToPowerShell, $PSCmdSyntax.Replace('^',''))
              $CmdLineOutput = $PathToCmd + $CmdSyntax
          }
        10 {
              If($ScriptString.Contains('\"')) {$ScriptString = $ScriptString.Replace('\"','"')}
              $PowerShellClip = Out-RandomClipboardInvokeSyntax
              ForEach($Char in @('<','>','|','&'))
              {
                  If($PowerShellClip.Contains("^$Char")) 
                  {
                      $PowerShellClip = $PowerShellClip.Replace("^$Char","^^^$Char")
                  }
              }
              $CommandFlagValue = $NULL
              If($PSBoundParameters['Command'] -OR $Command)
              {
                  $UpperLimit = $PowerShellFlagsArray.Count-1
                  $CommandFlagValue = $PowerShellFlagsArray[$PowerShellFlagsArray.Count-1]
              }
              Else
              {
                  $UpperLimit = $PowerShellFlagsArray.Count
              }
              $PowerShellFlags = @()
              For($i=0; $i -lt $UpperLimit; $i++)
              {
                  $PowerShellFlags += $PowerShellFlagsArray[$i]
              }
              $PowerShellFlags += (Get-Random -Input @('-st','-sta'))
              If($PowerShellFlags.Count -gt 1)
              {
                  $PowerShellFlags = Get-Random -InputObject $PowerShellFlags -Count $PowerShellFlags.Count
              }
              If($CommandFlagValue)
              {
                  $PowerShellFlags += $CommandFlagValue
              }
              For($i=0; $i -lt $PowerShellFlags.Count; $i++)
              {
                  $PowerShellFlags[$i] = ([Char[]]$PowerShellFlags[$i] | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
              }
              $PowerShellFlags = ($PowerShellFlags | ForEach-Object {$_ + ' '*(Get-Random -Minimum 1 -Maximum 3)}) -Join ''
              $PowerShellFlags = ' '*(Get-Random -Minimum 1 -Maximum 3) + $PowerShellFlags + ' '*(Get-Random -Minimum 1 -Maximum 3)
              $PSCmdSyntax = $PowerShellFlags + $PowerShellClip
              $CmdSyntax2  = $SlashC + ' '*(Get-Random -Minimum 0 -Maximum 4) + $PathToPowerShell + $PsCmdSyntax
              $CmdSyntax   = $SlashC + ' '*(Get-Random -Minimum 0 -Maximum 4) + '"'  + ' '*(Get-Random -Minimum 0 -Maximum 3) + $Echo + (Get-Random -Input ('/','\',' '*(Get-Random -Minimum 1 -Maximum 3))) + $ScriptString + ' '*(Get-Random -Minimum 0 -Maximum 2) + '|' + ' '*(Get-Random -Minimum 0 -Maximum 2) + $PathToClip + ' '*(Get-Random -Minimum 0 -Maximum 2) + '&&' + $PathToCmd + $CmdSyntax2 + '"'
              $ArgsDefenderWillSee += , @($PathToCmd       , $CmdSyntax)
              $ArgsDefenderWillSee += , @($PathToCmd       , $CmdSyntax2)
              $ArgsDefenderWillSee += , @($PathToPowerShell, $PSCmdSyntax.Replace('^',''))
              $CmdLineOutput = $PathToCmd + $CmdSyntax
          }
        11 {
              ForEach($Char in $CharsToEscape)
              {
                  If($ScriptString.Contains("^^^$Char")) {$ScriptString = $ScriptString.Replace("^^^$Char","^$Char")}
              }
              If($ScriptString.Contains('^^^^'))
              {
                  $ScriptString = $ScriptString.Replace('^^^^','^^')
              }
              If($ScriptString.Contains('\"')) {$ScriptString = $ScriptString.Replace('\"','"')}
              $CharsForVarName = @('a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z')
              $VariableName  = (Get-Random -Input $CharsForVarName -Count ($CharsForVarName.Count/(Get-Random -Input @(5..10)))) -Join ''
              $VariableName  = ([Char[]]$VariableName.ToLower() | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $SetSyntax  = ([Char[]]'set' | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $SetSyntax  = $SetSyntax + ' '*(Get-Random -Minimum 2 -Maximum 4) + $VariableName + '='
              $SetSyntax     = ([Char[]]$SetSyntax.ToLower()     | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $VariableName  = ([Char[]]$VariableName.ToLower()  | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $InvokeOption = (Out-RandomInvokeRandomEnvironmentVariableSyntax $VariableName).Replace('\"',"'").Replace('`','')
              $Shell32Dll = ([Char[]]'SHELL32.DLL' | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $ExecutionFlagsRunDllSyntax = ($PowerShellFlagsArray | Where-Object {$_.Trim().Length -gt 0} | ForEach-Object {'"' + ' '*(Get-Random -Minimum 0 -Maximum 3) + $_ + ' '*(Get-Random -Minimum 0 -Maximum 3) + '"' + ' '*(Get-Random -Minimum 1 -Maximum 4)}) -Join ''
              $PSCmdSyntax     = ' '*(Get-Random -Minimum 1 -Maximum 4) + $ExecutionFlagsRunDllSyntax + ' '*(Get-Random -Minimum 1 -Maximum 4) + "`"$InvokeOption`""
              $RundllCmdSyntax = ' '*(Get-Random -Minimum 1 -Maximum 4) + $Shell32Dll + (Get-Random -Input @(',',' ', ((Get-Random -Input @(',',',',',',' ',' ',' ') -Count (Get-Random -Input @(4..6)))-Join''))) + 'ShellExec_RunDLL' + ' '*(Get-Random -Minimum 1 -Maximum 4) + "`"$PathToPowerShell`"" + $PSCmdSyntax
              $CmdSyntax       = $SlashC + ' '*(Get-Random -Minimum 0 -Maximum 4) + '"' + $SetSyntax + $ScriptString + '&&' + $PathToRunDll + $RundllCmdSyntax
              $ArgsDefenderWillSee += , @($PathToCmd             , $CmdSyntax)
              $ArgsDefenderWillSee += , @($PathToRunDll          , $RundllCmdSyntax)
              $ArgsDefenderWillSee += , @("`"$PathToPowerShell`"", $PSCmdSyntax.Replace('^',''))
              $CmdLineOutput = $PathToCmd + $CmdSyntax
        }
        12 {
              ForEach($Char in $CharsToEscape)
              {
                  If($ScriptString.Contains("^^^$Char")) {$ScriptString = $ScriptString.Replace("^^^$Char","^$Char")}
              }
              If($ScriptString.Contains('^^^^'))
              {
                  $ScriptString = $ScriptString.Replace('^^^^','^^')
              }
              If($ScriptString.Contains('\"')) {$ScriptString = $ScriptString.Replace('\"','"')}
              $CharsForVarName = @('a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z')
              $VariableName  = (Get-Random -Input $CharsForVarName -Count ($CharsForVarName.Count/(Get-Random -Input @(5..10)))) -Join ''
              $VariableName  = ([Char[]]$VariableName.ToLower() | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $SetSyntax  = ([Char[]]'set' | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $SetSyntax  = $SetSyntax + ' '*(Get-Random -Minimum 2 -Maximum 4) + $VariableName + '='
              $SetSyntax     = ([Char[]]$SetSyntax.ToLower()     | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $VariableName  = ([Char[]]$VariableName.ToLower()  | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $InvokeOption = (Out-RandomInvokeRandomEnvironmentVariableSyntax $VariableName).Replace('\"',"'").Replace('`','')
              While($InvokeOption.Length -gt 200)
              {
                  $InvokeOption = (Out-RandomInvokeRandomEnvironmentVariableSyntax $VariableName).Replace('\"',"'").Replace('`','')
              }
              $CreateObject = ([Char[]]'VBScript:CreateObject' | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $WScriptShell = ([Char[]]'WScript.Shell'         | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $Run          = ([Char[]]'.Run'                  | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $TrueString   = ([Char[]]'True'                  | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              $WindowClose  = ([Char[]]'Window.Close'          | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
              If((Get-Random -Input @(0..1)) -eq 0)
              {
                  $WScriptShell = Out-ConcatenatedString $WScriptShell '"'
              }
              Else
              {
                  $WScriptShell = '"' + $WScriptShell + '"'
              }
              If((Get-Random -Input @(0..1)) -eq 0)
              {
                  $SubStringArray += (Out-ConcatenatedString $InvokeOption.Trim('"') '"').Replace('`"','"')
                  If($InvokeOption.Contains('^"+"'))
                  {
                      $InvokeOption = $InvokeOption.Replace('^"+"','^')
                  }
              }
              If((Get-Random -Input @(0..1)) -eq 0)
              {
                  $One = 1
              }
              Else
              {
                  $RandomNumber = Get-Random -Minimum 3 -Maximum 25
                  If(Get-Random -Input @(0..1))
                  {
                      $One = [String]$RandomNumber + '-' + ($RandomNumber-1)
                  }
                  Else
                  {
                      $SecondRandomNumber = Get-Random -Minimum 1 -Maximum $RandomNumber
                      $One = [String]$RandomNumber + '-' + $SecondRandomNumber + '-' + ($RandomNumber-$SecondRandomNumber-1)
                  }
                  If((Get-Random -Input @(0..1)) -eq 0)
                  {
                      $One = '(' + $One + ')'
                  }
              }
              $PSCmdSyntax    = $PowerShellFlags + ' '*(Get-Random -Minimum 0 -Maximum 3) + $InvokeOption + '",' + $One + ',' + $TrueString + ")($WindowClose)"
              $MshtaCmdSyntax = ' '*(Get-Random -Minimum 1 -Maximum 4) + $CreateObject + "($WScriptShell)" + $Run + '("' + $PathToPowerShell + $PSCmdSyntax + '"'
              $CmdSyntax      = $SlashC + ' '*(Get-Random -Minimum 0 -Maximum 4) + '"' + $SetSyntax + $ScriptString + '&&' + $PathToMshta + $MshtaCmdSyntax
              $ArgsDefenderWillSee += , @($PathToCmd       , $CmdSyntax)
              $ArgsDefenderWillSee += , @($PathToMshta     , $MshtaCmdSyntax)
              $ArgsDefenderWillSee += , @($PathToPowerShell, $PSCmdSyntax.Replace('^',''))
              $CmdLineOutput = $PathToCmd + $CmdSyntax
          }
        default {Write-Error "An invalid `$LaunchType value ($LaunchType) was passed to switch block for Out-PowerShellLauncher."; Exit;}
    }
    If($ArgsDefenderWillSee.Count -gt 0)
    {
        Write-Host "`n`nProcess Argument Tree of ObfuscatedCommand with current launcher:"
        $Counter = -1
        ForEach($Line in $ArgsDefenderWillSee)
        {
            If($Line.Count -gt 1)
            {
                $Part1 = $Line[0]
                $Part2 = $Line[1]
            }
            Else
            {
                $Part1 = $Line
                $Part2 = ''
            }
            $LineSpacing = ''
            If($Counter -ge 0)
            {
                $LineSpacing = '     '*$Counter
                Write-Host "$LineSpacing|`n$LineSpacing\--> " -NoNewline
            }
            Write-Host $Part1 -NoNewLine -ForegroundColor Yellow
            $CmdMaxLength = 8190
            If($Part2.Length -gt $CmdMaxLength)
            {
                $RedactedPrintLength = $CmdMaxLength/5
                $CmdLineWidth = (Get-Host).UI.RawUI.BufferSize.Width
                $RedactionMessage = "<REDACTED: ArgumentLength = $($Part1.Length + $Part2.Length)>"
                $CenteredRedactionMessageStartIndex = (($CmdLineWidth-$RedactionMessage.Length)/2) - ($Part1.Length+$LineSpacing.Length)
                $CurrentRedactionMessageStartIndex = ($RedactedPrintLength % $CmdLineWidth)
                If($CurrentRedactionMessageStartIndex -gt $CenteredRedactionMessageStartIndex)
                {
                    $RedactedPrintLength = $RedactedPrintLength-($CurrentRedactionMessageStartIndex-$CenteredRedactionMessageStartIndex)
                }
                Else
                {
                    $RedactedPrintLength = $RedactedPrintLength+($CenteredRedactionMessageStartIndex-$CurrentRedactionMessageStartIndex)
                }
                Write-Host $Part2.SubString(0,$RedactedPrintLength) -NoNewLine -ForegroundColor Cyan
                Write-Host $RedactionMessage -NoNewLine -ForegroundColor Magenta
                Write-Host $Part2.SubString($Part2.Length-$RedactedPrintLength) -ForegroundColor Cyan
            }
            Else
            {
                Write-Host $Part2 -ForegroundColor Cyan
            }
            $Counter++
        }
        Start-Sleep 1
    }
    $CmdMaxLength = 8190
    If(($CmdLineOutput.Length -gt $CmdMaxLength) -AND ($LaunchType -lt 13))
    {
        Write-Host ""
        Write-Warning "This command exceeds the cmd.exe maximum allowed length of $CmdMaxLength characters! Its length is $($CmdLineOutput.Length) characters."
        Start-Sleep 1
    }
    Return $CmdLineOutput
}
function Out-RandomInvokeRandomEnvironmentVariableSyntax
{
    [CmdletBinding()] Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $EnvVarName
    )
    $EnvVarName = Get-Random -Input $EnvVarName
    $ExecContextVariables  = @()
    $ExecContextVariables += '(' + (Get-Random -Input @('DIR','Get-ChildItem','GCI','ChildItem','LS','Get-Item','GI','Item')) + ' ' + "'variable:" + (Get-Random -Input @('ex*xt','ExecutionContext')) + "').Value"
    $ExecContextVariables += '(' + (Get-Random -Input @('Get-Variable','GV','Variable')) + ' ' + "'" + (Get-Random -Input @('ex*xt','ExecutionContext')) + "'" + (Get-Random -Input (').Value',(' ' + ('-ValueOnly'.SubString(0,(Get-Random -Minimum 3 -Maximum ('-ValueOnly'.Length+1)))) + ')')))
    $ExecContextVariable = Get-Random -Input $ExecContextVariables
    $GetRandomVariableSyntax  = @()
    $GetRandomVariableSyntax += '(' + (Get-Random -Input @('DIR','Get-ChildItem','GCI','ChildItem','LS','Get-Item','GI','Item')) + ' ' + 'env:' + $EnvVarName + ').Value'
    $GetRandomVariableSyntax += ('(' + '[Environment]::GetEnvironmentVariable(' + "'$EnvVarName'" + ',' + "'Process'" + ')' + ')')
    $GetRandomVariableSyntax = Get-Random -Input $GetRandomVariableSyntax
    $ExpressionToInvoke = $GetRandomVariableSyntax
    If(Get-Random -Input @(0..1))
    {
        $InvokeOption = Out-EncapsulatedInvokeExpression $ExpressionToInvoke
    }
    Else
    {
        $InvokeOption = (Get-Random -Input @('$ExecutionContext','${ExecutionContext}',$ExecContextVariable)) + '.InvokeCommand.InvokeScript(' + ' '*(Get-Random -Minimum 0 -Maximum 3) + $ExpressionToInvoke + ' '*(Get-Random -Minimum 0 -Maximum 3) + ')'
    }
    $InvokeOption = ([Char[]]$InvokeOption.ToLower() | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
    If($InvokeOption -ne '-')
    {
        $InvokeOption = Out-ObfuscatedTokenCommand -ScriptBlock ([ScriptBlock]::Create($InvokeOption))
        $InvokeOption = Out-ObfuscatedTokenCommand -ScriptBlock ([ScriptBlock]::Create($InvokeOption)) 'RandomWhitespace' 1
    }
    ForEach($Char in @('<','>','|','&'))
    {
        If($InvokeOption.Contains("$Char")) 
        {
            $InvokeOption = $InvokeOption.Replace("$Char","^$Char")
        }
    }
    If($InvokeOption.Contains('"'))
    {
        $InvokeOption = $InvokeOption.Replace('"','\"')
    }
    Return $InvokeOption
}
function Out-RandomPowerShellStdInInvokeSyntax
{
    $ExecContextVariables  = @()
    $ExecContextVariables += '(' + (Get-Random -Input @('DIR','Get-ChildItem','GCI','ChildItem','LS','Get-Item','GI','Item')) + ' ' + "'variable:" + (Get-Random -Input @('ex*xt','ExecutionContext')) + "').Value"
    $ExecContextVariables += '(' + (Get-Random -Input @('Get-Variable','GV','Variable')) + ' ' + "'" + (Get-Random -Input @('ex*xt','ExecutionContext')) + "'" + (Get-Random -Input (').Value',(' ' + ('-ValueOnly'.SubString(0,(Get-Random -Minimum 3 -Maximum ('-ValueOnly'.Length+1)))) + ')')))
    $ExecContextVariable = (Get-Random -Input $ExecContextVariables)
    $RandomInputVariable = (Get-Random -Input @('$Input','${Input}'))
    $ExpressionToInvoke = $RandomInputVariable
    If(Get-Random -Input @(0..1))
    {
        $InvokeOption = Out-EncapsulatedInvokeExpression $ExpressionToInvoke
    }
    Else
    {
        $InvokeOption = (Get-Random -Input @('$ExecutionContext','${ExecutionContext}',$ExecContextVariable)) + '.InvokeCommand.InvokeScript(' + ' '*(Get-Random -Minimum 0 -Maximum 3) + $ExpressionToInvoke + ' '*(Get-Random -Minimum 0 -Maximum 3) + ')'
    }
    $InvokeOption = ([Char[]]$InvokeOption.ToLower() | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
    If($NoExit)
    {
        $InvokeOption = '-'
    }
    $PowerShellStdIn = $InvokeOption
    $PowerShellStdIn = ([Char[]]$PowerShellStdIn.ToLower() | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
    If($PowerShellStdIn -ne '-')
    {
        $InvokeOption = Out-ObfuscatedTokenCommand -ScriptBlock ([ScriptBlock]::Create($InvokeOption))
        $InvokeOption = Out-ObfuscatedTokenCommand -ScriptBlock ([ScriptBlock]::Create($InvokeOption)) 'RandomWhitespace' 1
    }
    ForEach($Char in @('<','>','|','&'))
    {
        If($PowerShellStdIn.Contains("$Char")) 
        {
            $PowerShellStdIn = $PowerShellStdIn.Replace("$Char","^$Char")
        }
    }
    If($PowerShellStdIn.Contains('"'))
    {
        $PowerShellStdIn = $PowerShellStdIn.Replace('"','\"')
    }
    Return $PowerShellStdIn
}
function Out-RandomClipboardInvokeSyntax
{
    $ReflectionAssembly    = Get-Random -Input @('System.Reflection.Assembly','Reflection.Assembly')
    $WindowsClipboard      = Get-Random -Input @('Windows.Clipboard','System.Windows.Clipboard')
    $WindowsFormsClipboard = Get-Random -Input @('System.Windows.Forms.Clipboard','Windows.Forms.Clipboard')
    $FullArgument = "-AssemblyName"
    $AssemblyNameFlags = @()
    $AssemblyNameFlags += '-AN'
    For($Index=2; $Index -le $FullArgument.Length; $Index++)
    {
        $AssemblyNameFlags += $FullArgument.SubString(0,$Index)
    }
    $AssemblyNameFlag = Get-Random -Input $AssemblyNameFlags
    $CharsToRandomVarName  = @(0..9)
    $CharsToRandomVarName += @('A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z')
    $RandomVarLength = (Get-Random -Input @(3..6))
    If($CharsToRandomVarName.Count -lt $RandomVarLength) {$RandomVarLength = $CharsToRandomVarName.Count}
    $RandomVarName = ((Get-Random -Input $CharsToRandomVarName -Count $RandomVarLength) -Join '').Replace(' ','')
    $RandomVarName = ((Get-Random -Input $CharsToRandomVarName -Count $RandomVarLength) -Join '').Replace(' ','')
    $RandomClipSyntaxValue = Get-Random -Input @(1..3)
    Switch($RandomClipSyntaxValue)
    {
        1 {
            $LoadClipboardClassOption   = "Add-Type $AssemblyNameFlag PresentationCore"
            $GetClipboardContentsOption = "([$WindowsClipboard]::GetText())"
            $ClearClipboardOption       = "[$WindowsClipboard]::" + (Get-Random -Input @('Clear()',"SetText(' ')"))
        }
        2 {
            $LoadClipboardClassOption   = "Add-Type $AssemblyNameFlag System.Windows.Forms"
            $GetClipboardContentsOption = "([$WindowsFormsClipboard]::GetText())"
            $ClearClipboardOption       = "[$WindowsFormsClipboard]::" + (Get-Random -Input @('Clear()',"SetText(' ')"))
        }
        3 {
            $LoadClipboardClassOption   =  (Get-Random -Input @('[Void]','$NULL=',"`$$RandomVarName=")) + "[$ReflectionAssembly]::LoadWithPartialName('System.Windows.Forms')"
            $GetClipboardContentsOption = "([$WindowsFormsClipboard]::GetText())"
            $ClearClipboardOption       = "[$WindowsFormsClipboard]::" + (Get-Random -Input @('Clear()',"SetText(' ')"))
        }
        default {Write-Error "An invalid RandomClipSyntaxValue value ($RandomClipSyntaxValue) was passed to switch block for Out-RandomClipboardInvokeSyntax."; Exit;}
    }
    $ExecContextVariables  = @()
    $ExecContextVariables += '(' + (Get-Random -Input @('DIR','Get-ChildItem','GCI','ChildItem','LS','Get-Item','GI','Item')) + ' ' + "'variable:" + (Get-Random -Input @('ex*xt','ExecutionContext')) + "').Value"
    $ExecContextVariables += '(' + (Get-Random -Input @('Get-Variable','GV','Variable')) + ' ' + "'" + (Get-Random -Input @('ex*xt','ExecutionContext')) + "'" + (Get-Random -Input (').Value',(' ' + ('-ValueOnly'.SubString(0,(Get-Random -Minimum 3 -Maximum ('-ValueOnly'.Length+1)))) + ')')))
    $ExecContextVariable = Get-Random -Input $ExecContextVariables
    $ExpressionToInvoke = $GetClipboardContentsOption
    If(Get-Random -Input @(0..1))
    {
        $InvokeOption = Out-EncapsulatedInvokeExpression $ExpressionToInvoke
    }
    Else
    {
        $InvokeOption = (Get-Random -Input @('$ExecutionContext','${ExecutionContext}',$ExecContextVariable)) + '.InvokeCommand.InvokeScript(' + ' '*(Get-Random -Minimum 0 -Maximum 3) + $ExpressionToInvoke + ' '*(Get-Random -Minimum 0 -Maximum 3) + ')'
    }
    $InvokeOption = ([Char[]]$InvokeOption.ToLower() | ForEach-Object {$Char = $_; If(Get-Random -Input (0..1)){$Char = $Char.ToString().ToUpper()} $Char}) -Join ''
    $PowerShellClip = $LoadClipboardClassOption + ' '*(Get-Random -Minimum 0 -Maximum 3) + ';' + ' '*(Get-Random -Minimum 0 -Maximum 3) + $InvokeOption
    $PowerShellClip = $PowerShellClip + ' '*(Get-Random -Minimum 0 -Maximum 3) + ';' + ' '*(Get-Random -Minimum 0 -Maximum 3) + $ClearClipboardOption
    $PowerShellClip = Out-ObfuscatedTokenCommand -ScriptBlock ([ScriptBlock]::Create($PowerShellClip)) 'Member'
    $PowerShellClip = Out-ObfuscatedTokenCommand -ScriptBlock ([ScriptBlock]::Create($PowerShellClip)) 'Member'
    $PowerShellClip = Out-ObfuscatedTokenCommand -ScriptBlock ([ScriptBlock]::Create($PowerShellClip)) 'Command'
    $PowerShellClip = Out-ObfuscatedTokenCommand -ScriptBlock ([ScriptBlock]::Create($PowerShellClip)) 'CommandArgument'
    $PowerShellClip = Out-ObfuscatedTokenCommand -ScriptBlock ([ScriptBlock]::Create($PowerShellClip)) 'Variable'
    $PowerShellClip = Out-ObfuscatedTokenCommand -ScriptBlock ([ScriptBlock]::Create($PowerShellClip)) 'String'
    $PowerShellClip = Out-ObfuscatedTokenCommand -ScriptBlock ([ScriptBlock]::Create($PowerShellClip)) 'RandomWhitespace'
    ForEach($Char in @('<','>','|','&'))
    {
        If($PowerShellClip.Contains("$Char")) 
        {
            $PowerShellClip = $PowerShellClip.Replace("$Char","^$Char")
        }
    }
    If($PowerShellClip.Contains('"'))
    {
        $PowerShellClip = $PowerShellClip.Replace('"','\"')
    }
    Return $PowerShellClip
}
#}
#function Out-ObfuscatedTokenCommand {
function Out-ObfuscatedTokenCommand
{
    [CmdletBinding( DefaultParameterSetName = 'FilePath')] Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ParameterSetName = 'ScriptBlock')]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]
        $ScriptBlock,
        [Parameter(Position = 0, ParameterSetName = 'FilePath')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,
        [ValidateSet('Member', 'Command', 'CommandArgument', 'String', 'Variable', 'Type', 'RandomWhitespace', 'Comment')]
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $TokenTypeToObfuscate,
        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        [Int]
        $ObfuscationLevel = 10 
    )
    If($PSBoundParameters['Path'])
    {
        Get-ChildItem $Path -ErrorAction Stop | Out-Null
        $ScriptString = [IO.File]::ReadAllText((Resolve-Path $Path))
    }
    Else
    {
        $ScriptString = [String]$ScriptBlock
    }
    If($TokenTypeToObfuscate.Length -eq 0)
    {
        $ObfuscationChoices  = @()
        $ObfuscationChoices += 'Member'
        $ObfuscationChoices += 'Command'
        $ObfuscationChoices += 'CommandArgument'
        $ObfuscationChoices += 'Variable'
        $ObfuscationChoices += 'Type'
        $ObfuscationTypeOrder = @()
        $ObfuscationTypeOrder += 'Comment'
        $ObfuscationTypeOrder += 'String'
        $ObfuscationTypeOrder += (Get-Random -Input $ObfuscationChoices -Count $ObfuscationChoices.Count)
        ForEach($ObfuscationType in $ObfuscationTypeOrder) 
        {
            $ScriptString = Out-ObfuscatedTokenCommand ([ScriptBlock]::Create($ScriptString)) $ObfuscationType $ObfuscationLevel
        }
        Return $ScriptString
    }
    $Tokens = [System.Management.Automation.PSParser]::Tokenize($ScriptString,[ref]$null)
    $TokenCount = ([System.Management.Automation.PSParser]::Tokenize($ScriptString,[ref]$null) | Where-Object {$_.Type -eq $TokenTypeToObfuscate}).Count
    $TokensForInsertingWhitespace = @('Operator','GroupStart','GroupEnd','StatementSeparator')
    $Script:TypeTokenScriptStringGrowth = 0
    $Script:TypeTokenVariableArray = @()
    If($TokenTypeToObfuscate -eq 'RandomWhitespace')
    {
        $TokenCount = 0
        ForEach($TokenForInsertingWhitespace in $TokensForInsertingWhitespace)
        {
            $TokenCount += ([System.Management.Automation.PSParser]::Tokenize($ScriptString,[ref]$null) | Where-Object {$_.Type -eq $TokenForInsertingWhitespace}).Count
        }
    }
    If($TokenCount -gt 0)
    {
        $TokenTypeToObfuscateToPrint = $TokenTypeToObfuscate
        If($TokenTypeToObfuscateToPrint -eq 'CommandArgument')  {$TokenTypeToObfuscateToPrint = 'Argument'}
        If($TokenTypeToObfuscateToPrint -eq 'RandomWhitespace') {$TokenTypeToObfuscateToPrint = 'Whitespace'}
        If($TokenCount -gt 1) {$Plural = 's'}
        Else {$Plural = ''}
        Write-Host "`n[*] Obfuscating $($TokenCount)" -NoNewLine
        Write-Host " $TokenTypeToObfuscateToPrint" -NoNewLine -ForegroundColor Yellow
        Write-Host " token$Plural."
    }
    $Counter = $TokenCount
    $OutputCount = 0
    $IterationsToOutputOn = 100
    $DifferenceForEvenOutput = $TokenCount % $IterationsToOutputOn
    For($i=$Tokens.Count-1; $i -ge 0; $i--)
    {
        $Token = $Tokens[$i]
        If(($TokenCount -gt $IterationsToOutputOn*2) -AND ((($TokenCount-$Counter)-($OutputCount*$IterationsToOutputOn)) -eq ($IterationsToOutputOn+$DifferenceForEvenOutput)))
        {
            $OutputCount++
            $ExtraWhitespace = ' '*(([String]($TokenCount)).Length-([String]$Counter).Length)
            If($Counter -gt 0)
            {
                Write-Host "[*]             $ExtraWhitespace$Counter" -NoNewLine
                Write-Host " $TokenTypeToObfuscateToPrint" -NoNewLine -ForegroundColor Yellow
                Write-Host " tokens remaining to obfuscate."
            }
        }
        $ObfuscatedToken = ""
        If(($Token.Type -eq 'String') -AND ($TokenTypeToObfuscate.ToLower() -eq 'string')) 
        {
            $Counter--
            If(($Token.Start -gt 0) -AND ($ScriptString.SubString($Token.Start-1,1) -eq '.'))
            {
                Continue
            }
            $ValidObfuscationLevels = @(0,1,2)
            If($ValidObfuscationLevels -NotContains $ObfuscationLevel) {$ObfuscationLevel = $ValidObfuscationLevels | Sort-Object -Descending | Select-Object -First 1}  
            $ParameterValidationAttributesToTreatStringAsScriptblock  = @()
            $ParameterValidationAttributesToTreatStringAsScriptblock += 'alias'
            $ParameterValidationAttributesToTreatStringAsScriptblock += 'allownull'
            $ParameterValidationAttributesToTreatStringAsScriptblock += 'allowemptystring'
            $ParameterValidationAttributesToTreatStringAsScriptblock += 'allowemptycollection'
            $ParameterValidationAttributesToTreatStringAsScriptblock += 'validatecount'
            $ParameterValidationAttributesToTreatStringAsScriptblock += 'validatelength'
            $ParameterValidationAttributesToTreatStringAsScriptblock += 'validatepattern'
            $ParameterValidationAttributesToTreatStringAsScriptblock += 'validaterange'
            $ParameterValidationAttributesToTreatStringAsScriptblock += 'validatescript'
            $ParameterValidationAttributesToTreatStringAsScriptblock += 'validateset'
            $ParameterValidationAttributesToTreatStringAsScriptblock += 'validatenotnull'
            $ParameterValidationAttributesToTreatStringAsScriptblock += 'validatenotnullorempty'
            $ParameterValidationAttributesToTreatStringAsScriptblock += 'helpmessage'
            $ParameterValidationAttributesToTreatStringAsScriptblock += 'outputtype'
            $ParameterValidationAttributesToTreatStringAsScriptblock += 'diagnostics.codeanalysis.suppressmessageattribute'
            Switch($ObfuscationLevel)
            {
                0 {Continue}
                1 {$ScriptString = Out-ObfuscatedStringTokenLevel1 $ScriptString $Token 1}
                2 {$ScriptString = Out-ObfuscatedStringTokenLevel1 $ScriptString $Token 2}
                default {Write-Error "An invalid `$ObfuscationLevel value ($ObfuscationLevel) was passed to switch block for token type $($Token.Type)."; Exit;}
            }
        }
        ElseIf(($Token.Type -eq 'Member') -AND ($TokenTypeToObfuscate.ToLower() -eq 'member')) 
        {
            $Counter--
            $ValidObfuscationLevels = @(0,1,2,3,4)
            If($ValidObfuscationLevels -NotContains $ObfuscationLevel) {$ObfuscationLevel = $ValidObfuscationLevels | Sort-Object -Descending | Select-Object -First 1}
            $MemberTokensToOnlyRandomCase  = @()
            $MemberTokensToOnlyRandomCase += 'mandatory'
            $MemberTokensToOnlyRandomCase += 'position'
            $MemberTokensToOnlyRandomCase += 'parametersetname'
            $MemberTokensToOnlyRandomCase += 'valuefrompipeline'
            $MemberTokensToOnlyRandomCase += 'valuefrompipelinebypropertyname'
            $MemberTokensToOnlyRandomCase += 'valuefromremainingarguments'
            $MemberTokensToOnlyRandomCase += 'helpmessage'
            $MemberTokensToOnlyRandomCase += 'alias'
            $MemberTokensToOnlyRandomCase += 'confirmimpact'
            $MemberTokensToOnlyRandomCase += 'defaultparametersetname'
            $MemberTokensToOnlyRandomCase += 'helpuri'
            $MemberTokensToOnlyRandomCase += 'supportspaging'
            $MemberTokensToOnlyRandomCase += 'supportsshouldprocess'
            $MemberTokensToOnlyRandomCase += 'positionalbinding'
            $MemberTokensToOnlyRandomCase += 'ignorecase'
            Switch($ObfuscationLevel)
            {
                0 {Continue}
                1 {$ScriptString = Out-RandomCaseToken             $ScriptString $Token}
                2 {$ScriptString = Out-ObfuscatedWithTicks         $ScriptString $Token}
                3 {$ScriptString = Out-ObfuscatedMemberTokenLevel3 $ScriptString $Tokens $i 1}
                4 {$ScriptString = Out-ObfuscatedMemberTokenLevel3 $ScriptString $Tokens $i 2}
                default {Write-Error "An invalid `$ObfuscationLevel value ($ObfuscationLevel) was passed to switch block for token type $($Token.Type)."; Exit;}
            }
        }
        ElseIf(($Token.Type -eq 'CommandArgument') -AND ($TokenTypeToObfuscate.ToLower() -eq 'commandargument')) 
        {
            $Counter--
            $ValidObfuscationLevels = @(0,1,2,3,4)
            If($ValidObfuscationLevels -NotContains $ObfuscationLevel) {$ObfuscationLevel = $ValidObfuscationLevels | Sort-Object -Descending | Select-Object -First 1} 
            Switch($ObfuscationLevel)
            {
                0 {Continue}
                1 {$ScriptString = Out-RandomCaseToken                      $ScriptString $Token}
                2 {$ScriptString = Out-ObfuscatedWithTicks                  $ScriptString $Token}
                3 {$ScriptString = Out-ObfuscatedCommandArgumentTokenLevel3 $ScriptString $Token 1}
                4 {$ScriptString = Out-ObfuscatedCommandArgumentTokenLevel3 $ScriptString $Token 2}
                default {Write-Error "An invalid `$ObfuscationLevel value ($ObfuscationLevel) was passed to switch block for token type $($Token.Type)."; Exit;}
            }
        }
        ElseIf(($Token.Type -eq 'Command') -AND ($TokenTypeToObfuscate.ToLower() -eq 'command')) 
        {
            $Counter--
            $ValidObfuscationLevels = @(0,1,2,3)
            If($ValidObfuscationLevels -NotContains $ObfuscationLevel) {$ObfuscationLevel = $ValidObfuscationLevels | Sort-Object -Descending | Select-Object -First 1}
            If(($Token.Start -gt 1) -AND ($ScriptString.SubString($Token.Start-1,1) -eq '{') -AND ($ScriptString.SubString($Token.Start+$Token.Length,1) -eq '}'))
            {
                $ObfuscationLevel = 1
            }
            Switch($ObfuscationLevel)
            {
                0 {Continue}
                1 {$ScriptString = Out-ObfuscatedWithTicks          $ScriptString $Token}
                2 {$ScriptString = Out-ObfuscatedCommandTokenLevel2 $ScriptString $Token 1}
                3 {$ScriptString = Out-ObfuscatedCommandTokenLevel2 $ScriptString $Token 2}
                default {Write-Error "An invalid `$ObfuscationLevel value ($ObfuscationLevel) was passed to switch block for token type $($Token.Type)."; Exit;}
            }
        }
        ElseIf(($Token.Type -eq 'Variable') -AND ($TokenTypeToObfuscate.ToLower() -eq 'variable'))
        {
            $Counter--
            $ValidObfuscationLevels = @(0,1)
            If($ValidObfuscationLevels -NotContains $ObfuscationLevel) {$ObfuscationLevel = $ValidObfuscationLevels | Sort-Object -Descending | Select-Object -First 1} 
            Switch($ObfuscationLevel)
            {
                0 {Continue}
                1 {$ScriptString = Out-ObfuscatedVariableTokenLevel1 $ScriptString $Token}
                default {Write-Error "An invalid `$ObfuscationLevel value ($ObfuscationLevel) was passed to switch block for token type $($Token.Type)."; Exit;}
            }
        }
        ElseIf(($Token.Type -eq 'Type') -AND ($TokenTypeToObfuscate.ToLower() -eq 'type')) 
        {
            $Counter--
            $ValidObfuscationLevels = @(0,1,2)
            If($ValidObfuscationLevels -NotContains $ObfuscationLevel) {$ObfuscationLevel = $ValidObfuscationLevels | Sort-Object -Descending | Select-Object -First 1} 
            $TypesThatCannotByDirectTypeCasted  = @()
            $TypesThatCannotByDirectTypeCasted += 'directoryservices.accountmanagement.'
            $TypesThatCannotByDirectTypeCasted += 'windows.clipboard'
            Switch($ObfuscationLevel)
            {
                0 {Continue}
                1 {$ScriptString = Out-ObfuscatedTypeToken $ScriptString $Token 1}
                2 {$ScriptString = Out-ObfuscatedTypeToken $ScriptString $Token 2}
                default {Write-Error "An invalid `$ObfuscationLevel value ($ObfuscationLevel) was passed to switch block for token type $($Token.Type)."; Exit;}
            }
        }
        ElseIf(($TokensForInsertingWhitespace -Contains $Token.Type) -AND ($TokenTypeToObfuscate.ToLower() -eq 'randomwhitespace')) 
        {
            $Counter--
            $ValidObfuscationLevels = @(0,1)
            If($ValidObfuscationLevels -NotContains $ObfuscationLevel) {$ObfuscationLevel = $ValidObfuscationLevels | Sort-Object -Descending | Select-Object -First 1} 
            Switch($ObfuscationLevel)
            {
                0 {Continue}
                1 {$ScriptString = Out-RandomWhitespace $ScriptString $Tokens $i}
                default {Write-Error "An invalid `$ObfuscationLevel value ($ObfuscationLevel) was passed to switch block for token type $($Token.Type)."; Exit;}
            }
        }
        ElseIf(($Token.Type -eq 'Comment') -AND ($TokenTypeToObfuscate.ToLower() -eq 'comment'))
        {
            $Counter--
            $ValidObfuscationLevels = @(0,1)
            If($ValidObfuscationLevels -NotContains $ObfuscationLevel) {$ObfuscationLevel = $ValidObfuscationLevels | Sort-Object -Descending | Select-Object -First 1} 
            Switch($ObfuscationLevel)
            {
                0 {Continue}
                1 {$ScriptString = Out-RemoveComments $ScriptString $Token}
                default {Write-Error "An invalid `$ObfuscationLevel value ($ObfuscationLevel) was passed to switch block for token type $($Token.Type)."; Exit;}
            }
        }    
    }
    Return $ScriptString
}
function Out-ObfuscatedStringTokenLevel1
{
    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptString,
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSToken]
        $Token,
        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateSet(1, 2)]
        [Int]
        $ObfuscationLevel
    )
    $EncapsulateAsScriptBlockInsteadOfParentheses = $FALSE
    $SubStringLength = 25
    If($Token.Start -lt $SubStringLength)
    {
        $SubStringLength = $Token.Start
    }
    $SubString = $ScriptString.SubString($Token.Start-$SubStringLength,$SubStringLength).Replace(' ','').Replace("`t",'').Replace("`n",'')
    $SubStringLength = 5
    If($SubString.Length -lt $SubStringLength)
    {
        $SubStringLength = $SubString.Length
    }
    $SubString = $SubString.SubString($SubString.Length-$SubStringLength,$SubStringLength)
    If(($ObfuscationLevel -gt 1) -AND ($Token.Start -gt 5) -AND ($SubString.Contains('(') -OR $SubString.Contains(',')) -AND $ScriptString.SubString(0,$Token.Start).Contains('[') -AND $ScriptString.SubString(0,$Token.Start).Contains('('))
    {
	    $ParameterBindingName = $ScriptString.SubString(0,$Token.Start)
	    $ParameterBindingName = $ParameterBindingName.SubString(0,$ParameterBindingName.LastIndexOf('('))
        $ParameterBindingName = $ParameterBindingName.SubString($ParameterBindingName.LastIndexOf('[')+1).Trim()
	    If(!$ParameterBindingName.Contains(' ') -AND !$ParameterBindingName.Contains(']') -AND !($ParameterBindingName.Length -eq 0))
	    {
		    If($ParameterValidationAttributesToTreatStringAsScriptblock -Contains $ParameterBindingName.ToLower())
		    {
			    $EncapsulateAsScriptBlockInsteadOfParentheses = $TRUE
		    }
	    }
    }
    ElseIf(($ObfuscationLevel -gt 1) -AND ($Token.Start -gt 5) -AND $ScriptString.SubString($Token.Start-5,5).Contains('='))
    {
        ForEach($Parameter in $ParameterValidationAttributesToTreatStringAsScriptblock)
        {
            $SubStringLength = $Parameter.Length
            $SubStringLength += 10
            If($Token.Start -lt $SubStringLength)
            {
                $SubStringLength = $Token.Start
            }
            $SubString = $ScriptString.SubString($Token.Start-$SubStringLength,$SubStringLength+1).Trim()
            If($SubString -Match "$Parameter.*=")
            {
                $EncapsulateAsScriptBlockInsteadOfParentheses = $TRUE
            }
        }
    }
    If($Token.Content.Length -le 1) {Return $ScriptString}
    If(($Token.Content.Length -le 3) -AND $ObfuscationLevel -eq 2) {Return $ScriptString}
    If($Token.Content.Contains('{') -OR $Token.Content.Contains('}')) {Return $ScriptString}
    If($Token.Content.ToLower() -eq 'invoke') {Return $ScriptString}
    $TokenContent = $Token.Content
    $TokenContent = $ScriptString.SubString($Token.Start+1,$Token.Length-2)
    If($TokenContent.Contains('$') -OR $TokenContent.Contains('`'))
    {
        $ObfuscatedToken = ''
        $Counter = 0
        $TokenContentSplit = $TokenContent.Split(' ')
        $ContainsVariableSpecialCases = (($TokenContent.Contains('$(') -OR $TokenContent.Contains('${')) -AND ($ScriptString[$Token.Start] -eq '"'))
        If($ContainsVariableSpecialCases)
        {
            $TokenContentSplit = $TokenContent
        }
        ForEach($SubToken in $TokenContentSplit)
        {
            $Counter++
            $ObfuscatedSubToken = $SubToken
            $SpecialCaseContainsVariableInDoubleQuotes = (($ObfuscatedSubToken.Contains('$') -OR $ObfuscatedSubToken.Contains('`')) -AND ($ScriptString[$Token.Start] -eq '"'))
            If($Counter -lt $TokenContent.Split(' ').Count)
            {
                $ObfuscatedSubToken = $ObfuscatedSubToken + ' '
            }
            If(($ObfuscatedSubToken.Length -gt 1) -AND !($SpecialCaseContainsVariableInDoubleQuotes))
            {
                $ObfuscatedSubToken = Out-StringDelimitedAndConcatenated $ObfuscatedSubToken -PassThru
                While($ObfuscatedSubToken.StartsWith('(') -AND $ObfuscatedSubToken.EndsWith(')'))
                {
                    $ObfuscatedSubToken = ($ObfuscatedSubToken.SubString(1,$ObfuscatedSubToken.Length-2)).Trim()
                }
            }
            Else
            {
                If($SpecialCaseContainsVariableInDoubleQuotes)
                {
                    $ObfuscatedSubToken = '"' + $ObfuscatedSubToken + '"'
                }
                ElseIf($ObfuscatedSubToken.Contains("'") -OR $ObfuscatedSubToken.Contains('$'))
                {
                    $ObfuscatedSubToken = '"' + $ObfuscatedSubToken + '"'
                }
                Else
                {
                    $ObfuscatedSubToken = "'" + $ObfuscatedSubToken + "'"
                }
            }
            If($ObfuscatedSubToken -eq $PreObfuscatedSubToken)
            {
            }
            ElseIf($ObfuscatedSubToken.ToLower().Contains("replace"))
            {
                $ObfuscatedToken += ( '(' + $ObfuscatedSubToken + ')' + '+' )
            }
            Else
            {
                $ObfuscatedToken += ($ObfuscatedSubToken + '+' )
            }
        }
        $ObfuscatedToken = $ObfuscatedToken.Trim(' + ')
    }
    Else
    {
        $SubStringStart = 30
        If($Token.Start -lt $SubStringStart)
        {
            $SubStringStart = $Token.Start
        }
        $SubString = $ScriptString.SubString($Token.Start-$SubStringStart,$SubStringStart).ToLower()
        If($SubString.Contains('defaultparametersetname') -AND $SubString.Contains('='))
        {
            $EncapsulateAsScriptBlockInsteadOfParentheses = $TRUE
        }
        If($SubString.Contains('parametersetname') -OR $SubString.Contains('confirmimpact') -AND !$SubString.Contains('defaultparametersetname') -AND $SubString.Contains('='))
        {
            $ObfuscatedToken = $Token.Content
            $TokenForTicks = [System.Management.Automation.PSParser]::Tokenize($ObfuscatedToken,[ref]$null)
            $ObfuscatedToken = '"' + (Out-ObfuscatedWithTicks $ObfuscatedToken $TokenForTicks[0]) + '"'
        }
        Else
        {
            Switch($ObfuscationLevel)
            {
                1 {$ObfuscatedToken = Out-StringDelimitedAndConcatenated $TokenContent -PassThru}
                2 {$ObfuscatedToken = Out-StringDelimitedConcatenatedAndReordered $TokenContent -PassThru}
                default {Write-Error "An invalid `$ObfuscationLevel value ($ObfuscationLevel) was passed to switch block for String Token Obfuscation."; Exit}
            }
        }
        While($ObfuscatedToken.StartsWith('(') -AND $ObfuscatedToken.EndsWith(')'))
        {
            $TrimmedObfuscatedToken = ($ObfuscatedToken.SubString(1,$ObfuscatedToken.Length-2)).Trim()
            $Balanced = $True
            $Counter = 0
            ForEach($char in $TrimmedObfuscatedToken.ToCharArray()) {
                If($char -eq '(') {
                    $Counter = $Counter + 1
                }
                ElseIf($char -eq ')') {
                    If($Counter -eq 0) {
                        $Balanced = $False
                        break
                    }
                    Else {
                        $Counter = $Counter - 1
                    }
                }
            }
            If($Balanced -and $Counter -eq 0) {
                $ObfuscatedToken = $TrimmedObfuscatedToken
            }
            Else {
                break
            }
        }
    }
    If($ObfuscatedToken.Length -ne ($TokenContent.Length + 2))
    {
        If($EncapsulateAsScriptBlockInsteadOfParentheses)
        {
            $ObfuscatedToken = '{' + $ObfuscatedToken + '}'
        }
        ElseIf(($ObfuscatedToken.Length -eq $TokenContent.Length + 5) -AND $ObfuscatedToken.SubString(2,$ObfuscatedToken.Length-4) -eq ($TokenContent + ' '))
        {
            If($ContainsVariableSpecialCases) {
                $ObfuscatedToken = '"' + $TokenContent + '"'
            }
            Else {
                $ObfuscatedToken = $TokenContent
            }
        }
        ElseIf($ObfuscatedToken.StartsWith('"') -AND $ObfuscatedToken.EndsWith('"') -AND !$ObfuscatedToken.Contains('+') -AND !$ObfuscatedToken.Contains('-f'))
        {
            $ObfuscatedToken = $ObfuscatedToken
        }
        ElseIf($ObfuscatedToken.Length -ne $TokenContent.Length + 2)
        {
            $ObfuscatedToken = '(' + $ObfuscatedToken + ')'
        }
    }
    If($ObfuscatedToken.EndsWith("+''") -OR $ObfuscatedToken.EndsWith('+""'))
    {
        $ObfuscatedToken = $ObfuscatedToken.SubString(0,$ObfuscatedToken.Length-3)
    }
    If($ObfuscatedToken.Contains('`'))
    {
        If($ObfuscatedToken.Contains('`"+"'))
        {
            $ObfuscatedToken = $ObfuscatedToken.Replace('`"+"','"+"`')
        }
        If($ObfuscatedToken.Contains("``'+'"))
        {
            $ObfuscatedToken = $ObfuscatedToken.Replace("``'+'","'+'``")
        }
    }
    If((($Token.Start -gt 0) -AND ($ScriptString.SubString($Token.Start-1,1) -eq '.')) -OR (($Token.Start -gt 1) -AND ($ScriptString.SubString($Token.Start-2,2) -eq '::')) -AND ($ScriptString.SubString($Token.Start+$Token.Length,1) -eq '('))
    {
        $ScriptString = $ScriptString.SubString(0,$Token.Start) + $ObfuscatedToken + '.Invoke' + $ScriptString.SubString($Token.Start+$Token.Length)
    }
    Else
    {
        $ScriptString = $ScriptString.SubString(0,$Token.Start) + $ObfuscatedToken + $ScriptString.SubString($Token.Start+$Token.Length)
    }
    Return $ScriptString
}
function Out-ObfuscatedCommandTokenLevel2
{
    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptString,
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSToken]
        $Token,
        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateSet(1, 2)]
        [Int]
        $ObfuscationLevel
    )
    $TokenContent = $Token.Content
    If($TokenContent.Contains('`')) {$TokenContent = $TokenContent.Replace('`','')}
    $TokenArray = [Char[]]$TokenContent
    $ObfuscatedToken = Out-RandomCase $TokenArray
    Switch($ObfuscationLevel)
    {
        1 {$ObfuscatedToken = Out-StringDelimitedAndConcatenated $TokenContent -PassThru}
        2 {$ObfuscatedToken = Out-StringDelimitedConcatenatedAndReordered $TokenContent -PassThru}
        default {Write-Error "An invalid `$ObfuscationLevel value ($ObfuscationLevel) was passed to switch block for Command Token Obfuscation."; Exit}
    }
    While($ObfuscatedToken.StartsWith('(') -AND $ObfuscatedToken.EndsWith(')'))
    {
        $ObfuscatedToken = ($ObfuscatedToken.SubString(1,$ObfuscatedToken.Length-2)).Trim()
    }
    $ObfuscatedToken = '(' + $ObfuscatedToken + ')'
    $SubStringLength = 15
    If($Token.Start -lt $SubStringLength)
    {
        $SubStringLength = $Token.Start
    }
    $SubString = $ScriptString.SubString($Token.Start-$SubStringLength,$SubStringLength).Trim()
    $InvokeOperatorAlreadyPresent = $FALSE
    If($SubString.EndsWith('.') -OR $SubString.EndsWith('&'))
    {
        $InvokeOperatorAlreadyPresent = $TRUE
    }
    If(!$InvokeOperatorAlreadyPresent)
    {
        If($ScriptString.Length -gt 10000) {$RandomInvokeOperator = '&'}
        Else {$RandomInvokeOperator = Get-Random -InputObject @('&','.')}
        $ObfuscatedToken = $RandomInvokeOperator + $ObfuscatedToken
    }
    $ScriptString = $ScriptString.SubString(0,$Token.Start) + $ObfuscatedToken + $ScriptString.SubString($Token.Start+$Token.Length)
    Return $ScriptString
}
function Out-ObfuscatedWithTicks
{
    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptString,
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSToken]
        $Token
    )
    If($Token.Content.Contains('`'))
    {
        Return $ScriptString
    }
    If($MemberTokensToOnlyRandomCase -Contains $Token.Content.ToLower())
    {
        $ObfuscatedToken = Out-RandomCase $Token.Content
        $ScriptString = $ScriptString.SubString(0,$Token.Start) + $ObfuscatedToken + $ScriptString.SubString($Token.Start+$Token.Length)
        Return $ScriptString
    }
    $EncapsulateWithDoubleQuotes = $FALSE
    If($ScriptString.SubString(0,$Token.Start).Contains('@{') -AND ($ScriptString.SubString($Token.Start+$Token.Length).Trim()[0] -eq '='))
    {
        $EncapsulateWithDoubleQuotes = $TRUE
    }
    $TokenArray = [Char[]]$Token.Content
    $TokenArray = Out-RandomCase $TokenArray
    $ObfuscationPercent = Get-Random -Minimum 15 -Maximum 30
    $NumberOfCharsToObfuscate = [int]($Token.Length*($ObfuscationPercent/100))
    If($NumberOfCharsToObfuscate -eq 0) {$NumberOfCharsToObfuscate = 1}
    $CharIndexesToObfuscate = (Get-Random -InputObject (1..($TokenArray.Length-2)) -Count $NumberOfCharsToObfuscate)
    $SpecialCharacters = @('a','b','f','n','r','u','t','v','0')
    $ObfuscatedToken = '' #$NULL
    $ObfuscatedToken += $TokenArray[0]
    For($i=1; $i -le $TokenArray.Length-1; $i++)
    {
        $CurrentChar = $TokenArray[$i]
        If($CharIndexesToObfuscate -Contains $i)
        {
            If($SpecialCharacters -Contains $CurrentChar) {$CurrentChar = ([string]$CurrentChar).ToUpper()}
            If($CurrentChar -eq '0') {$ObfuscatedToken += $CurrentChar; Continue}
            $ObfuscatedToken += '`' + $CurrentChar
        }
        Else
        {
            $ObfuscatedToken += $CurrentChar
        }
    }
    If((($Token.Start -gt 0) -AND ($ScriptString.SubString($Token.Start-1,1) -eq '.')) -OR (($Token.Start -gt 1) -AND ($ScriptString.SubString($Token.Start-2,2) -eq '::')))
    {
        $ObfuscatedToken = '"' + $ObfuscatedToken + '"'
    }
    ElseIf($EncapsulateWithDoubleQuotes)
    {
        $ObfuscatedToken = '"' + $ObfuscatedToken + '"'
    }
    $ScriptString = $ScriptString.SubString(0,$Token.Start) + $ObfuscatedToken + $ScriptString.SubString($Token.Start+$Token.Length)
    Return $ScriptString
}
function Out-ObfuscatedMemberTokenLevel3
{
    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptString,
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSToken[]]
        $Tokens,
        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Int]
        $Index,
        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateSet(1, 2)]
        [Int]
        $ObfuscationLevel
    )
    $Token = $Tokens[$Index]
    If($MemberTokensToOnlyRandomCase -Contains $Token.Content.ToLower())
    {
        $ObfuscatedToken = Out-RandomCase $Token.Content
        $ScriptString = $ScriptString.SubString(0,$Token.Start) + $ObfuscatedToken + $ScriptString.SubString($Token.Start+$Token.Length)
        Return $ScriptString
    }
    $RemainingSubString = 50
    If($RemainingSubString -gt $ScriptString.SubString($Token.Start+$Token.Length).Length)
    {
        $RemainingSubString = $ScriptString.SubString($Token.Start+$Token.Length).Length
    }
    $SubSubString = $ScriptString.SubString($Token.Start+$Token.Length,$RemainingSubString)
    If(($Token.Content.ToLower() -eq 'invoke') `
    -OR ($Token.Content.ToLower() -eq 'computehash') `
    -OR ($Token.Content.ToLower() -eq 'tobase64string') `
    -OR ($Token.Content.ToLower() -eq 'getstring') `
    -OR ($Token.Content.ToLower() -eq 'getconstructor') `
    -OR (((($Token.Start -gt 0) -AND ($ScriptString.SubString($Token.Start-1,1) -eq '.')) `
    -OR (($Token.Start -gt 1) -AND ($ScriptString.SubString($Token.Start-2,2) -eq '::'))) `
    -AND (($ScriptString.Length -ge $Token.Start+$Token.Length+1) -AND (($SubSubString.SubString(0,1) -ne '(') -OR (($SubSubString.Contains('[')) -AND !($SubSubString.SubString(0,$SubSubString.IndexOf('[')).Contains(')')))))))
    {
        $PrevLength = $ScriptString.Length
        $ScriptString = Out-ObfuscatedWithTicks $ScriptString $Token
        $TokenLength = $Token.Length + ($ScriptString.Length - $PrevLength)
        $ObfuscatedTokenExtracted =  $ScriptString.SubString($Token.Start,$TokenLength)
        If($ObfuscatedTokenExtracted.StartsWith('"') -AND $ObfuscatedTokenExtracted.EndsWith('"'))
        {
            $ScriptString = $ScriptString.SubString(0,$Token.Start) + $ObfuscatedTokenExtracted + $ScriptString.SubString($Token.Start+$TokenLength)
        }
        Else
        {
            $ScriptString = $ScriptString.SubString(0,$Token.Start) + '"' + $ObfuscatedTokenExtracted + '"' + $ScriptString.SubString($Token.Start+$TokenLength)
        }
        Return $ScriptString
    }
    $TokenContent = $Token.Content
    If($TokenContent.Contains('`')) {$TokenContent = $TokenContent.Replace('`','')}
    $TokenArray = [Char[]]$TokenContent
    $TokenArray = Out-RandomCase $TokenArray
    Switch($ObfuscationLevel)
    {
        1 {$ObfuscatedToken = Out-StringDelimitedAndConcatenated $TokenContent -PassThru}
        2 {$ObfuscatedToken = Out-StringDelimitedConcatenatedAndReordered $TokenContent -PassThru}
        default {Write-Error "An invalid `$ObfuscationLevel value ($ObfuscationLevel) was passed to switch block for Member Token Obfuscation."; Exit}
    }
    While($ObfuscatedToken.StartsWith('(') -AND $ObfuscatedToken.EndsWith(')'))
    {
        $ObfuscatedToken = ($ObfuscatedToken.SubString(1,$ObfuscatedToken.Length-2)).Trim()
    }
    $ObfuscatedToken = '(' + $ObfuscatedToken + ')'
    $InvokeToken = $Token
    $TokenLengthIncrease = $ObfuscatedToken.Length - $Token.Content.Length
    If(($Index -lt $Tokens.Count) -AND ($Tokens[$Index+1].Content -eq '(') -AND ($Tokens[$Index+1].Type -eq 'GroupStart')) 
    {
        $ObfuscatedToken = $ObfuscatedToken + '.Invoke'
    }
    $ScriptString = $ScriptString.SubString(0,$Token.Start) + $ObfuscatedToken + $ScriptString.SubString($Token.Start+$Token.Length)  
    Return $ScriptString
}
function Out-ObfuscatedCommandArgumentTokenLevel3
{
    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptString,
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSToken]
        $Token,
        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateSet(1, 2)]
        [Int]
        $ObfuscationLevel
    )
    If($ScriptString.SubString(0,$Token.Start-1).Trim().ToLower().EndsWith('function') -or $ScriptString.SubString(0,$Token.Start-1).Trim().ToLower().EndsWith('filter'))
    {
        $ScriptString = Out-ObfuscatedWithTicks $ScriptString $Token
        Return $ScriptString
    }
    $TokenContent = $Token.Content
    If($TokenContent.Contains('`')) {$TokenContent = $TokenContent.Replace('`','')}
    Switch($ObfuscationLevel)
    {
        1 {$ObfuscatedToken = Out-StringDelimitedAndConcatenated $TokenContent -PassThru}
        2 {$ObfuscatedToken = Out-StringDelimitedConcatenatedAndReordered $TokenContent -PassThru}
        default {Write-Error "An invalid `$ObfuscationLevel value ($ObfuscationLevel) was passed to switch block for Argument Token Obfuscation."; Exit}
    }
    While($ObfuscatedToken.StartsWith('(') -AND $ObfuscatedToken.EndsWith(')'))
    {
        $ObfuscatedToken = ($ObfuscatedToken.SubString(1,$ObfuscatedToken.Length-2)).Trim()
    }
    $ObfuscatedToken = '(' + $ObfuscatedToken + ')'
    $ScriptString = $ScriptString.SubString(0,$Token.Start) + $ObfuscatedToken + $ScriptString.SubString($Token.Start+$Token.Length)
    Return $ScriptString
}
function Out-ObfuscatedTypeToken
{
    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptString,
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSToken]
        $Token,
        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateSet(1, 2)]
        [Int]
        $ObfuscationLevel
    )
    ForEach($Type in $TypesThatCannotByDirectTypeCasted)
    {
        If($Token.Content.ToLower().Contains($Type))
        {
            Return $ScriptString
        }
    }
    If(($ScriptString.SubString($Token.Start+$Script:TypeTokenScriptStringGrowth+$Token.Length,1) -ne '.') -AND ($ScriptString.SubString($Token.Start+$Script:TypeTokenScriptStringGrowth+$Token.Length,2) -ne '::'))
    {
        Return $ScriptString
    }
    $PrevLength = $ScriptString.Length
    $RandomVarName = $NULL
    $UsingPreviouslyDefinedVarName = $FALSE
    ForEach($DefinedTokenVariable in $Script:TypeTokenVariableArray)
    {
        If($Token.Content.ToLower() -eq $DefinedTokenVariable[0])
        {
            $RandomVarName = $DefinedTokenVariable[1]
            $UsingPreviouslyDefinedVarName = $TRUE
        }
    }
    If(!($UsingPreviouslyDefinedVarName))
    {
        $TokenContent = $Token.Content.Trim('[]')
        Switch($ObfuscationLevel)
        {
            1 {$ObfuscatedToken = Out-StringDelimitedAndConcatenated $TokenContent -PassThru}
            2 {$ObfuscatedToken = Out-StringDelimitedConcatenatedAndReordered $TokenContent -PassThru}
            default {Write-Error "An invalid `$ObfuscationLevel value ($ObfuscationLevel) was passed to switch block for Type Token Obfuscation."; Exit}
        }
        While($ObfuscatedToken.StartsWith('(') -AND $ObfuscatedToken.EndsWith(')'))
        {
            $ObfuscatedToken = ($ObfuscatedToken.SubString(1,$ObfuscatedToken.Length-2)).Trim()
        }
        $ObfuscatedTokenTypeCast = '[type]' + '(' + $ObfuscatedToken + ')'
        $CharsToRandomVarName  = @(0..9)
        $CharsToRandomVarName += @('A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z')
        $RandomVarLength = (Get-Random -Input @(3..6))
        If($CharsToRandomVarName.Count -lt $RandomVarLength) {$RandomVarLength = $CharsToRandomVarName.Count}
        $RandomVarName = ((Get-Random -Input $CharsToRandomVarName -Count $RandomVarLength) -Join '').Replace(' ','')
        While($ScriptString.ToLower().Contains($RandomVarName.ToLower()))
        {
            $RandomVarName = ((Get-Random -Input $CharsToRandomVarName -Count $RandomVarLength) -Join '').Replace(' ','')
            $RandomVarLength++
        }
        $Script:TypeTokenVariableArray += , @($Token.Content,$RandomVarName)
    }
    $RandomVarNameMaybeConcatenated = $RandomVarName
    $RandomVarNameMaybeConcatenatedWithVariablePrepended = 'variable:' + $RandomVarName
    If((Get-Random -Input @(0..1)) -eq 0)
    {
        $RandomVarNameMaybeConcatenated = '(' + (Out-ConcatenatedString $RandomVarName (Get-Random -Input @('"',"'"))) + ')'
        $RandomVarNameMaybeConcatenatedWithVariablePrepended = '(' + (Out-ConcatenatedString "variable:$RandomVarName" (Get-Random -Input @('"',"'"))) + ')'
    }
    $RandomVarSetSyntax  = @()
    $RandomVarSetSyntax += '$' + $RandomVarName + ' '*(Get-Random @(0..2)) + '=' + ' '*(Get-Random @(0..2)) + $ObfuscatedTokenTypeCast
    $RandomVarSetSyntax += (Get-Random -Input @('Set-Variable','SV','Set')) + ' '*(Get-Random @(1..2)) + $RandomVarNameMaybeConcatenated + ' '*(Get-Random @(1..2)) + '(' + ' '*(Get-Random @(0..2)) + $ObfuscatedTokenTypeCast + ' '*(Get-Random @(0..2)) + ')'
    $RandomVarSetSyntax += 'Set-Item' + ' '*(Get-Random @(1..2)) + $RandomVarNameMaybeConcatenatedWithVariablePrepended + ' '*(Get-Random @(1..2)) + '(' + ' '*(Get-Random @(0..2)) + $ObfuscatedTokenTypeCast + ' '*(Get-Random @(0..2)) + ')'
    $RandomVarSet = (Get-Random -Input $RandomVarSetSyntax)
    $RandomVarSet = Out-RandomCase $RandomVarSet
    $RandomVarGetSyntax  = @()
    $RandomVarGetSyntax += '$' + $RandomVarName
    $RandomVarGetSyntax += '(' + ' '*(Get-Random @(0..2)) + (Get-Random -Input @('Get-Variable','Variable')) + ' '*(Get-Random @(1..2)) + $RandomVarNameMaybeConcatenated + (Get-Random -Input ((' '*(Get-Random @(0..2)) + ').Value'),(' '*(Get-Random @(1..2)) + ('-ValueOnly'.SubString(0,(Get-Random -Minimum 3 -Maximum ('-ValueOnly'.Length+1)))) + ' '*(Get-Random @(0..2)) + ')')))
    $RandomVarGetSyntax += '(' + ' '*(Get-Random @(0..2)) + (Get-Random -Input @('DIR','Get-ChildItem','GCI','ChildItem','LS','Get-Item','GI','Item')) + ' '*(Get-Random @(1..2)) + $RandomVarNameMaybeConcatenatedWithVariablePrepended + ' '*(Get-Random @(0..2)) + ').Value'
    $RandomVarGet = (Get-Random -Input $RandomVarGetSyntax)
    $RandomVarGet = Out-RandomCase $RandomVarGet
    $PortionToPrependToScriptString = ''
    If(!($UsingPreviouslyDefinedVarName))
    {
        $PortionToPrependToScriptString = ' '*(Get-Random @(0..2)) + $RandomVarSet  + ' '*(Get-Random @(0..2)) + ';' + ' '*(Get-Random @(0..2))
    }
    $ScriptString = $PortionToPrependToScriptString + $ScriptString.SubString(0,$Token.Start+$Script:TypeTokenScriptStringGrowth) + ' '*(Get-Random @(1..2)) + $RandomVarGet + $ScriptString.SubString($Token.Start+$Token.Length+$Script:TypeTokenScriptStringGrowth)
    $Script:TypeTokenScriptStringGrowth = $Script:TypeTokenScriptStringGrowth + $PortionToPrependToScriptString.Length
    Return $ScriptString
}
function Out-ObfuscatedVariableTokenLevel1
{
    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptString,
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSToken]
        $Token
    )
    If($ScriptString.SubString($Token.Start,2) -eq '${' -OR $ScriptString.SubString($Token.Start,1) -eq '@')
    {
        Return $ScriptString
    }
    $PrevLength = $ScriptString.Length
    $ScriptString = Out-ObfuscatedWithTicks $ScriptString $Token   
    $ObfuscatedToken = $ScriptString.SubString($Token.Start,$Token.Length+($ScriptString.Length-$PrevLength))
    $ObfuscatedToken = '${' + $ObfuscatedToken.Trim('"') + '}'
    $ScriptString = $ScriptString.SubString(0,$Token.Start) + $ObfuscatedToken + $ScriptString.SubString($Token.Start+$Token.Length+($ScriptString.Length-$PrevLength))
    Return $ScriptString
}
function Out-RandomCaseToken
{
    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptString,
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSToken]
        $Token
    )
    $TokenArray = [Char[]]$Token.Content
    $TokenArray = Out-RandomCase $TokenArray
    $ObfuscatedToken = $TokenArray -Join ''
    $ScriptString = $ScriptString.SubString(0,$Token.Start) + $ObfuscatedToken + $ScriptString.SubString($Token.Start+$Token.Length)
    Return $ScriptString
}
function Out-ConcatenatedString
{
    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $InputVal,
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Char]
        $Quote
    )
    If($InputVal.Contains("'")) {$InputVal = $InputVal.Replace("'","`'")}
    If($InputVal.Contains('"')) {$InputVal = $InputVal.Replace('"','`"')}
    $ObfuscatedToken = ''
    If($InputVal.Length -le 2)
    {
        $ObfuscatedToken = $Quote + $InputVal + $Quote
        Return $ObfuscatedToken
    }
    If($InputVal.Length -gt 25000)
    {
        $ConcatPercent = Get-Random -Minimum 0.05 -Maximum 0.10
    }
    ElseIf($InputVal.Length -gt 1000)
    {
        $ConcatPercent = Get-Random -Minimum 2 -Maximum 4
    }
    Else
    {
        $ConcatPercent = Get-Random -Minimum 15 -Maximum 30
    }
    $ConcatCount =  [Int]($InputVal.Length*($ConcatPercent/100))
    If($ConcatCount -eq 0) 
    {
        $ConcatCount = 1
    }
    $CharIndexesToConcat = (Get-Random -InputObject (1..($InputVal.Length-1)) -Count $ConcatCount) | Sort-Object
    $LastIndex = 0
    ForEach($IndexToObfuscate in $CharIndexesToConcat)
    {
        $SubString = $InputVal.SubString($LastIndex,$IndexToObfuscate-$LastIndex)
        $ObfuscatedToken += $SubString + $Quote + "+" + $Quote
        $LastIndex = $IndexToObfuscate
    }
    $ObfuscatedToken += $InputVal.SubString($LastIndex)
    $ObfuscatedToken += $FinalSubString
    If(!($ObfuscatedToken.StartsWith($Quote) -AND $ObfuscatedToken.EndsWith($Quote)))
    {
        $ObfuscatedToken = $Quote + $ObfuscatedToken + $Quote
    }
    If($ObfuscatedToken.StartsWith("''+"))
    {
        $ObfuscatedToken = $ObfuscatedToken.SubString(3)
    }
    If($ObfuscatedToken.EndsWith("+''"))
    {
        $ObfuscatedToken = $ObfuscatedToken.SubString(0,$ObfuscatedToken.Length-3)
    }
    Return $ObfuscatedToken
}
function Out-RandomCase
{
    [CmdletBinding( DefaultParameterSetName = 'InputVal')] Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ParameterSetName = 'InputValStr')]
        [ValidateNotNullOrEmpty()]
        [String]
        $InputValStr,
        [Parameter(Position = 0, ParameterSetName = 'InputVal')]
        [ValidateNotNullOrEmpty()]
        [Char[]]
        $InputVal
    )
    If($PSBoundParameters['InputValStr'])
    {
        $InputVal = [Char[]]$InputValStr
    }
    $OutputVal = ($InputVal | ForEach-Object {If((Get-Random -Minimum 0 -Maximum 2) -eq 0) {([String]$_).ToUpper()} Else {([String]$_).ToLower()}}) -Join ''
    Return $OutputVal
}
function Out-RandomWhitespace
{
    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptString,
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSToken[]]
        $Tokens,
        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Int]
        $Index
    )
    $Token = $Tokens[$Index]
    $ObfuscatedToken = $Token.Content
    Switch($Token.Content) {
        '(' {$ObfuscatedToken = $ObfuscatedToken + ' '*(Get-Random -Minimum 0 -Maximum 3)}
        ')' {$ObfuscatedToken = ' '*(Get-Random -Minimum 0 -Maximum 3) + $ObfuscatedToken}
        ';' {$ObfuscatedToken = ' '*(Get-Random -Minimum 0 -Maximum 3) + $ObfuscatedToken + ' '*(Get-Random -Minimum 0 -Maximum 3)}
        '|' {$ObfuscatedToken = ' '*(Get-Random -Minimum 0 -Maximum 3) + $ObfuscatedToken + ' '*(Get-Random -Minimum 0 -Maximum 3)}
        '+' {$ObfuscatedToken = ' '*(Get-Random -Minimum 0 -Maximum 3) + $ObfuscatedToken + ' '*(Get-Random -Minimum 0 -Maximum 3)}
        '=' {$ObfuscatedToken = ' '*(Get-Random -Minimum 0 -Maximum 3) + $ObfuscatedToken + ' '*(Get-Random -Minimum 0 -Maximum 3)}
        '&' {$ObfuscatedToken = ' '*(Get-Random -Minimum 0 -Maximum 3) + $ObfuscatedToken + ' '*(Get-Random -Minimum 0 -Maximum 3)}
        '.' {
            If($Index -eq 0) {$PrevChar = ' '}
            Else {$PrevChar = $ScriptString.SubString($Token.Start-1,1)}
            If(($PrevChar -eq ' ') -OR ($PrevChar -eq ';')) {$ObfuscatedToken = ' '*(Get-Random -Minimum 0 -Maximum 3) + $ObfuscatedToken + ' '*(Get-Random -Minimum 0 -Maximum 3)}
        }
    }
    $ScriptString = $ScriptString.SubString(0,$Token.Start) + $ObfuscatedToken + $ScriptString.SubString($Token.Start+$Token.Length)
    Return $ScriptString
}
function Out-RemoveComments
{
    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptString,
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSToken]
        $Token
    )
    $ScriptString = $ScriptString.SubString(0,$Token.Start) + $ScriptString.SubString($Token.Start+$Token.Length)
    Return $ScriptString
}
#}
#function Out-ObfuscatedStringCommand {
function Out-ObfuscatedStringCommand
{
    [CmdletBinding( DefaultParameterSetName = 'FilePath')] Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ParameterSetName = 'ScriptBlock')]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]
        $ScriptBlock,
        [Parameter(Position = 0, ParameterSetName = 'FilePath')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,
        [ValidateSet('1', '2', '3')]
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Int]
        $ObfuscationLevel = (Get-Random -Input @(1..3)) # Default to random obfuscation level if $ObfuscationLevel isn't defined
    )
    If($PSBoundParameters['Path'])
    {
        Get-ChildItem $Path -ErrorAction Stop | Out-Null
        $ScriptString = [IO.File]::ReadAllText((Resolve-Path $Path))
    }
    Else
    {
        $ScriptString = [String]$ScriptBlock
    }
    $ValidObfuscationLevels = @(0,1,2,3)
    If($ValidObfuscationLevels -NotContains $ObfuscationLevel) {$ObfuscationLevel = $ValidObfuscationLevels | Sort-Object -Descending | Select-Object -First 1}  
    Switch($ObfuscationLevel)
    {
        0 {Continue}
        1 {$ScriptString = Out-StringDelimitedAndConcatenated $ScriptString}
        2 {$ScriptString = Out-StringDelimitedConcatenatedAndReordered $ScriptString}
        3 {$ScriptString = Out-StringReversed $ScriptString}
        default {Write-Error "An invalid `$ObfuscationLevel value ($ObfuscationLevel) was passed to switch block for String Obfuscation."; Exit}
    }
    Return $ScriptString
}
function Out-StringDelimitedAndConcatenated
{
    [CmdletBinding()] Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptString,
        [Switch]
        $PassThru
    )
    $CharsToReplace = @('$','|','`','\','"',"'")
    $CharsToReplace = (Get-Random -Input $CharsToReplace -Count $CharsToReplace.Count)
    $ContainsCharsToReplace = $FALSE
    ForEach($CharToReplace in $CharsToReplace)
    {
        If($ScriptString.Contains($CharToReplace))
        {
            $ContainsCharsToReplace = $TRUE
            Break
        }
    }
    If(!$ContainsCharsToReplace)
    {
        $ScriptString = Out-ConcatenatedString $ScriptString "'"
        $ScriptString = '(' + $ScriptString + ')'
        If(!$PSBoundParameters['PassThru'])
        {
            $ScriptString = Out-EncapsulatedInvokeExpression $ScriptString
        }
        Return $ScriptString
    }
    $CharsToReplaceWith  = @(0..9)
    $CharsToReplaceWith += @('a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z')
    $CharsToReplaceWith += @('A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z')
    $DelimiterLength = 3
    $DelimiterTable = @()
    ForEach($CharToReplace in $CharsToReplace)
    {
        If($ScriptString.Contains($CharToReplace))
        {
            If($CharsToReplaceWith.Count -lt $DelimiterLength) {$DelimiterLength = $CharsToReplaceWith.Count}
            $Delim = (Get-Random -Input $CharsToReplaceWith -Count $DelimiterLength) -Join ''
            While($ScriptString.ToLower().Contains($Delim.ToLower()))
            {
                $Delim = (Get-Random -Input $CharsToReplaceWith -Count $DelimiterLength) -Join ''
                If($DelimiterLength -lt $CharsToReplaceWith.Count)
                {
                    $DelimiterLength++
                }
            }
            $DelimiterTable += , @($Delim,$CharToReplace)
            $ScriptString = $ScriptString.Replace($CharToReplace,$Delim)
        }
    }
    $DelimiterTableWithQuotes = @()
    ForEach($DelimiterArray in $DelimiterTable)
    {
        $Delimiter    = $DelimiterArray[0]
        $OriginalChar = $DelimiterArray[1]
        $RandomQuote = Get-Random -InputObject @("'","`"")
        If($OriginalChar -eq "'") {$RandomQuote = '"'}
        Else {$RandomQuote = "'"}
        $Delimiter = $RandomQuote + $Delimiter + $RandomQuote
        $OriginalChar = $RandomQuote + $OriginalChar + $RandomQuote
        $DelimiterTableWithQuotes += , @($Delimiter,$OriginalChar)
    }
    [Array]::Reverse($DelimiterTable)
    If(($ScriptString.Contains('{')) -AND ($ScriptString.Contains('}')))
    {
        $RandomInput = Get-Random -Input (1..2)
    }
    Else
    {
        $RandomInput = Get-Random -Input (1..3)
    }
    $StringStr   = Out-RandomCase 'string'
    $CharStr     = Out-RandomCase 'char'
    $ReplaceStr  = Out-RandomCase 'replace'
    $CReplaceStr = Out-RandomCase 'creplace'
    Switch($RandomInput) {
        1 {
            $ScriptString = "'" + $ScriptString + "'"
            $ReversingCommand = ""
            ForEach($DelimiterArray in $DelimiterTableWithQuotes)
            {
                $Delimiter    = $DelimiterArray[0]
                $OriginalChar = $DelimiterArray[1]
                If($OriginalChar[1] -eq "'")
                {
                    $OriginalChar = "[$StringStr][$CharStr]39"
                    $Delimiter = "'" + $Delimiter.SubString(1,$Delimiter.Length-2) + "'"
                }
                ElseIf($OriginalChar[1] -eq '"')
                {
                    $OriginalChar = "[$StringStr][$CharStr]34"
                }
                Else
                {
                    If(Get-Random -Input (0..1))
                    {
                        $OriginalChar = "[$StringStr][$CharStr]" + [Int][Char]$OriginalChar[1]
                    }
                }
                If(Get-Random -Input (0..1))
                {
                    $DelimiterCharSyntax = ""
                    For($i=1; $i -lt $Delimiter.Length-1; $i++)
                    {
                        $DelimiterCharSyntax += "[$CharStr]" + [Int][Char]$Delimiter[$i] + '+'
                    }
                    $Delimiter = '(' + $DelimiterCharSyntax.Trim('+') + ')'
                }
                $ReversingCommand = ".$ReplaceStr($Delimiter,$OriginalChar)" + $ReversingCommand
            }
            $ScriptString = Out-ConcatenatedString $ScriptString "'"
            $ScriptString = '(' + $ScriptString + ')'
            $ScriptString = $ScriptString + $ReversingCommand
        }
        2 {
            $ScriptString = "'" + $ScriptString + "'"
            $ReversingCommand = ""
            ForEach($DelimiterArray in $DelimiterTableWithQuotes)
            {
                $Delimiter    = $DelimiterArray[0]
                $OriginalChar = $DelimiterArray[1]
                If($OriginalChar[1] -eq '"')
                {
                    $OriginalChar = "[$CharStr]34"
                }
                ElseIf($OriginalChar[1] -eq "'")
                {
                    $OriginalChar = "[$CharStr]39"; $Delimiter = "'" + $Delimiter.SubString(1,$Delimiter.Length-2) + "'"
                }
                Else
                {
                    $OriginalChar = "[$CharStr]" + [Int][Char]$OriginalChar[1]
                }
                If(Get-Random -Input (0..1))
                {
                    $DelimiterCharSyntax = ""
                    For($i=1; $i -lt $Delimiter.Length-1; $i++)
                    {
                        $DelimiterCharSyntax += "[$CharStr]" + [Int][Char]$Delimiter[$i] + '+'
                    }
                    $Delimiter = '(' + $DelimiterCharSyntax.Trim('+') + ')'
                }
                $Replace = (Get-Random -Input @("-$ReplaceStr","-$CReplaceStr"))
                $ReversingCommand = ' '*(Get-Random -Minimum 0 -Maximum 3) + $Replace + ' '*(Get-Random -Minimum 0 -Maximum 3) + "$Delimiter,$OriginalChar" + $ReversingCommand                
            }
            $ScriptString = Out-ConcatenatedString $ScriptString "'"
            $ScriptString = '(' + $ScriptString + ')'
            $ScriptString = '(' + $ScriptString + $ReversingCommand + ')'
        }
        3 {
            $ScriptString = "'" + $ScriptString + "'"
            $ReversingCommand = ""
            $Counter = 0
            For($i=$DelimiterTableWithQuotes.Count-1; $i -ge 0; $i--)
            {
                $DelimiterArray = $DelimiterTableWithQuotes[$i]
                $Delimiter    = $DelimiterArray[0]
                $OriginalChar = $DelimiterArray[1]
                $DelimiterNoQuotes = $Delimiter.SubString(1,$Delimiter.Length-2)
                If($OriginalChar[1] -eq '"')
                {
                    $OriginalChar = "[$CharStr]34"
                }
                ElseIf($OriginalChar[1] -eq "'")
                {
                    $OriginalChar = "[$CharStr]39"; $Delimiter = "'" + $Delimiter.SubString(1,$Delimiter.Length-2) + "'"
                }
                Else
                {
                    $OriginalChar = "[$CharStr]" + [Int][Char]$OriginalChar[1]
                }
                $ReversingCommand = $ReversingCommand + ",$OriginalChar"
                $ScriptString = $ScriptString.Replace($DelimiterNoQuotes,"{$Counter}")
                $Counter++
            }
            $ReversingCommand = $ReversingCommand.Trim(',')
            $ScriptString = Out-ConcatenatedString $ScriptString "'"
            $ScriptString = '(' + $ScriptString + ')'
            $FormatOperator = (Get-Random -Input @('-f','-F'))
            $ScriptString = '(' + $ScriptString + ' '*(Get-Random -Minimum 0 -Maximum 3) + $FormatOperator + ' '*(Get-Random -Minimum 0 -Maximum 3) + $ReversingCommand + ')'
        }
        default {Write-Error "An invalid `$RandomInput value ($RandomInput) was passed to switch block."; Exit;}
    }
    If(!$PSBoundParameters['PassThru'])
    {
        $ScriptString = Out-EncapsulatedInvokeExpression $ScriptString
    }
    Return $ScriptString
}
function Out-StringDelimitedConcatenatedAndReordered
{
    [CmdletBinding()] Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptString,
        [Switch]
        $PassThru
    )
    If(!$PSBoundParameters['PassThru'])
    {
        $ScriptString = Out-StringDelimitedAndConcatenated $ScriptString
    }
    Else
    {
        $ScriptString = Out-StringDelimitedAndConcatenated $ScriptString -PassThru
    }
    $Tokens = [System.Management.Automation.PSParser]::Tokenize($ScriptString,[ref]$null)
    $GroupStartCount = 0
    $ConcatenatedStringsIndexStart = $NULL
    $ConcatenatedStringsIndexEnd   = $NULL
    $ConcatenatedStringsArray = @()
    For($i=0; $i -le $Tokens.Count-1; $i++) {
        $Token = $Tokens[$i]
        If(($Token.Type -eq 'GroupStart') -AND ($Token.Content -eq '('))
        {
            $GroupStartCount = 1
            $ConcatenatedStringsIndexStart = $Token.Start+1
        }
        ElseIf(($Token.Type -eq 'GroupEnd') -AND ($Token.Content -eq ')') -OR ($Token.Type -eq 'Operator') -AND ($Token.Content -ne '+'))
        {
            $GroupStartCount--
            $ConcatenatedStringsIndexEnd = $Token.Start
            If(($GroupStartCount -eq 0) -AND ($ConcatenatedStringsArray.Count -gt 0))
            {
                Break
            }
        }
        ElseIf(($GroupStartCount -gt 0) -AND ($Token.Type -eq 'String'))
        {
            $ConcatenatedStringsArray += $Token.Content
        }
        ElseIf($Token.Type -ne 'Operator')
        {
            $GroupStartCount = 0
            $ConcatenatedStringsArray = @()
        }
    }
    $ConcatenatedStrings = $ScriptString.SubString($ConcatenatedStringsIndexStart,$ConcatenatedStringsIndexEnd-$ConcatenatedStringsIndexStart)
    If($ConcatenatedStringsArray.Count -le 1)
    {
        Return $ScriptString
    }
    $RandomIndexes = (Get-Random -Input (0..$($ConcatenatedStringsArray.Count-1)) -Count $ConcatenatedStringsArray.Count)
    $Arguments1 = ''
    $Arguments2 = @('')*$ConcatenatedStringsArray.Count
    For($i=0; $i -lt $ConcatenatedStringsArray.Count; $i++)
    {
        $RandomIndex = $RandomIndexes[$i]
        $Arguments1 += '{' + $RandomIndex + '}'
        $Arguments2[$RandomIndex] = "'" + $ConcatenatedStringsArray[$i] + "'"
    }
    $ScriptStringReordered = '(' + '"' + $Arguments1 + '"' + ' '*(Get-Random @(0..1)) + '-f' + ' '*(Get-Random @(0..1)) + ($Arguments2 -Join ',') + ')'
    $ScriptString = $ScriptString.SubString(0,$ConcatenatedStringsIndexStart) + $ScriptStringReordered + $ScriptString.SubString($ConcatenatedStringsIndexEnd)
    Return $ScriptString
}
function Out-StringReversed
{
    [CmdletBinding()] Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptString
    )
    $ScriptString = Out-ObfuscatedStringCommand ([ScriptBlock]::Create($ScriptString)) 1
    $ScriptStringReversed = $ScriptString[-1..-($ScriptString.Length)] -Join ''
    $CharsToRandomVarName  = @(0..9)
    $CharsToRandomVarName += @('A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z')
    $RandomVarLength = (Get-Random -Input @(3..6))
    If($CharsToRandomVarName.Count -lt $RandomVarLength) {$RandomVarLength = $CharsToRandomVarName.Count}
    $RandomVarName = ((Get-Random -Input $CharsToRandomVarName -Count $RandomVarLength) -Join '').Replace(' ','')
    While($ScriptString.ToLower().Contains($RandomVarName.ToLower()))
    {
        $RandomVarName = ((Get-Random -Input $CharsToRandomVarName -Count $RandomVarLength) -Join '').Replace(' ','')
        $RandomVarLength++
    }
    $RandomVarNameMaybeConcatenated = $RandomVarName
    $RandomVarNameMaybeConcatenatedWithVariablePrepended = 'variable:' + $RandomVarName
    If((Get-Random -Input @(0..1)) -eq 0)
    {
        $RandomVarNameMaybeConcatenated = '(' + (Out-ConcatenatedString $RandomVarName (Get-Random -Input @('"',"'"))) + ')'
        $RandomVarNameMaybeConcatenatedWithVariablePrepended = '(' + (Out-ConcatenatedString "variable:$RandomVarName" (Get-Random -Input @('"',"'"))) + ')'
    }
    $RandomVarValPlaceholder = '<[)(]>'
    $RandomVarSetSyntax  = @()
    $RandomVarSetSyntax += '$' + $RandomVarName + ' '*(Get-Random @(0..2)) + '=' + ' '*(Get-Random @(0..2)) + $RandomVarValPlaceholder
    $RandomVarSetSyntax += (Get-Random -Input @('Set-Variable','SV','Set')) + ' '*(Get-Random @(1..2)) + $RandomVarNameMaybeConcatenated + ' '*(Get-Random @(1..2)) + '(' + ' '*(Get-Random @(0..2)) + $RandomVarValPlaceholder + ' '*(Get-Random @(0..2)) + ')'
    $RandomVarSet = (Get-Random -Input $RandomVarSetSyntax)
    $RandomVarSet = Out-RandomCase $RandomVarSet
    $RandomVarGetSyntax  = @()
    $RandomVarGetSyntax += '$' + $RandomVarName
    $RandomVarGetSyntax += '(' + ' '*(Get-Random @(0..2)) + (Get-Random -Input @('Get-Variable','Variable')) + ' '*(Get-Random @(1..2)) + $RandomVarNameMaybeConcatenated + (Get-Random -Input ((' '*(Get-Random @(0..2)) + ').Value'),(' '*(Get-Random @(1..2)) + ('-ValueOnly'.SubString(0,(Get-Random -Minimum 3 -Maximum ('-ValueOnly'.Length+1)))) + ' '*(Get-Random @(0..2)) + ')')))
    $RandomVarGetSyntax += '(' + ' '*(Get-Random @(0..2)) + (Get-Random -Input @('DIR','Get-ChildItem','GCI','ChildItem','LS','Get-Item','GI','Item')) + ' '*(Get-Random @(1..2)) + $RandomVarNameMaybeConcatenatedWithVariablePrepended + ' '*(Get-Random @(0..2)) + ').Value'
    $RandomVarGet = (Get-Random -Input $RandomVarGetSyntax)
    $RandomVarGet = Out-RandomCase $RandomVarGet
    $SetOfsVarSyntax      = @()
    $SetOfsVarSyntax     += '$OFS' + ' '*(Get-Random -Input @(0,1)) + '=' + ' '*(Get-Random -Input @(0,1))  + "''"
    $SetOfsVarSyntax     += 'Set-Item' + ' '*(Get-Random -Input @(1,2)) + "'Variable:OFS'" + ' '*(Get-Random -Input @(1,2)) + "''"
    $SetOfsVarSyntax     += (Get-Random -Input @('Set-Variable','SV','SET')) + ' '*(Get-Random -Input @(1,2)) + "'OFS'" + ' '*(Get-Random -Input @(1,2)) + "''"
    $SetOfsVar            = (Get-Random -Input $SetOfsVarSyntax)
    $SetOfsVarBackSyntax  = @()
    $SetOfsVarBackSyntax += 'Set-Item' + ' '*(Get-Random -Input @(1,2)) + "'Variable:OFS'" + ' '*(Get-Random -Input @(1,2)) + "' '"
    $SetOfsVarBackSyntax += (Get-Random -Input @('Set-Variable','SV','SET')) + ' '*(Get-Random -Input @(1,2)) + "'OFS'" + ' '*(Get-Random -Input @(1,2)) + "' '"
    $SetOfsVarBack        = (Get-Random -Input $SetOfsVarBackSyntax)
    $SetOfsVar            = Out-RandomCase $SetOfsVar
    $SetOfsVarBack        = Out-RandomCase $SetOfsVarBack
    $StringStr            = Out-RandomCase 'string'
    $JoinStr              = Out-RandomCase 'join'
    $LengthStr            = Out-RandomCase 'length'
    $ArrayStr             = Out-RandomCase 'array'
    $ReverseStr           = Out-RandomCase 'reverse'
    $CharStr              = Out-RandomCase 'char'
    $RightToLeftStr       = Out-RandomCase 'righttoleft'
    $RegexStr             = Out-RandomCase 'regex'
    $MatchesStr           = Out-RandomCase 'matches'
    $ValueStr             = Out-RandomCase 'value'
    $ForEachObject        = Out-RandomCase (Get-Random -Input @('ForEach-Object','ForEach','%'))
    Switch(Get-Random -Input (1..3)) {
        1 {
            $RandomVarSet = $RandomVarSet.Replace($RandomVarValPlaceholder,('"' + ' '*(Get-Random -Input @(0,1)) + $ScriptStringReversed + ' '*(Get-Random -Input @(0,1)) + '"'))
            $ScriptString = $RandomVarSet + ' '*(Get-Random -Input @(0,1)) + ';' + ' '*(Get-Random -Input @(0,1))
            $RandomVarGet = $RandomVarGet + '[' + ' '*(Get-Random -Input @(0,1)) + '-' + ' '*(Get-Random -Input @(0,1)) + '1' + ' '*(Get-Random -Input @(0,1)) + '..' + ' '*(Get-Random -Input @(0,1)) + '-' + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $RandomVarGet + ".$LengthStr" + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + ']'
            $JoinOptions  = @()
            $JoinOptions += "-$JoinStr" + ' '*(Get-Random -Input @(0,1)) + $RandomVarGet
            $JoinOptions += $RandomVarGet + ' '*(Get-Random -Input @(0,1)) + "-$JoinStr" + ' '*(Get-Random -Input @(0,1)) + "''"
            $JoinOptions += "[$StringStr]::$JoinStr" + '(' + ' '*(Get-Random -Input @(0,1)) + "''" + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + (Get-Random -Input $RandomVarGet) + ' '*(Get-Random -Input @(0,1)) + ')'
            $JoinOptions += '"' + ' '*(Get-Random -Input @(0,1)) + '$(' + ' '*(Get-Random -Input @(0,1)) + $SetOfsVar + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '"' + ' '*(Get-Random -Input @(0,1)) + '+' + ' '*(Get-Random -Input @(0,1)) + "[$StringStr]" + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $RandomVarGet + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '+' + '"' + ' '*(Get-Random -Input @(0,1)) + '$(' + ' '*(Get-Random -Input @(0,1)) + $SetOfsVarBack + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '"'
            $JoinOption = (Get-Random -Input $JoinOptions)
            $JoinOption = Out-EncapsulatedInvokeExpression $JoinOption
            $ScriptString = $ScriptString + $JoinOption
        }
        2 {
            $RandomVarSet = $RandomVarSet.Replace($RandomVarValPlaceholder,("[$CharStr[" + ' '*(Get-Random -Input @(0,1)) + ']' + ' '*(Get-Random -Input @(0,1)) + ']' + ' '*(Get-Random -Input @(0,1)) + '"' + $ScriptStringReversed + '"'))
            $ScriptString = $RandomVarSet + ' '*(Get-Random -Input @(0,1)) + ';' + ' '*(Get-Random -Input @(0,1))
            $ScriptString = $ScriptString + ' '*(Get-Random -Input @(0,1)) + "[$ArrayStr]::$ReverseStr(" + ' '*(Get-Random -Input @(0,1)) + $RandomVarGet + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + ';'
            $JoinOptions  = @()
            $JoinOptions += "-$JoinStr" + ' '*(Get-Random -Input @(0,1)) + $RandomVarGet
            $JoinOptions += $RandomVarGet + ' '*(Get-Random -Input @(0,1)) + "-$JoinStr" + ' '*(Get-Random -Input @(0,1)) + "''"
            $JoinOptions += "[$StringStr]::$JoinStr" + '(' + ' '*(Get-Random -Input @(0,1)) + "''" + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + $RandomVarGet + ' '*(Get-Random -Input @(0,1)) + ')'
            $JoinOptions += '"' + ' '*(Get-Random -Input @(0,1)) + '$(' + ' '*(Get-Random -Input @(0,1)) + $SetOfsVar + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '"' + ' '*(Get-Random -Input @(0,1)) + '+' + ' '*(Get-Random -Input @(0,1)) + "[$StringStr]" + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $RandomVarGet + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '+' + '"' + ' '*(Get-Random -Input @(0,1)) + '$(' + ' '*(Get-Random -Input @(0,1)) + $SetOfsVarBack + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '"'
            $JoinOption = (Get-Random -Input $JoinOptions)
            $JoinOption = Out-EncapsulatedInvokeExpression $JoinOption
            $ScriptString = $ScriptString + $JoinOption
        }
        3 {
            If(Get-Random -Input (0..1))
            {
                $RightToLeft = Out-ConcatenatedString $RightToLeftStr "'"
            }
            Else
            {
                $RightToLeft = "'$RightToLeftStr'"
            }
            $JoinOptions  = @()
            $JoinOptions += ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + "-$JoinStr" + ' '*(Get-Random -Input @(0,1)) + "[$RegexStr]::$MatchesStr(" + ' '*(Get-Random -Input @(0,1)) + '"' + $ScriptStringReversed + ' '*(Get-Random -Input @(0,1)) + '"' + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + "'.'" + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + $RightToLeft + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1))
            $JoinOptions += ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + "[$RegexStr]::$MatchesStr(" + ' '*(Get-Random -Input @(0,1)) + '"' + $ScriptStringReversed + '"' + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + "'.'" + ' '*(Get-Random -Input @(0,1)) + ',' +  ' '*(Get-Random -Input @(0,1)) + $RightToLeft + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + "-$JoinStr" + ' '*(Get-Random -Input @(0,1)) + "''" + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1))
            $JoinOptions += ' '*(Get-Random -Input @(0,1)) + "[$StringStr]::$JoinStr(" + ' '*(Get-Random -Input @(0,1)) + "''" + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + "[$RegexStr]::$MatchesStr(" + ' '*(Get-Random -Input @(0,1)) + '"' + $ScriptStringReversed + '"' + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + "'.'" + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + $RightToLeft + ' '*(Get-Random -Input @(0,1)) + ")" + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $ForEachObject + ' '*(Get-Random -Input @(0,1)) + '{' + ' '*(Get-Random -Input @(0,1)) + '$_' + ".$ValueStr" + ' '*(Get-Random -Input @(0,1)) + '}' + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1))
            $JoinOptions += '"' + ' '*(Get-Random -Input @(0,1)) + '$(' + ' '*(Get-Random -Input @(0,1)) + $SetOfsVar + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '"' + ' '*(Get-Random -Input @(0,1)) + '+' +          ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + "[$StringStr]" + ' '*(Get-Random -Input @(0,1)) + "[$RegexStr]::$MatchesStr(" + ' '*(Get-Random -Input @(0,1)) + '"' + $ScriptStringReversed + '"' + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + "'.'" + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + $RightToLeft + ' '*(Get-Random -Input @(0,1)) + ")" + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $ForEachObject + ' '*(Get-Random -Input @(0,1)) + '{' + ' '*(Get-Random -Input @(0,1)) + '$_' + ' '*(Get-Random -Input @(0,1)) + '}' + ' '*(Get-Random -Input @(0,1)) + ')'             + ' '*(Get-Random -Input @(0,1)) + '+' + '"' + ' '*(Get-Random -Input @(0,1)) + '$(' + ' '*(Get-Random -Input @(0,1)) + $SetOfsVarBack + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '"'
            $ScriptString = (Get-Random -Input $JoinOptions)
            $ScriptString = Out-EncapsulatedInvokeExpression $ScriptString
        }
        default {Write-Error "An invalid value was passed to switch block."; Exit;}
    }
    $SpecialCharacters = @('a','b','f','n','r','u','t','v','0')
    ForEach($SpecialChar in $SpecialCharacters)
    {
        If($ScriptString.Contains("``"+$SpecialChar))
        {
            $ScriptString = $ScriptString.Replace("``"+$SpecialChar,$SpecialChar)
        }
    }
    Return $ScriptString
}
function Out-EncapsulatedInvokeExpression
{
    [CmdletBinding()] Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ScriptString
    )
    $InvokeExpressionSyntax  = @()
    $InvokeExpressionSyntax += (Get-Random -Input @('IEX','Invoke-Expression'))
    $InvocationOperator = (Get-Random -Input @('.','&')) + ' '*(Get-Random -Input @(0,1))
    $InvokeExpressionSyntax += $InvocationOperator + "( `$ShellId[1]+`$ShellId[13]+'x')"
    $InvokeExpressionSyntax += $InvocationOperator + "( `$PSHome[" + (Get-Random -Input @(4,21)) + "]+`$PSHome[" + (Get-Random -Input @(30,34)) + "]+'x')"
    $InvokeExpressionSyntax += $InvocationOperator + "( `$env:ComSpec[4," + (Get-Random -Input @(15,24,26)) + ",25]-Join'')"
    $InvokeExpressionSyntax += $InvocationOperator + "((" + (Get-Random -Input @('Get-Variable','GV','Variable')) + " '*mdr*').Name[3,11,2]-Join'')"
    $InvokeExpressionSyntax += $InvocationOperator + "( " + (Get-Random -Input @('$VerbosePreference.ToString()','([String]$VerbosePreference)')) + "[1,3]+'x'-Join'')"
    $InvokeExpression = (Get-Random -Input $InvokeExpressionSyntax)
    $InvokeExpression = Out-RandomCase $InvokeExpression
    $InvokeOptions  = @()
    $InvokeOptions += ' '*(Get-Random -Input @(0,1)) + $InvokeExpression + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $ScriptString + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1))
    $InvokeOptions += ' '*(Get-Random -Input @(0,1)) + $ScriptString + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $InvokeExpression
    $ScriptString = (Get-Random -Input $InvokeOptions)
    Return $ScriptString
}
#}
#function Out-ObfuscatedAst {
function Out-ObfuscatedAst
{
    [CmdletBinding(DefaultParameterSetName = "ByString")] Param(
        [Parameter(ParameterSetName = "ByString", Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String] $ScriptString,
        [Parameter(ParameterSetName = "ByScriptBlock", Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock] $ScriptBlock,
        [Parameter(ParameterSetName = "ByPath", Position = 0, ValueFromPipelineByPropertyName, Mandatory)]
        [ValidateScript({Test-Path $_ -PathType leaf})]
        [Alias('PSPath')]
        [String] $ScriptPath,
        [Parameter(ParameterSetName = "ByUri", Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory)]
        [ValidateScript({$_.Scheme -match 'http|https'})]
        [Uri] $ScriptUri,
        [Parameter(ParameterSetName = "ByTree", Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.Ast] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        If ($ScriptString) { $AbstractSyntaxTree = Get-Ast -ScriptString $ScriptString }
        ElseIf ($ScriptBlock) {
            $AbstractSyntaxTree = Get-Ast -ScriptBlock $ScriptBlock
        }
        ElseIf ($ScriptPath) {
            $AbstractSyntaxTree = Get-Ast -ScriptPath $ScriptPath
        }
        ElseIf ($ScriptUri) {
            $AbstractSyntaxTree = Get-Ast -ScriptUri $ScriptUri
        }
        Switch ($AbstractSyntaxTree.GetType().Name) {
            "ArrayExpressionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedArrayExpressionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedArrayExpressionAst -Ast $AbstractSyntaxTree }
            }
            "ArrayLiteralAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedArrayLiteralAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedArrayLiteralAst -AstTypesToObfuscate $AstTypesToObfuscate -Ast $AbstractSyntaxTree }
            }
            "AssignmentStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedAssignmentStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedAssignmentStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "AttributeAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedAttributeAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedAttributeAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "AttributeBaseAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedAttributeBaseAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedAttributeBaseAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "AttributedExpessionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedAttributedExpessionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedAssignmentStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "BaseCtorInvokeMemberExpressionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedBaseCtorInvokeMemberExpressionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedBaseCtorInvokeMemberExpressionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "BinaryExpressionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedBinaryExpressionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedBinaryExpressionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "BlockStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedBlockStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedBlockStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "BreakStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedBreakStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedBreakStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "CatchClauseAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedCatchClauseAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedCatchClauseAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "CommandAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedCommandAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedCommandAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "CommandBaseAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedCommandBaseAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedCommandBaseAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "CommandElementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedCommandElementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedCommandElementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "CommandExpressionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedCommandExpressionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedCommandExpressionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "CommandParameterAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedCommandParameterAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedCommandParameterAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "ConfigurationDefinitionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedConfigurationDefinitionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedConfigurationDefinitionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "ConstantExpressionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedConstantExpressionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedConstantExpressionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "ContinueStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedContinueStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { $ObfuscatedExtent = Out-ObfuscatedContinueStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "ConvertExpressionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedConvertExpressionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedConvertExpressionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "DataStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedDataStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedDataStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "DoUntilStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedDoUntilStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedDoUntilStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "DoWhileStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedDoWhileStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedDoWhileStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "DynamicKeywordStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedDynamicKeywordStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedDynamicKeywordStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "ErrorStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedErrorStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedErrorStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "ExitStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedExitStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedExitStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "ExpandableStringExpressionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedExpandableStringExpressionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedExpandableStringExpressionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "ExpressionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedExpressionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedExpressionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "FileRedirectionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedFileRedirectionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedFileRedirectionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "ForEachStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedForEachStatementAstt -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedForEachStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "ForStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedForStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedForStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "FunctionDefinitionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedFunctionDefinitionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedFunctionDefinitionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "FunctionMemberAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedFunctionMemberAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedFunctionMemberAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "HashtableAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedHashtableAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedHashtableAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "IfStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedIfStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedIfStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "IndexExpressionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedIndexExpressionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedIndexExpressionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "InvokeMemberExpressionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedInvokeMemberExpressionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedInvokeMemberExpressionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "LabeledStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedLabeledStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedLabeledStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "LoopStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedLoopStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedLoopStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "MemberAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedMemberAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedMemberAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "MemberExpressionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedMemberExpressionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedMemberExpressionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "MergingRedirectionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedMergingRedirectionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedMergingRedirectionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "NamedAttributeArgumentAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedNamedAttributeArgumentAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedNamedAttributeArgumentAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "NamedBlockAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedNamedBlockAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedNamedBlockAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "ParamBlockAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedParamBlockAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedParamBlockAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "ParameterAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedParameterAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedParameterAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "ParenExpressionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedParenExpressionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedParenExpressionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "PipelineAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedPipelineAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedPipelineAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "PipelineBaseAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedPipelineBaseAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedPipelineBaseAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "PropertyMemberAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedPropertyMemberAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedPropertyMemberAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "RedirectionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedRedirectionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedRedirectionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "ReturnStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedReturnStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedReturnStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "ScriptBlockAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedScriptBlockAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedScriptBlockAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "ScriptBlockExpressionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedScriptBlockExpressionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedScriptBlockExpressionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "StatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "StatementBlockAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedStatementBlockAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedStatementBlockAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "StringConstantExpressionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedStringConstantExpressionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedStringConstantExpressionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "SubExpressionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedSubExpressionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedSubExpressionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "SwitchStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedSwitchStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedSwitchStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "ThrowStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedThrowStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedThrowStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "TrapStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedTrapStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedTrapStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "TryStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedTryStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedTryStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "TypeConstraintAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedTypeConstraintAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedTypeConstraintAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "TypeDefinitionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedTypeDefinitionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedTypeDefinitionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "TypeExpressionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedTypeExpressionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedTypeExpressionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "UnaryExpressionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedUnaryExpressionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedUnaryExpressionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "UsingExpressionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedUsingExpressionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedUsingExpressionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "UsingStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedUsingStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedUsingStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "VariableExpressionAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedVariableExpressionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedVariableExpressionAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            "WhileStatementAst" {
                If ($DisableNestedObfuscation) { Out-ObfuscatedWhileStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation }
                Else { Out-ObfuscatedWhileStatementAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
        }
    }
}
function Out-ObfuscatedAttributeBaseAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.AttributeBaseAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedAttributeBaseAst]"
        If ($AbstractSyntaxTree.GetType().Name -eq 'AttributeAst') {
            Out-ObfuscatedAttributeAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'TypeConstraintAst') {
            Out-ObfuscatedTypeConstraintAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        ElseIf (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else {
            $AbstractSyntaxTree.Extent.Text
        }
    }
}
function Out-ObfuscatedCatchClauseAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.CatchClauseAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedCatchClauseAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedCommandElementAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.CommandElementAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedCommandElementAst]"
        If ($AbstractSyntaxTree.GetType().Name -eq 'CommandParameterAst') {
            Out-ObfuscatedCommandParameterAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'ExpressionAst') {
            Out-ObfuscatedExpressionAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        ElseIf (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else {
            $AbstractSyntaxTree.Extent.Text
        }
    }
}
function Out-ObfuscatedMemberAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.MemberAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedMemberAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedNamedAttributeArgumentAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.NamedAttributeArgumentAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedNamedAttributeArgumentAst]"
        If (-not ($AbstractSyntaxTree.GetType() -in $AstTypesToObfuscate)) {
            If (-not $DisableNestedObfuscation) {
                Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
            }
            Else { $AbstractSyntaxTree.Extent.Text }
        }
        ElseIf ($AbstractSyntaxTree.ExpressionOmitted) {
            $AbstractSyntaxTree.Extent.Text + " = `$True"
        }
        ElseIf ($AbstractSyntaxTree.Argument.Extent.Text -eq "`$True") {
            $AbstractSyntaxTree.ArgumentName
        }
        ElseIf (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedNamedBlockAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.NamedBlockAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedNamedBlockAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedParamBlockAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ParamBlockAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedParamBlockAst]"
        If (-not ($AbstractSyntaxTree.GetType() -in $AstTypesToObfuscate)) {
            If (-not $DisableNestedObfuscation) {
                Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
            }
            Else { $AbstractSyntaxTree.Extent.Text }
        }
        ElseIf (-not $DisableNestedObfuscation) {
            $Children = (Get-AstChildren -AbstractSyntaxTree $AbstractSyntaxTree | ? { $_.Extent.StartScriptPosition.GetType().Name -ne 'EmptyScriptPosition' } | Sort-Object { $_.Extent.StartOffset }) -as [array]
            $ChildrenNotAttributes = $Children | ? { -not ($_ -in $AbstractSyntaxTree.Attributes) }
            $ChildrenAttributes = $Children | ? { $_ -in $AbstractSyntaxTree.Attributes }
            Out-ObfuscatedAstsReordered -ParentAst $AbstractSyntaxTree -ChildrenAsts $ChildrenNotAttributes -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedParameterAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ParameterAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedParameterAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedRedirectionAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.RedirectionAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedRedirectionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedScriptBlockAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ScriptBlockAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedScriptBlockAst]"
        If (-not ($AbstractSyntaxTree.GetType() -in $AstTypesToObfuscate)) {
            If (-not $DisableNestedObfuscation) {
                Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
            }
            Else { $AbstractSyntaxTree.Extent.Text }
        }
        ElseIf (-not $DisableNestedObfuscation) {
            $Children = (Get-AstChildren -Ast $AbstractSyntaxTree | ? { $_.Extent.StartScriptPosition.GetType().Name -ne 'EmptyScriptPosition' }) -as [array]
            $RealChildren = $Children
            $FunctionDefinitionBlocks = @()
            If ($AbstractSyntaxTree.BeginBlock) { $FunctionDefinitionBlocks += $AbstractSyntaxTree.BeginBlock }
            If ($AbstractSyntaxTree.ProcessBlock) { $FunctionDefinitionBlocks += $AbstractSyntaxTree.ProcessBlock }
            If ($AbstractSyntaxTree.EndBlock) { $FunctionDefinitionBlocks += $AbstractSyntaxTree.EndBlock }
            If ($Children.Count -eq 2 -AND $Children[0].GetType().Name -eq 'ParamBlockAst' -AND $Children[1].GetType().Name -eq 'NamedBlockAst' -AND $Children[1] -eq $AbstractSyntaxTree.EndBlock) {
                [System.Management.Automation.Language.Ast[]] $RealChildren = ($Children[0]) -as [array]
                $RealChildren += (Get-AstChildren -Ast $Children[1] | ? { $_.Extent.StartScriptPosition.GetType().Name -ne 'EmptyScriptPosition' } | Sort-Object { $_.Extent.StartOffset }) -as [array]
                Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -ChildrenAsts $RealChildren -AstTypesToObfuscate $AstTypesToObfuscate
            }
            ElseIf ($FunctionDefinitionBlocks.Count -gt 1) {
                $Children = $Children | Sort-Object { $_.Extent.StartOffset }
                $Reordered  = Out-ObfuscatedAstsReordered -ParentAst $AbstractSyntaxTree -ChildrenAsts ($FunctionDefinitionBlocks | Sort-Object { $_.Extent.StartOffset }) -AstTypesToObfuscate $AstTypesToObfuscate
                If ($AbstractSyntaxTree.ParamBlock) {
                    $ObfuscatedParamBlock = Out-ObfuscatedAst -AbstractSyntaxTree $AbstractSyntaxTree.ParamBlock -AstTypesToObfuscate $AstTypesToObfuscate
                    $FinalObfuscated = [String] $AbstractSyntaxTree.Extent.Text.Substring(0, $AbstractSyntaxTree.ParamBlock.Extent.StartOffset - $AbstractSyntaxTree.Extent.StartOffset)
                    $FinalObfuscated += [String] $ObfuscatedParamBlock
                    $FinalObfuscated += [String] $Reordered.Substring($AbstractSyntaxTree.ParamBlock.Extent.StartOffset - $AbstractSyntaxTree.Extent.StartOffset + $AbstractSyntaxTree.ParamBlock.Extent.Text.Length)
                } Else { $FinalObfuscated = $Reordered }
                $FinalObfuscated
            }
            Else {
                $Children = $Children | Sort-Object { $_.Extent.StartOffset }
                Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -ChildrenAsts $Children -AstTypesToObfuscate $AstTypesToObfuscate
            }
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedStatementAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.StatementAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedStatementBlockAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.StatementBlockAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedStatementBlockAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedAttributeAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.AttributeAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedAttributeAst]"
        If (-not ($AbstractSyntaxTree.GetType() -in $AstTypesToObfuscate)) {
            If (-not $DisableNestedObfuscation) {
                Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
            }
            Else { $AbstractSyntaxTree.Extent.Text }
        }
        Else {
            $ObfuscatedString = $AbstractSyntaxTree.Extent.Text
            If ($AbstractSyntaxTree.NamedArguments.Count -gt 0) {
                $NamedArguments = $AbstractSyntaxTree.NamedArguments
                If ($DisableNestedObfuscation) {
                    $ObfuscatedString = Out-ObfuscatedAstsReordered -ParentAst $AbstractSyntaxTree -ChildrenAsts $NamedArguments -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation
                } Else {
                    $ObfuscatedString = Out-ObfuscatedAstsReordered -ParentAst $AbstractSyntaxTree -ChildrenAsts $NamedArguments -AstTypesToObfuscate $AstTypesToObfuscate
                }
            }
            ElseIf ($AbstractSyntaxTree.PositionalArguments.Count -gt 0) {
                If ($AbstractSyntaxTree.TypeName.FullName -in @('Alias', 'ValidateSet')) {
                    $PositionalArguments = $AbstractSyntaxTree.PositionalArguments
                    If ($DisableNestedObfuscation) {
                        $ObfuscatedString = Out-ObfuscatedAstsReordered -ParentAst $AbstractSyntaxTree -ChildrenAsts $PositionalArguments -AstTypesToObfuscate $AstTypesToObfuscate -DisableNestedObfuscation
                    } Else {
                        $ObfuscatedString = Out-ObfuscatedAstsReordered -ParentAst $AbstractSyntaxTree -ChildrenAsts $PositionalArguments -AstTypesToObfuscate $AstTypesToObfuscate
                    }
                }
            }
            $ObfuscatedString
        }
    }
}
function Out-ObfuscatedTypeConstraintAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.TypeConstraintAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedTypeConstraintAst]"
        If (-not ($AbstractSyntaxTree.GetType() -in $AstTypesToObfuscate)) {
            If (-not $DisableNestedObfuscation) {
                Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
            }
            Else { $AbstractSyntaxTree.Extent.Text }
        }
        Else {
            $TypeAccelerators = @(
                @("[Int]", "[System.Int32]"),
                @("[Long]", "[System.Int64]"),
                @("[Bool]", "[System.Boolean]"),
                @("[Float]", "[System.Single]"),
                @("[Regex]", "[System.Text.RegularExpressions.Regex]"),
                @("[Xml]", "[System.Xml.XmlDocument]"),
                @("[ScriptBlock]", "[System.Management.Automation.ScriptBlock]"),
                @("[Switch]", "[System.Management.Automation.SwitchParameter]"),
                @("[HashTable]", "[System.Collections.HashTable]"),
                @("[Ref]", "[System.Management.Automation.PSReference]"),
                @("[PSObject]", "[System.Management.Automation.PSObject]"),
                @("[PSCustomObject]", "[System.Management.Automation.PSCustomObject]"),
                @("[PSModuleInfo]", "[System.Management.Automation.PSModuleInfo]"),
                @("[PowerShell]", "[System.Management.Automation.PSModuleInfo]"),
                @("[RunspaceFactory]", "[System.Management.Automation.Runspaces.RunspaceFactory]"),
                @("[Runspace]", "[System.Management.Automation.Runspaces.Runspace]"),
                @("[IPAddress]", "[System.Net.IPAddress]"),
                @("[WMI]", "[System.Management.ManagementObject]"),
                @("[WMISearcher]", "[System.Management.ManagementObjectSearcher]"),
                @("[WMIClass]", "[System.Management.ManagementClass]"),
                @("[ADSI]", "[System.DirectoryServices.DirectoryEntry]"),
                @("[ADSISearcher]", "[System.DirectoryServices.DirectorySearcher]"),
                @("[PSPrimitiveDictionary]", "[System.Management.Automation.PSPrimitiveDictionary]")
            )
            $TypesCannotPrependSystem = $TypeAccelerators | %  { $_[0] }
            $ObfuscatedExtent = $AbstractSyntaxTree.Extent.Text
            $FoundEquivalent = $False
            ForEach ($TypeAccelerator in $TypeAccelerators) {
                ForEach ($TypeName in $TypeAccelerator) {
                    If ($TypeName.ToLower() -eq $AbstractSyntaxTree.Extent.Text.ToLower()) {
                        $ObfuscatedExtent = $TypeAccelerator | Get-Random
                        $FoundEquivalent = $True
                        break
                    }
                }
                If ($FoundEquivalent)  { break }
            }
            If ($ObfuscatedExtent.ToLower().StartsWith("[system.")) {
                If ((Get-Random -Minimum 1 -Maximum 3) -eq 1) {
                    $ObfuscatedExtent = "[" + $ObfuscatedExtent.SubString(8)
                }
            }
            ElseIf ((-not $ObfuscatedExtent.ToLower().StartsWith("[system.")) -AND (-not $ObfuscatedExtent -in $TypesCannotPrependSystem)) {
                If ((Get-Random -Minimum 1 -Maximum 3) -eq 1) {
                    $ObfuscatedExtent = "[System." + $ObfuscatedExtent.SubString(1)
                }
            }
            $ObfuscatedExtent
        }
    }
}
function Out-ObfuscatedCommandParameterAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.CommandParameterAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedCommandParameterAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedExpressionAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ExpressionAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedExpressionAst]"
        If ($AbstractSyntaxTree.GetType().Name -eq 'ArrayExpressionAst') {
            Out-ObfuscatedArrayExpressionAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'ArrayLiteralAst') {
            Out-ObfuscatedArrayLiteralAst -AbstractSyntaxTree $AbstractSyntaxTree
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'AttributedExpressionAst') {
            Out-ObfuscatedAttributedExpressionAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'BinaryExpressionAst') {
            Out-ObfuscatedBinaryExpressionAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'ConstantExpressionAst') {
            Out-ObfuscatedConstantExpressionAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'ErrorExpressionAst') {
            Out-ObfuscatedErrorExpressionAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'ExpandedStringExpressionAst') {
            Out-ObfuscatedExpandedStringExpressionAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'HashtableAst') {
            Out-ObfuscatedHashtableAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'IndexExpressionAst') {
            Out-ObfuscatedIndexExpressionAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'MemberExpressionAst') {
            Out-ObfuscatedMemberExpressionAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'ParenExpressionAst') {
            Out-ObfuscatedParenExpressionAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'ScriptBlockExpressionAst') {
            Out-ObfuscatedScriptBlockExpressionAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'SubExpressionAst') {
            Out-ObfuscatedSubExpressionAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'TypeExpressionAst') {
            Out-ObfuscatedTypeExpressionAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'UnaryExpressionAst') {
            Out-ObfuscatedUnaryExpressionAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'UsingExpressionAst') {
            Out-ObfuscatedUsingExpressionAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'VariableExpressionAst') {
            Out-ObfuscatedVariableExpressionAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        ElseIf (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else {
            $AbstractSyntaxTree.Extent.Text
        }
    }
}
function Out-ObfuscatedArrayExpressionAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ArrayExpressionAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedArrayExpressionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedArrayLiteralAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ArrayLiteralAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedArrayLiteralAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedAttributedExpressionAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.AttributedExpressionAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedAttributedExpressionAst]"
        If ($AbstractSyntaxTree.GetType().Name -eq 'ConvertExpressionAst') {
            Out-ObfuscatedArrayExpressionAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        ElseIf (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else {
            $AbstractSyntaxTree.Extent.Text
        }
    }
}
function Out-ObfuscatedBinaryExpressionAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.BinaryExpressionAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedBinaryExpressionAst]"
        If (-not ($AbstractSyntaxTree.GetType() -in $AstTypesToObfuscate)) {
            If (-not $DisableNestedObfuscation) {
                Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
            }
            Else { $AbstractSyntaxTree.Extent.Text }
        }
        Else {
            $OperatorText = [System.Management.Automation.Language.TokenTraits]::Text($AbstractSyntaxTree.Operator)
            $ObfuscatedString = $AbstractSyntaxTree.Extent.Text
            If((Test-ExpressionAstIsNumeric -Ast $AbstractSyntaxTree.Left) -AND (Test-ExpressionAstIsNumeric -Ast $AbstractSyntaxTree.Right)) {
                $Whitespace = ""
                If ((Get-Random @(0,1)) -eq 0) { $Whitespace = " " }
                $LeftString = $AbstractSyntaxTree.Left.Extent.Text
                $RightString = $AbstractSyntaxTree.Right.Extent.Text
                If (-not $DisableNestedObfuscation) {
                    $LeftString = Out-ObfuscatedAst -AbstractSyntaxTree $AbstractSyntaxTree.Left -AstTypesToObfuscate $AstTypesToObfuscate
                    $RightString = Out-ObfuscatedAst -AbstractSyntaxTree $AbstractSyntaxTree.Right -AstTypesToObfuscate $AstTypesToObfuscate
                }
                If ($OperatorText -in @("+", "*")) {
                    $ObfuscatedString = $RightString + $Whitespace + $OperatorText + $Whitespace + $LeftString
                }
                ElseIf ($OperatorText -eq "-") {
                    $ObfuscatedString = Out-ParenthesizedString ("-" + $Whitespace + (Out-ParenthesizedString ((Out-ParenthesizedString $RightString) + $Whitespace + $OperatorText + $Whitespace + (Out-ParenthesizedString $LeftString))))
                }
            }
            ElseIf (-not $DisableNestedObfuscation) { $ObfuscatedString = Out-ObfuscatedChildrenAst -Ast $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            $ObfuscatedString
        }
    }
}
function Out-ObfuscatedConstantExpressionAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ConstantExpressionAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedConstantExpressionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedErrorExpressionAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ErrorExpressionAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedErrorExpressionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedExpandableStringExpressionAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ExpandableStringExpressionAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedExpandableStringExpressionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedHashtableAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.HashtableAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedHashtableAst]"
        If (-not ($AbstractSyntaxTree.GetType() -in $AstTypesToObfuscate)) {
            If (-not $DisableNestedObfuscation) {
                Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
            }
            Else { $AbstractSyntaxTree.Extent.Text }
        }
        Else {
            $ObfuscatedKeyValuePairs = @()
            $ChildrenAsts = $AbstractSyntaxTree.KeyValuePairs | %  { $_.Item1; $_.Item2 }
            If ($DisableNestedObfuscation) {
                $ObfuscatedKeyValuePairs = $AbstractSyntaxTree.KeyValuePairs
            }
            Else {
                ForEach ($KeyValuePair in $AbstractSyntaxTree.KeyValuePairs) {
                    $ObfuscatedItem1 = Out-ObfuscatedAst $KeyValuePair.Item1 -AstTypesToObfuscate $AstTypesToObfuscate
                    $ObfuscatedItem2 = Out-ObfuscatedAst $KeyValuePair.Item2 -AstTypesToObfuscate $AstTypesToObfuscate
                    $ObfuscatedKeyValuePairs += [System.Tuple]::Create($ObfuscatedItem1, $ObfuscatedItem2)
                }
            }
            $ObfuscatedString = $AbstractSyntaxTree.Extent.Text
            $ObfuscatedString = "@{"
            If ($ObfuscatedKeyValuePairs.Count -ge 1) {
                $ObfuscatedKeyValuePairs = $ObfuscatedKeyValuePairs | Get-Random -Count $ObfuscatedKeyValuePairs.Count
                ForEach ($ObfuscatedKeyValuePair in $ObfuscatedKeyValuePairs) {
                    $ObfuscatedString += $ObfuscatedKeyValuePair.Item1 + "=" + $ObfuscatedKeyValuePair.Item2 + ";"
                }
            }
            $ObfuscatedString += "}"
            $ObfuscatedString
        }
    }
}
function Out-ObfuscatedIndexExpressionAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.IndexExpressionAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedIndexExpressionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedMemberExpressionAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.MemberExpressionAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedMemberExpressionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedParenExpressionAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ParenExpressionAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedParenExpressionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedScriptBlockExpressionAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ScriptBlockExpressionAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedScriptBlockExpressionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedSubExpressionAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.SubExpressionAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedSubExpressionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedTypeExpressionAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.TypeExpressionAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedTypeExpressionAst]"
        If (-not ($AbstractSyntaxTree.GetType() -in $AstTypesToObfuscate)) {
            If (-not $DisableNestedObfuscation) {
                Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
            }
            Else { $AbstractSyntaxTree.Extent.Text }
        }
        Else {
            $TypeAccelerators = @(
                @("[Int]", "[System.Int32]"),
                @("[Long]", "[System.Int64]"),
                @("[Bool]", "[System.Boolean]"),
                @("[Float]", "[System.Single]"),
                @("[Regex]", "[System.Text.RegularExpressions.Regex]"),
                @("[Xml]", "[System.Xml.XmlDocument]"),
                @("[ScriptBlock]", "[System.Management.Automation.ScriptBlock]"),
                @("[Switch]", "[System.Management.Automation.SwitchParameter]"),
                @("[HashTable]", "[System.Collections.HashTable]"),
                @("[Ref]", "[System.Management.Automation.PSReference]"),
                @("[PSObject]", "[System.Management.Automation.PSObject]"),
                @("[PSCustomObject]", "[System.Management.Automation.PSCustomObject]"),
                @("[PSModuleInfo]", "[System.Management.Automation.PSModuleInfo]"),
                @("[PowerShell]", "[System.Management.Automation.PSModuleInfo]"),
                @("[RunspaceFactory]", "[System.Management.Automation.Runspaces.RunspaceFactory]"),
                @("[Runspace]", "[System.Management.Automation.Runspaces.Runspace]"),
                @("[IPAddress]", "[System.Net.IPAddress]"),
                @("[WMI]", "[System.Management.ManagementObject]"),
                @("[WMISearcher]", "[System.Management.ManagementObjectSearcher]"),
                @("[WMIClass]", "[System.Management.ManagementClass]"),
                @("[ADSI]", "[System.DirectoryServices.DirectoryEntry]"),
                @("[ADSISearcher]", "[System.DirectoryServices.DirectorySearcher]"),
                @("[PSPrimitiveDictionary]", "[System.Management.Automation.PSPrimitiveDictionary]")
            )
            $TypesCannotPrependSystem = $TypeAccelerators | %  { $_[0] }
            $ObfuscatedExtent = $AbstractSyntaxTree.Extent.Text
            $FoundEquivalent = $False
            ForEach ($TypeAccelerator in $TypeAccelerators) {
                ForEach ($TypeName in $TypeAccelerator) {
                    If ($TypeName.ToLower() -eq $AbstractSyntaxTree.Extent.Text.ToLower()) {
                        $ObfuscatedExtent = $TypeAccelerator | Get-Random
                        $FoundEquivalent = $True
                        break
                    }
                }
                If ($FoundEquivalent)  { break }
            }
            If ($ObfuscatedExtent.ToLower().StartsWith("[system.")) {
                If ((Get-Random -Minimum 1 -Maximum 3) -eq 1) {
                    $ObfuscatedExtent = "[" + $ObfuscatedExtent.SubString(8)
                }
            }
            ElseIf ((-not $ObfuscatedExtent.ToLower().StartsWith("[system.")) -AND (-not $ObfuscatedExtent -in $TypesCannotPrependSystem)) {
                If ((Get-Random -Minimum 1 -Maximum 3) -eq 1) {
                    $ObfuscatedExtent = "[System." + $ObfuscatedExtent.SubString(1)
                }
            }
            $ObfuscatedExtent
        }
    }
}
function Out-ObfuscatedUnaryExpressionAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.UnaryExpressionAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedUnaryExpressionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedUsingExpressionAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.UsingExpressionAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedUsingExpressionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedVariableExpressionAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.VariableExpressionAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedVariableExpressionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedConvertExpressionAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ConvertExpressionAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedConvertExpressionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -ChildrenAsts @($AbstractSyntaxTree.Attribute, $AbstractSyntaxTree.Child) -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedStringConstantExpressionAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.StringConstantExpressionAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedStringConstantExpressionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedInvokeMemberExpressionAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.InvokeMemberExpressionAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedInvokeMemberExpressionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedBaseCtorInvokeMemberExpressionAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.BaseCtorInvokeMemberExpressionAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedBaseCtorInvokeMemberExpressionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedFunctionMemberAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.FunctionMemberAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedFunctionMemberAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedPropertyMemberAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.PropertyMemberAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedPropertyMemberAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedFileRedirectionAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.FileRedirectionAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedFileRedirectionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedMergingRedirectionAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.MergingRedirectionAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedMergingRedirectionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedBlockStatementAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.BlockStatementAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedBlockStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedBreakStatementAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.BreakStatementAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedBreakStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedCommandBaseAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.CommandBaseAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedCommandBaseAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedConfigurationDefinitionAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ConfigurationDefinitionAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedConfigurationDefinitionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedContinueStatementAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ContinueStatementAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedContinueStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedDataStatementAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.DataStatementAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedDataStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedDynamicKeywordStatementAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.DynamicKeywordStatementAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedDynamicKeywordStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedExitStatementAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ExitStatementAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedExitStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedFunctionDefinitionAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.FunctionDefinitionAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedFunctionDefinitionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedIfStatementAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.IfStatementAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedIfStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedLabeledStatementAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.LabeledStatementAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedLabeledStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedPipelineBaseAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.PipelineBaseAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedPipelineBaseAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedReturnStatementAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ReturnStatementAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedReturnStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedThrowStatementAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ThrowStatementAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedThrowStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedTrapStatementAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.TrapStatementAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedTrapStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedTryStatementAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.TryStatementAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedTryStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedTypeDefinitionAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.TypeDefinitionAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedTypeDefinitionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedUsingStatementAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.UsingStatementAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedUsingStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedCommandAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.CommandAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedCommandAst]"
        If (-not ($AbstractSyntaxTree.GetType() -in $AstTypesToObfuscate)) {
            If (-not $DisableNestedObfuscation) {
                Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
            }
            Else { $AbstractSyntaxTree.Extent.Text }
        }
        ElseIf (-not $DisableNestedObfuscation) {
            $Children = Get-AstChildren -AbstractSyntaxTree $AbstractSyntaxTree
            If($Children.Count -ge 5) {
                $ReorderableIndices = @()
                $ObfuscatedReorderableExtents = @()
                $LastChild = $Children[1]
                For ([Int] $i = 2; $i -lt $Children.Count; $i++) {
                    $CurrentChild = $Children[$i]
                    If ($LastChild.GetType().Name -eq 'CommandParameterAst' -AND $CurrentChild.GetType().Name -ne 'CommandParameterAst') {
                        $FirstIndex = $LastChild.Extent.StartOffset - $AbstractSyntaxTree.Extent.StartOffset
                        $PairLength = $CurrentChild.Extent.StartOffset + $CurrentChild.Extent.Text.Length - $LastChild.Extent.StartOffset
                        $SecondIndex = $CurrentChild.Extent.StartOffset + $CurrentChild.Extent.Text.Length - $AbstractSyntaxTree.Extent.StartOffset
                        $PairExtent = $AbstractSyntaxTree.Extent.Text.Substring($FirstIndex, $PairLength)
                        $ObfuscatedLastChild = Out-ObfuscatedAst -AbstractSyntaxTree $LastChild -AstTypesToObfuscate $AstTypesToObfuscate
                        $ObfuscatedCurrentChild = Out-ObfuscatedAst -AbstractSyntaxTree $CurrentChild -AstTypesToObfuscate $AstTypesToObfuscate
                        $ObfuscatedPairExtent = $ObfuscatedLastChild + " " + $ObfuscatedCurrentChild
                        $ReorderableIndices += [Tuple]::Create($FirstIndex, $SecondIndex)
                        $ObfuscatedReorderableExtents += [String] $ObfuscatedPairExtent
                    }
                    ElseIf ($LastChild.GetType().Name -eq 'CommandParameterAst' -AND $CurrentChild.GetType().Name -eq 'CommandParameterAst') {
                        $ObfuscatedLastChild = Out-ObfuscatedAst -AbstractSyntaxTree $LastChild -AstTypesToObfuscate $AstTypesToObfuscate
                        $FirstIndex = $LastChild.Extent.StartOffset - $AbstractSyntaxTree.Extent.StartOffset
                        $SecondIndex = $LastChild.Extent.StartOffset + $LastChild.Extent.Text.Length - $AbstractSyntaxTree.Extent.StartOffset
                        $ReorderableIndices += [Tuple]::Create($FirstIndex, $SecondIndex)
                        $ObfuscatedReorderableExtents += [String] $ObfuscatedLastChild
                    }
                    ElseIf ($CurrentChild.GetType().Name -eq 'CommandParameterAst' -AND $i -eq ($Children.Count -1)) {
                        $ObfuscatedCurrentChild = Out-ObfuscatedAst -AbstractSyntaxTree $CurrentChild -AstTypesToObfuscate $AstTypesToObfuscate
                        $FirstIndex = $CurrentChild.Extent.StartOffset - $AbstractSyntaxTree.Extent.StartOffset
                        $SecondIndex = $CurrentChild.Extent.StartOffset + $CurrentChild.Extent.Text.Length - $AbstractSyntaxTree.Extent.StartOffset
                        $ReorderableIndices += [Tuple]::Create($FirstIndex, $SecondIndex)
                        $ObfuscatedReorderableExtents += [String] $ObfuscatedCurrentChild
                    }
                    $LastChild = $CurrentChild
                }
                If ($ObfuscatedReorderableExtents.Count -gt 1) {
                    $ObfuscatedReorderableExtents = $ObfuscatedReorderableExtents | Get-Random -Count $ObfuscatedReorderableExtents.Count
                    $ObfuscatedExtent = $AbstractSyntaxTree.Extent.Text
                    For ([Int] $i = 0; $i -lt $ObfuscatedReorderableExtents.Count; $i++) {
                        $LengthDifference = $ObfuscatedExtent.Length - $AbstractSyntaxTree.Extent.Text.Length
                        $ObfuscatedExtent = $ObfuscatedExtent.Substring(0, $ReorderableIndices[$i].Item1 + $LengthDifference)
                        $ObfuscatedExtent += [String] $ObfuscatedReorderableExtents[$i]
                        $ObfuscatedExtent += [String] $AbstractSyntaxTree.Extent.Text.Substring($ReorderableIndices[$i].Item2)
                    }
                    $ObfuscatedExtent
                } Else { Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
            }
            Else { Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedCommandExpressionAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.CommandExpressionAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedCommandExpressionAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedLoopStatementAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.LoopStatementAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedLoopStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedSwitchStatementAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.SwitchStatementAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedSwitchStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedDoUntilStatementAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.DoUntilStatementAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedDoUntilStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedDoWhileStatementAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.DoWhileStatementAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedDoWhileStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedForEachStatementAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ForEachStatementAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedForEachStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedForStatementAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ForStatementAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedForStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedWhileStatementAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.WhileStatementAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedWhileStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedAssignmentStatementAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.AssignmentStatementAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedAssignmentStatementAst]"
        If (-not ($AbstractSyntaxTree.GetType() -in $AstTypesToObfuscate)) {
            If (-not $DisableNestedObfuscation) {
                Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
            }
            Else { $AbstractSyntaxTree.Extent.Text }
        }
        Else {
            $OperatorText = [System.Management.Automation.Language.TokenTraits]::Text($AbstractSyntaxTree.Operator)
            If ($AbstractSyntaxTree.Left.GetType().Name -eq "VariableExpressionAst" -AND $AbstractSyntaxTree.Left.VariablePath.IsVariable) {
                If ($OperatorText -eq "=") {
                    $RightExtent = $AbstractSyntaxTree.Right.Extent.Text
                    If (-not $DisableNestedObfuscation) { $RightExtent = Out-ObfuscatedAst -AbstractSyntaxTree $AbstractSyntaxTree.Right -AstTypesToObfuscate $AstTypesToObfuscate }
                    "Set-Variable -Name " + $AbstractSyntaxTree.Left.VariablePath.UserPath + " -Value " + (Out-ParenthesizedString $RightExtent)
                }
                ElseIf ($OperatorText -eq "+=") {
                    $RightExtent = $AbstractSyntaxTree.Right.Extent.Text
                    If (-not $DisableNestedObfuscation) { $RightExtent = Out-ObfuscatedAst -AbstractSyntaxTree $AbstractSyntaxTree.Right -AstTypesToObfuscate $AstTypesToObfuscate }
                    $LeftExtent = $AbstractSyntaxTree.Left.Extent.Text
                    If (-not $DisableNestedObfuscation) { $LeftExtent = Out-ObfuscatedAst -AbstractSyntaxTree $AbstractSyntaxTree.Left -AstTypesToObfuscate $AstTypesToObfuscate }
                    "Set-Variable -Name " + $AbstractSyntaxTree.Left.VariablePath.UserPath + " -Value " + (Out-ParenthesizedString ($LeftExtent + " + " + (Out-ParenthesizedString $RightExtent)))
                }
                ElseIf ($OperatorText -eq "-=") {
                    $RightExtent = $AbstractSyntaxTree.Right.Extent.Text
                    If (-not $DisableNestedObfuscation) { $RightExtent = Out-ObfuscatedAst -AbstractSyntaxTree $AbstractSyntaxTree.Right -AstTypesToObfuscate $AstTypesToObfuscate }
                    $LeftExtent = $AbstractSyntaxTree.Left.Extent.Text
                    If (-not $DisableNestedObfuscation) { $LeftExtent = Out-ObfuscatedAst -AbstractSyntaxTree $AbstractSyntaxTree.Left -AstTypesToObfuscate $AstTypesToObfuscate }
                    "Set-Variable -Name " + $AbstractSyntaxTree.Left.VariablePath.UserPath + " -Value " + (Out-ParenthesizedString ($LeftExtent + " - " + (Out-ParenthesizedString $RightExtent)))
                }
                ElseIf ($OperatorText -eq "*=") {
                    $RightExtent = $AbstractSyntaxTree.Right.Extent.Text
                    If (-not $DisableNestedObfuscation) { $RightExtent = Out-ObfuscatedAst -AbstractSyntaxTree $AbstractSyntaxTree.Right -AstTypesToObfuscate $AstTypesToObfuscate }
                    $LeftExtent = $AbstractSyntaxTree.Left.Extent.Text
                    If (-not $DisableNestedObfuscation) { $LeftExtent = Out-ObfuscatedAst -AbstractSyntaxTree $AbstractSyntaxTree.Left -AstTypesToObfuscate $AstTypesToObfuscate }
                    "Set-Variable -Name " + $AbstractSyntaxTree.Left.VariablePath.UserPath + " -Value " + (Out-ParenthesizedString ($LeftExtent + " * " + (Out-ParenthesizedString $RightExtent)))
                }
                ElseIf ($OperatorText -eq "/=") {
                    $RightExtent = $AbstractSyntaxTree.Right.Extent.Text
                    If (-not $DisableNestedObfuscation) { $RightExtent = Out-ObfuscatedAst -AbstractSyntaxTree $AbstractSyntaxTree.Right -AstTypesToObfuscate $AstTypesToObfuscate }
                    $LeftExtent = $AbstractSyntaxTree.Left.Extent.Text
                    If (-not $DisableNestedObfuscation) { $LeftExtent = Out-ObfuscatedAst -AbstractSyntaxTree $AbstractSyntaxTree.Left -AstTypesToObfuscate $AstTypesToObfuscate }
                    "Set-Variable -Name " + $AbstractSyntaxTree.Left.VariablePath.UserPath + " -Value " + (Out-ParenthesizedString ($LeftExtent + " / " + (Out-ParenthesizedString $RightExtent)))
                }
                ElseIf ($OperatorText -eq "%=") {
                    $RightExtent = $AbstractSyntaxTree.Right.Extent.Text
                    If (-not $DisableNestedObfuscation) { $RightExtent = Out-ObfuscatedAst -AbstractSyntaxTree $AbstractSyntaxTree.Right -AstTypesToObfuscate $AstTypesToObfuscate }
                    $LeftExtent = $AbstractSyntaxTree.Left.Extent.Text
                    If (-not $DisableNestedObfuscation) { $LeftExtent = Out-ObfuscatedAst -AbstractSyntaxTree $AbstractSyntaxTree.Left -AstTypesToObfuscate $AstTypesToObfuscate }
                    "Set-Variable -Name " + $AbstractSyntaxTree.Left.VariablePath.UserPath + " -Value " + (Out-ParenthesizedString ($LeftExtent + " % " + (Out-ParenthesizedString $RightExtent)))
                }
                ElseIf ($OperatorText -eq "++") {
                    $RightExtent = $AbstractSyntaxTree.Right.Extent.Text
                    If (-not $DisableNestedObfuscation) { $RightExtent = Out-ObfuscatedAst -AbstractSyntaxTree $AbstractSyntaxTree.Right -AstTypesToObfuscate $AstTypesToObfuscate }
                    $LeftExtent = $AbstractSyntaxTree.Left.Extent.Text
                    If (-not $DisableNestedObfuscation) { $LeftExtent = Out-ObfuscatedAst -AbstractSyntaxTree $AbstractSyntaxTree.Left -AstTypesToObfuscate $AstTypesToObfuscate }
                    "Set-Variable -Name " + $AbstractSyntaxTree.Left.VariablePath.UserPath + " -Value " + (Out-ParenthesizedString ($LeftExtent + " + 1"))
                }
                ElseIf ($OperatorText -eq "--") {
                    $RightExtent = $AbstractSyntaxTree.Right.Extent.Text
                    If (-not $DisableNestedObfuscation) { $RightExtent = Out-ObfuscatedAst -AbstractSyntaxTree $AbstractSyntaxTree.Right -AstTypesToObfuscate $AstTypesToObfuscate }
                    $LeftExtent = $AbstractSyntaxTree.Left.Extent.Text
                    If (-not $DisableNestedObfuscation) { $LeftExtent = Out-ObfuscatedAst -AbstractSyntaxTree $AbstractSyntaxTree.Left -AstTypesToObfuscate $AstTypesToObfuscate }
                    "Set-Variable -Name " + $AbstractSyntaxTree.Left.VariablePath.UserPath + " -Value " + (Out-ParenthesizedString ($LeftExtent + " - 1"))
                }
                ElseIf (-not $DisableNestedObfuscation) { Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
                Else { $AbstractSyntaxTree.Extent.Text }
            }
            ElseIf ($AbstractSyntaxTree.Left.GetType().Name -eq "ConvertExpressionAst" -AND $AbstractSyntaxTree.Left.Child.GetType().Name -eq "VariableExpressionAst" -AND
                    $AbstractSyntaxTree.Left.VariablePath.IsVariable -AND $AbstractSyntaxTree.Left.Attribute.GetType().Name -eq 'TypeConstraintName') {
                If ($OperatorText -eq "=") {
                    "Set-Variable -Name " + $AbstractSyntaxTree.Left.Child.VariablePath.UserPath + " -Value " + (Out-ParenthesizedString ($AbstractSyntaxTree.Left.Attribute.Extent.Text + " " + $AbstractSyntaxTree.Right.Extent.Text))
                }
                ElseIf ($OperatorText -eq "+=") {
                    "Set-Variable -Name " + $AbstractSyntaxTree.Left.Child.VariablePath.UserPath + " -Value " + (Out-ParenthesizedString ($AbstractSyntaxTree.Left.Attribute.Extent.Text + " " + $AbstractSyntaxTree.Left.Extent.Text + " + " + (Out-ParenthesizedString $AbstractSyntaxTree.Right.Extent.Text)))
                }
                ElseIf ($OperatorText -eq "-=") {
                    "Set-Variable -Name " + $AbstractSyntaxTree.Left.Child.VariablePath.UserPath + " -Value " + (Out-ParenthesizedString ($AbstractSyntaxTree.Left.Attribute.Extent.Text + " " + $AbstractSyntaxTree.Left.Extent.Text + " - " + (Out-ParenthesizedString $AbstractSyntaxTree.Right.Extent.Text)))
                }
                ElseIf ($OperatorText -eq "*=") {
                    "Set-Variable -Name " + $AbstractSyntaxTree.Left.Child.VariablePath.UserPath + " -Value " + (Out-ParenthesizedString ($AbstractSyntaxTree.Left.Attribute.Extent.Text + " " + $AbstractSyntaxTree.Left.Extent.Text + " * " + (Out-ParenthesizedString $AbstractSyntaxTree.Right.Extent.Text)))
                }
                ElseIf ($OperatorText -eq "/=") {
                    "Set-Variable -Name " + $AbstractSyntaxTree.Left.VariablePath.UserPath + " -Value " + (Out-ParenthesizedString ($AbstractSyntaxTree.Left.Attribute.Extent.Text + " " + $AbstractSyntaxTree.Left.Extent.Text + " / " + (Out-ParenthesizedString $AbstractSyntaxTree.Right.Extent.Text)))
                }
                ElseIf ($OperatorText -eq "%=") {
                    "Set-Variable -Name " + $AbstractSyntaxTree.Left.Child.VariablePath.UserPath + " -Value " + (Out-ParenthesizedString ($AbstractSyntaxTree.Left.Attribute.Extent.Text + " " + $AbstractSyntaxTree.Left.Extent.Text + " % " + (Out-ParenthesizedString $AbstractSyntaxTree.Right.Extent.Text)))
                }
                ElseIf ($OperatorText -eq "++") {
                    "Set-Variable -Name " + $AbstractSyntaxTree.Left.Child.VariablePath.UserPath + " -Value " + (Out-ParenthesizedString ($AbstractSyntaxTree.Left.Attribute.Extent.Text + " " + $AbstractSyntaxTree.Left.Extent.Text + " + 1"))
                }
                ElseIf ($OperatorText -eq "--") {
                    "Set-Variable -Name " + $AbstractSyntaxTree.Left.Child.VariablePath.UserPath + " -Value " + (Out-ParenthesizedString ($AbstractSyntaxTree.Left.Attribute.Extent.Text + " " + $AbstractSyntaxTree.Left.Extent.Text + " - 1"))
                }
                ElseIf (-not $DisableNestedObfuscation) { Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate }
                Else { $AbstractSyntaxTree.Extent.Text }
            }
            ElseIf (-not $DisableNestedObfuscation) {
                Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
            }
            Else { $AbstractSyntaxTree.Extent.Text }
        }
    }
}
function Out-ObfuscatedErrorStatementAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ErrorStatementAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedErrorStatementAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedPipelineAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.PipelineAst] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedPipelineAst]"
        If (-not $DisableNestedObfuscation) {
            Out-ObfuscatedChildrenAst -AbstractSyntaxTree $AbstractSyntaxTree -AstTypesToObfuscate $AstTypesToObfuscate
        }
        Else { $AbstractSyntaxTree.Extent.Text }
    }
}
function Out-ObfuscatedAstsReordered {
    Param (
        [Parameter(Position = 0, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast', 'AbstractSyntaxTree')]
        [System.Management.Automation.Language.Ast] $ParentAst,
        [Parameter(Position = 1, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.Language.Ast[]] $ChildrenAsts,
        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Write-Verbose "[Out-ObfuscatedAstsReordered]"
    If ($DisableNestedObfuscation) {
        $ChildrenObfuscatedExtents = ($ChildrenAsts | % { $_.Extent.Text }) -as [array]
    }
    Else {
        $ChildrenObfuscatedExtents = ($ChildrenAsts | Out-ObfuscatedAst -AstTypesToObfuscate $AstTypesToObfuscate) -as [array]
    }
    $ObfuscatedString = $ParentAst.Extent.Text
    $PrevChildrenLength = 0
    $PrevObfuscatedChildrenLength = 0
    If ($ChildrenObfuscatedExtents.Count -gt 1) {
        $ChildrenObfuscatedExtents = $ChildrenObfuscatedExtents | Get-Random -Count $ChildrenObfuscatedExtents.Count
        For ([Int] $i = 0; $i -lt $ChildrenAsts.Count; $i++) {
            $LengthDifference = $ObfuscatedString.Length - $ParentAst.Extent.Text.Length
            $BeginLength = ($ChildrenAsts[$i].Extent.StartOffset - $ParentAst.Extent.StartOffset) + $LengthDifference
            $EndStartIndex = ($ChildrenAsts[$i].Extent.StartOffset - $ParentAst.Extent.StartOffset) + $ChildrenAsts[$i].Extent.Text.Length
            $ObfuscatedString = [String] $ObfuscatedString.SubString(0, $BeginLength)
            $ObfuscatedString += [String] $ChildrenObfuscatedExtents[$i]
            $ObfuscatedString += [String] $ParentAst.Extent.Text.Substring($EndStartIndex)
        }
    }
    $ObfuscatedString
}
function Out-ParenthesizedString {
    Param(
        [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory)]
        [String] $ScriptString
    )
    Process {
        Write-Verbose "[Out-ParenthesizedString]"
        $TrimmedString = $ScriptString.Trim()
        If ($TrimmedString.StartsWith("(") -and $TrimmedString.EndsWith(")")) {
            $StackDepth = 1
            $SurroundingMatch = $True
            For([Int]$i = 1; $i -lt $TrimmedString.Length - 1; $i++) {
                $Char = $TrimmedString[$i]
                If ($Char -eq ")") {
                    If ($StackDepth -eq 1) { $SurroundingMatch = $False; break; }
                    Else { $StackDepth -= 1 }
                }
                ElseIf ($Char -eq "(") { $StackDepth += 1 }
            }
            If ($SurroundingMatch) { $ScriptString }
            Else { "(" + $ScriptString + ")" }
        } Else {
            "(" + $ScriptString + ")"
        }
    }
}
function Test-ExpressionAstIsNumeric {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.ExpressionAst] $AbstractSyntaxTree
    )
    Process {
        If ($AbstractSyntaxTree.StaticType.Name -in @('Int32', 'Int64', 'UInt32', 'UInt64', 'Decimal', 'Single', 'Double')) {
            $True
        }
        ElseIf ($AbstractSyntaxTree.Extent.Text -match "^[\d\.]+$") {
            $True
        }
        ElseIf ($AbstractSyntaxTree.Extent.Text -match "^[\d\.]+$") {
            $True
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'BinaryExpressionAst') {
            ((Test-ExpressionAstIsNumeric -Ast $AbstractSyntaxTree.Left) -AND (Test-ExpressionAstIsNumeric -Ast $AbstractSyntaxTree.Right))
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'UnaryExpressionAst' -AND [System.Management.Automation.Language.TokenTraits]::Text($AbstractSyntaxTree.TokenKind) -in @("+", "-", "*", "/", "++", "--")) {
            (Test-ExpressionAstIsNumeric -Ast $AbstractSyntaxTree.Child)
        }
        ElseIf ($AbstractSyntaxTree.GetType().Name -eq 'ParenExpressionAst' -AND $AbstractSyntaxTree.Pipeline.GetType().Name -eq 'PipelineAst') {
            $PipelineElements = ($AbstractSyntaxTree.Pipeline.PipelineElements) -as [array]
            If ($PipelineElements.Count -eq 1) {
                (Test-ExpressionAstIsNumeric -Ast $PipelineElements[0].Expression)
            } Else { $False }
        }
        Else {
            $False
        }
    }
}
function Get-AstChildren {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.Ast] $AbstractSyntaxTree
    )
    Process {
        Write-Verbose "[Get-AstChildren]"
        ForEach ($Property in $AbstractSyntaxTree.PSObject.Properties) {
            If ($Property.Name -eq 'Parent') { continue }
            $PropertyValue = $Property.Value
            If ($PropertyValue -ne $null -AND $PropertyValue -is [System.Management.Automation.Language.Ast]) {
                $PropertyValue
            }
            Else {
                $Collection = $PropertyValue -as [System.Management.Automation.Language.Ast[]]
                If ($Collection -ne $null) {
                    $Collection
                }
            }
        }
    }
}
function Out-ObfuscatedChildrenAst {
    Param (
        [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [Alias('Ast')]
        [System.Management.Automation.Language.Ast] $AbstractSyntaxTree,
        [Parameter(Position = 1)]
        [System.Management.Automation.Language.Ast[]] $ChildrenAsts = @(),
        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        [Alias('AstTypes', 'Types')]
        [System.Type[]] $AstTypesToObfuscate = @('System.Management.Automation.Language.NamedAttributeArgumentAst', 'System.Management.Automation.Language.ParamBlockAst', 'System.Management.Automation.Language.ScriptBlockAst', 'System.Management.Automation.Language.AttributeAst', 'System.Management.Automation.Language.BinaryExpressionAst', 'System.Management.Automation.Language.HashtableAst', 'System.Management.Automation.Language.CommandAst', 'System.Management.Automation.Language.AssignmentStatementAst', 'System.Management.Automation.Language.TypeExpressionAst', 'System.Management.Automation.Language.TypeConstraintAst'),
        [Switch] $DisableNestedObfuscation
    )
    Process {
        Write-Verbose "[Out-ObfuscatedChildrenAst]"
        If ($ChildrenAsts.Count -eq 0) {
            $ChildrenAsts = (Get-AstChildren -AbstractSyntaxTree $AbstractSyntaxTree | ? { $_.Extent.StartScriptPosition.GetType().Name -ne 'EmptyScriptPosition' } | Sort-Object { $_.Extent.StartOffset }) -as [array]
        }
        If ($ChildrenAsts.Count -gt 0) {
            $ChildrenObfuscatedExtents = ($ChildrenAsts | Out-ObfuscatedAst -AstTypesToObfuscate $AstTypesToObfuscate) -as [array]
        }
        $ObfuscatedExtent = $AbstractSyntaxTree.Extent.Text
        If ($ChildrenObfuscatedExtents.Count -gt 0 -AND $ChildrenAsts.Count -gt 0 -AND $ChildrenObfuscatedExtents.Count -eq $ChildrenAsts.Count) {
            For ([Int] $i = 0; $i -lt $ChildrenAsts.Length; $i++) {
                $LengthDifference = $ObfuscatedExtent.Length - $AbstractSyntaxTree.Extent.Text.Length
                $EndStartIndex = ($ChildrenAsts[$i].Extent.StartOffset - $AbstractSyntaxTree.Extent.StartOffset) + $ChildrenAsts[$i].Extent.Text.Length
                $StartLength = ($ChildrenAsts[$i].Extent.StartOffset - $AbstractSyntaxTree.Extent.StartOffset) + $LengthDifference
                $ObfuscatedExtent = [String] $ObfuscatedExtent.Substring(0, $StartLength)
                If (-not $ChildrenObfuscatedExtents[$i]) {
                    $ObfuscatedExtent += [String] $ChildrenAsts[$i].Extent.Text
                }
                Else {
                    $ObfuscatedExtent += [String] $ChildrenObfuscatedExtents[$i]
                }
                $ObfuscatedExtent += [String] $AbstractSyntaxTree.Extent.Text.Substring($EndStartIndex)
            }
        }
        $ObfuscatedExtent
    }
}
function Get-Ast {
    [CmdletBinding(DefaultParameterSetName = "ByString")] Param(
        [Parameter(ParameterSetName = "ByString", Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String] $ScriptString,
        [Parameter(ParameterSetName = "ByScriptBlock", Position = 0, ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock] $ScriptBlock,
        [Parameter(ParameterSetName = "ByPath", Position = 0, ValueFromPipelineByPropertyName, Mandatory)]
        [ValidateScript({Test-Path $_ -PathType leaf})]
        [Alias('PSPath')]
        [String] $ScriptPath,
        [Parameter(ParameterSetName = "ByUri", Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory)]
        [ValidateScript({$_.Scheme -match 'http|https'})]
        [Uri] $ScriptUri
    )
    Process {
        If ($ScriptBlock) { $ScriptString = $ScriptBlock -as [String] }
        ElseIf ($ScriptPath) { $ScriptString = Get-Content -Path $ScriptPath -Raw }
        ElseIf ($ScriptUri) { $ScriptString = [Net.Webclient]::new().DownloadString($ScriptUri) }
        [Management.Automation.Language.ParseError[]] $ParseErrors = @()
        $Ast = [Management.Automation.Language.Parser]::ParseInput($ScriptString, $null, [ref] $null, [ref] $ParseErrors)
        $Ast
    }
}
#}
#function Out-EncodedWhitespaceCommand {
function Out-EncodedWhitespaceCommand
{
    [CmdletBinding(DefaultParameterSetName = 'FilePath')] Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ParameterSetName = 'ScriptBlock')]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]
        $ScriptBlock,
        [Parameter(Position = 0, ParameterSetName = 'FilePath')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,
        [Switch]
        $NoExit,
        [Switch]
        $NoProfile,
        [Switch]
        $NonInteractive,
        [Switch]
        $NoLogo,
        [Switch]
        $Wow64,
        [Switch]
        $Command,
        [ValidateSet('Normal', 'Minimized', 'Maximized', 'Hidden')]
        [String]
        $WindowStyle,
        [ValidateSet('Bypass', 'Unrestricted', 'RemoteSigned', 'AllSigned', 'Restricted')]
        [String]
        $ExecutionPolicy,
        [Switch]
        $PassThru
    )
    If($PSBoundParameters['Path'])
    {
        Get-ChildItem $Path -ErrorAction Stop | Out-Null
        $ScriptString = [IO.File]::ReadAllText((Resolve-Path $Path))
    }
    Else
    {
        $ScriptString = [String]$ScriptBlock
    }
    $AsciiArray = [Int[]][Char[]]$ScriptString
    $RandomIndex  = Get-Random -Input @(0,1)
    $EncodedArray = @()
    $EncodingChar       = @(' ',[Char]9)[$RandomIndex]
    $DigitDelimiterChar = @([Char]9,' ')[$RandomIndex]
    ForEach($AsciiValue in $AsciiArray)
    {
        $EncodedAsciiValueArray = @()
        ForEach($Digit in [Char[]][String]$AsciiValue)
        {
            $EncodedAsciiValueArray += [String]$EncodingChar*([Int][String]$Digit + 1)
        }
        $EncodedArray += ($EncodedAsciiValueArray -Join $DigitDelimiterChar)
    }
    $IntDelimiterChar = $DigitDelimiterChar + $DigitDelimiterChar
    $EncodedString = ($EncodedArray -Join $IntDelimiterChar)
    $ForEachObject = Get-Random -Input @('ForEach','ForEach-Object','%')
    $SplitMethod   = Get-Random -Input @('-Split','-CSplit','-ISplit')
    $Trim          = Get-Random -Input @('Trim','TrimStart')
    $StrJoin       = ([Char[]]'[String]::Join'      | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $StrStr        = ([Char[]]'[String]'            | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $Join          = ([Char[]]'-Join'               | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $CharStr       = ([Char[]]'Char'                | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $Int           = ([Char[]]'Int'                 | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $Length        = ([Char[]]'Length'              | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $ForEachObject = ([Char[]]$ForEachObject        | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $SplitMethod   = ([Char[]]$SplitMethod          | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $SplitMethod2  = ([Char[]]'Split'               | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $Trim          = ([Char[]]$Trim                 | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $SplitOnDelim  = Get-Random -Input @(" $SplitMethod '$DigitDelimiterChar'",".$SplitMethod2('$DigitDelimiterChar')")
    $RandomScriptVar = (Get-Random -Input @('a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z') -Count (Get-Random -Input @(5..8)) | ForEach-Object {$UpperLowerChar = $_; If(Get-Random -Input @(0..1)) {$UpperLowerChar = $UpperLowerChar.ToUpper()} $UpperLowerChar}) -Join ''
    $ScriptStringPart1 = "'$EncodedString'" + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $ForEachObject + ' '*(Get-Random -Input @(0,1)) + '{' + ' '*(Get-Random -Input @(0,1)) + "`$$RandomScriptVar" + ' '*(Get-Random -Input @(0,1)) + '=' + ' '*(Get-Random -Input @(0,1)) + "`$_ $SplitMethod '$IntDelimiterChar'" + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $ForEachObject + ' '*(Get-Random -Input @(0,1)) + '{' + ' '*(Get-Random -Input @(0,1)) + "'$DigitDelimiterChar'" + ' '*(Get-Random -Input @(0,1)) + ';' + ' '*(Get-Random -Input @(0,1)) + "`$_$SplitOnDelim" + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $ForEachObject + ' '*(Get-Random -Input @(0,1)) + '{' + ' '*(Get-Random -Input @(0,1)) + "`$_.$Length" + ' '*(Get-Random -Input @(0,1)) + '-' + ' '*(Get-Random -Input @(0,1)) + '1' + ' '*(Get-Random -Input @(0,1)) + '}' + ' '*(Get-Random -Input @(0,1)) + '}' + ' '*(Get-Random -Input @(0,1)) + ';'
    $RandomStringSyntax = ([Char[]](Get-Random -Input @('[String]$_','$_.ToString()')) | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $RandomConversionSyntax  = @()
    $RandomConversionSyntax += "[$CharStr]" + ' '*(Get-Random -Input @(0,1)) + "[$Int]" + ' '*(Get-Random -Input @(0,1)) + "`$_"
    $RandomConversionSyntax += "[$Int]" + ' '*(Get-Random -Input @(0,1)) + "`$_" + ' '*(Get-Random -Input @(0,1)) + (Get-Random -Input @('-as','-As','-aS','-AS')) + ' '*(Get-Random -Input @(0,1)) + "[$CharStr]"
    $RandomConversionSyntax = (Get-Random -Input $RandomConversionSyntax)
    $EncodedArray = ''
    ([Char[]]$ScriptString) | ForEach-Object {$EncodedArray += ([Convert]::ToString(([Int][Char]$_),$EncodingBase) + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)))}
    $EncodedArray = ('(' + ' '*(Get-Random -Input @(0,1)) + $EncodedArray.Trim().Trim(',') + ')')
    $SetOfsVarSyntax      = @()
    $SetOfsVarSyntax     += 'Set-Item' + ' '*(Get-Random -Input @(1,2)) + "'Variable:OFS'" + ' '*(Get-Random -Input @(1,2)) + "''"
    $SetOfsVarSyntax     += (Get-Random -Input @('Set-Variable','SV','SET')) + ' '*(Get-Random -Input @(1,2)) + "'OFS'" + ' '*(Get-Random -Input @(1,2)) + "''"
    $SetOfsVar            = (Get-Random -Input $SetOfsVarSyntax)
    $SetOfsVarBackSyntax  = @()
    $SetOfsVarBackSyntax += 'Set-Item' + ' '*(Get-Random -Input @(1,2)) + "'Variable:OFS'" + ' '*(Get-Random -Input @(1,2)) + "' '"
    $SetOfsVarBackSyntax += (Get-Random -Input @('Set-Variable','SV','SET')) + ' '*(Get-Random -Input @(1,2)) + "'OFS'" + ' '*(Get-Random -Input @(1,2)) + "' '"
    $SetOfsVarBack        = (Get-Random -Input $SetOfsVarBackSyntax)
    $SetOfsVar            = ([Char[]]$SetOfsVar     | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $SetOfsVarBack        = ([Char[]]$SetOfsVarBack | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $BaseScriptArray1  = "`$$RandomScriptVar[0..(`$$RandomScriptVar.$Length-1)]"
    $NewScriptArray1   = @()
    $NewScriptArray1  += $BaseScriptArray1 + ' '*(Get-Random -Input @(0,1)) + $Join + ' '*(Get-Random -Input @(0,1)) + "''"
    $NewScriptArray1  += $Join + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $BaseScriptArray1 + ' '*(Get-Random -Input @(0,1)) + ')'
    $NewScriptArray1  += $StrJoin + '(' + ' '*(Get-Random -Input @(0,1)) + "''" + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + $BaseScriptArray1 + ' '*(Get-Random -Input @(0,1)) + ')'
    $NewScriptArray1  += '"' + ' '*(Get-Random -Input @(0,1)) + '$(' + ' '*(Get-Random -Input @(0,1)) + $SetOfsVar + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '"' + ' '*(Get-Random -Input @(0,1)) + '+' + ' '*(Get-Random -Input @(0,1)) + $StrStr + $BaseScriptArray1 + ' '*(Get-Random -Input @(0,1)) + '+' + '"' + ' '*(Get-Random -Input @(0,1)) + '$(' + ' '*(Get-Random -Input @(0,1)) + $SetOfsVarBack + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '"'
    $NewScript1 = (Get-Random -Input $NewScriptArray1)
    $BaseScriptArray2  = @()
    $BaseScriptArray2 += '(' + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $NewScript1 + ' '*(Get-Random -Input @(0,1)) + ").$Trim(" + ' '*(Get-Random -Input @(0,1)) + "'$DigitDelimiterChar '" + ' '*(Get-Random -Input @(0,1)) + ").$SplitMethod2(" + ' '*(Get-Random -Input @(0,1)) + "'" + $DigitDelimiterChar + "'" + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $ForEachObject + ' '*(Get-Random -Input @(0,1)) + '{' + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $RandomConversionSyntax + ')' +  ' '*(Get-Random -Input @(0,1)) + '}' + ' '*(Get-Random -Input @(0,1)) + ')'
    $BaseScriptArray2 += "`[$CharStr[]]" + ' '*(Get-Random -Input @(0,1)) + "[$Int[]]" + ' '*(Get-Random -Input @(0,1)) + "(" + ' '*(Get-Random -Input @(0,1)) + $NewScript1 + ' '*(Get-Random -Input @(0,1)) + ").$Trim(" + ' '*(Get-Random -Input @(0,1)) + "'$DigitDelimiterChar '" + ' '*(Get-Random -Input @(0,1)) + ").$SplitMethod2(" + ' '*(Get-Random -Input @(0,1)) + "'$DigitDelimiterChar'" + ' '*(Get-Random -Input @(0,1)) + ')'
    $BaseScriptArray2  = (Get-Random -Input $BaseScriptArray2)
    $NewScriptArray2   = @()
    $NewScriptArray2  += $BaseScriptArray2 + ' '*(Get-Random -Input @(0,1)) + $Join + ' '*(Get-Random -Input @(0,1)) + "''"
    $NewScriptArray2  += $Join + ' '*(Get-Random -Input @(0,1)) + '(' + $BaseScriptArray2 + ')'
    $NewScriptArray2  += $StrJoin + '(' + ' '*(Get-Random -Input @(0,1)) + "''" + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + $BaseScriptArray2 + ' '*(Get-Random -Input @(0,1)) + ')'
    $NewScript = (Get-Random -Input $NewScriptArray2)
    $InvokeExpressionSyntax  = @()
    $InvokeExpressionSyntax += (Get-Random -Input @('IEX','Invoke-Expression'))
    $InvocationOperator = (Get-Random -Input @('.','&')) + ' '*(Get-Random -Input @(0,1))
    $InvokeExpressionSyntax += $InvocationOperator + "( `$ShellId[1]+`$ShellId[13]+'x')"
    $InvokeExpressionSyntax += $InvocationOperator + "( `$PSHome[" + (Get-Random -Input @(4,21)) + "]+`$PSHome[" + (Get-Random -Input @(30,34)) + "]+'x')"
    $InvokeExpressionSyntax += $InvocationOperator + "( `$env:ComSpec[4," + (Get-Random -Input @(15,24,26)) + ",25]-Join'')"
    $InvokeExpressionSyntax += $InvocationOperator + "((" + (Get-Random -Input @('Get-Variable','GV','Variable')) + " '*mdr*').Name[3,11,2]-Join'')"
    $InvokeExpressionSyntax += $InvocationOperator + "( " + (Get-Random -Input @("([String]''.Insert)"         , "''.Insert.ToString()"))         + '[' + (Get-Random -Input @(3,7,14,23,33)) + ',' + (Get-Random -Input @(10,26,41)) + ",27]-Join''" + ")"
    $InvokeExpressionSyntax += $InvocationOperator + "( " + (Get-Random -Input @("([String]''.Normalize)"      , "''.Normalize.ToString()"))      + '[' + (Get-Random -Input @(3,13,23,33,55,59,77)) + ',' + (Get-Random -Input @(15,35,41,45)) + ",46]-Join''" + ")"
    $InvokeExpressionSyntax += $InvocationOperator + "( " + (Get-Random -Input @("([String]''.Chars)"          , "''.Chars.ToString()"))          + '[' + (Get-Random -Input @(11,15)) + ',' + (Get-Random -Input @(18,24)) + ",19]-Join''" + ")"
    $InvokeExpressionSyntax += $InvocationOperator + "( " + (Get-Random -Input @("([String]''.SubString)"      , "''.SubString.ToString()"))      + '[' + (Get-Random -Input @(3,13,17,26,37,47,51,60,67)) + ',' + (Get-Random -Input @(29,63,72)) + ',' + (Get-Random -Input @(30,64)) + "]-Join''" + ")"
    $InvokeExpressionSyntax += $InvocationOperator + "( " + (Get-Random -Input @("([String]''.Remove)"         , "''.Remove.ToString()"))         + '[' + (Get-Random -Input @(3,14,23,30,45,56,65)) + ',' + (Get-Random -Input @(8,12,26,50,54,68)) + ',' + (Get-Random -Input @(27,69)) + "]-Join''" + ")"
    $InvokeExpressionSyntax += $InvocationOperator + "( " + (Get-Random -Input @("([String]''.LastIndexOfAny)" , "''.LastIndexOfAny.ToString()")) + '[' + (Get-Random -Input @(0,8,34,42,67,76,84,92,117,126,133)) + ',' + (Get-Random -Input @(11,45,79,95,129)) + ',' + (Get-Random -Input @(12,46,80,96,130)) + "]-Join''" + ")"
    $InvokeExpressionSyntax += $InvocationOperator + "( " + (Get-Random -Input @("([String]''.LastIndexOf)"    , "''.LastIndexOf.ToString()"))    + '[' + (Get-Random -Input @(0,8,29,37,57,66,74,82,102,111,118,130,138,149,161,169,180,191,200,208,216,227,238,247,254,266,274,285,306,315,326,337,345,356,367,376,393,402,413,424,432,443,454,463,470,491,500,511)) + ',' + (Get-Random -Input @(11,25,40,54,69,85,99,114,141,157,172,188,203,219,235,250,277,293,300,333,348,364,379,387,420,435,451,466,485,518)) + ',' + (Get-Random -Input @(12,41,70,86,115,142,173,204,220,251,278,349,380,436,467)) + "]-Join''" + ")"
    $InvokeExpressionSyntax += $InvocationOperator + "( " + (Get-Random -Input @("([String]''.IsNormalized)"   , "''.IsNormalized.ToString()"))   + '[' + (Get-Random -Input @(5,13,26,34,57,61,75,79)) + ',' + (Get-Random -Input @(15,36,43,47)) + ",48]-Join''" + ")"
    $InvokeExpressionSyntax += $InvocationOperator + "( " + (Get-Random -Input @("([String]''.IndexOfAny)"     , "''.IndexOfAny.ToString()"))     + '[' + (Get-Random -Input @(0,4,30,34,59,68,76,80,105,114,121)) + ',' + (Get-Random -Input @(7,37,71,83,117)) + ',' + (Get-Random -Input @(8,38,72,84,118)) + "]-Join''" + ")"
    $InvokeExpressionSyntax += $InvocationOperator + "( " + (Get-Random -Input @("([String]''.IndexOf)"        , "''.IndexOf.ToString()"))        + '[' + (Get-Random -Input @(0,4,25,29,49,58,66,70,90,99,106,118,122,133,145,149,160,171,180,188,192,203,214,223,230,242,246,257,278,287,298,309,313,324,335,344,361,370,381,392,396,407,418,427,434,455,464,475)) + ',' + (Get-Random -Input @(7,21,32,46,61,73,87,102,125,141,152,168,183,195,211,226,249,265,272,305,316,332,347,355,388,399,415,430,449,482)) + ',' + (Get-Random -Input @(8,33,62,74,103,126,153,184,196,227,250,317,348,400,431)) + "]-Join''" + ")"
    $InvokeExpression = (Get-Random -Input $InvokeExpressionSyntax)
    $InvokeExpression = ([Char[]]$InvokeExpression | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $InvokeOptions  = @()
    $InvokeOptions += ' '*(Get-Random -Input @(0,1)) + $InvokeExpression + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $NewScript + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1))
    $InvokeOptions += ' '*(Get-Random -Input @(0,1)) + $NewScript + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $InvokeExpression
    $NewScript = (Get-Random -Input $InvokeOptions)
    $NewScript = $ScriptStringPart1 + $NewScript + '}'
    If(!$PSBoundParameters['PassThru'])
    {
        $PowerShellFlags = @()
        $CommandlineOptions = New-Object String[](0)
        If($PSBoundParameters['NoExit'])
        {
          $FullArgument = "-NoExit";
          $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 4 -Maximum ($FullArgument.Length+1)))
        }
        If($PSBoundParameters['NoProfile'])
        {
          $FullArgument = "-NoProfile";
          $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 4 -Maximum ($FullArgument.Length+1)))
        }
        If($PSBoundParameters['NonInteractive'])
        {
          $FullArgument = "-NonInteractive";
          $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 5 -Maximum ($FullArgument.Length+1)))
        }
        If($PSBoundParameters['NoLogo'])
        {
          $FullArgument = "-NoLogo";
          $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 4 -Maximum ($FullArgument.Length+1)))
        }
        If($PSBoundParameters['WindowStyle'] -OR $WindowsStyle)
        {
            $FullArgument = "-WindowStyle"
            If($WindowsStyle) {$ArgumentValue = $WindowsStyle}
            Else {$ArgumentValue = $PSBoundParameters['WindowStyle']}
            Switch($ArgumentValue.ToLower())
            {
                'normal'    {If(Get-Random -Input @(0..1)) {$ArgumentValue = (Get-Random -Input @('0','n','no','nor','norm','norma'))}}
                'hidden'    {If(Get-Random -Input @(0..1)) {$ArgumentValue = (Get-Random -Input @('1','h','hi','hid','hidd','hidde'))}}
                'minimized' {If(Get-Random -Input @(0..1)) {$ArgumentValue = (Get-Random -Input @('2','mi','min','mini','minim','minimi','minimiz','minimize'))}}
                'maximized' {If(Get-Random -Input @(0..1)) {$ArgumentValue = (Get-Random -Input @('3','ma','max','maxi','maxim','maximi','maximiz','maximize'))}}
                default {Write-Error "An invalid `$ArgumentValue value ($ArgumentValue) was passed to switch block for Out-PowerShellLauncher."; Exit;}
            }
            $PowerShellFlags += $FullArgument.SubString(0,(Get-Random -Minimum 2 -Maximum ($FullArgument.Length+1))) + ' '*(Get-Random -Minimum 1 -Maximum 3) + $ArgumentValue
        }
        If($PSBoundParameters['ExecutionPolicy'] -OR $ExecutionPolicy)
        {
            $FullArgument = "-ExecutionPolicy"
            If($ExecutionPolicy) {$ArgumentValue = $ExecutionPolicy}
            Else {$ArgumentValue = $PSBoundParameters['ExecutionPolicy']}
            $ExecutionPolicyFlags = @()
            $ExecutionPolicyFlags += '-EP'
            For($Index=3; $Index -le $FullArgument.Length; $Index++)
            {
                $ExecutionPolicyFlags += $FullArgument.SubString(0,$Index)
            }
            $ExecutionPolicyFlag = Get-Random -Input $ExecutionPolicyFlags
            $PowerShellFlags += $ExecutionPolicyFlag + ' '*(Get-Random -Minimum 1 -Maximum 3) + $ArgumentValue
        }
        If($CommandlineOptions.Count -gt 1)
        {
            $CommandlineOptions = Get-Random -InputObject $CommandlineOptions -Count $CommandlineOptions.Count
        }
        If($PSBoundParameters['Command'])
        {
            $FullArgument = "-Command"
            $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 2 -Maximum ($FullArgument.Length+1)))
        }
        For($i=0; $i -lt $PowerShellFlags.Count; $i++)
        {
            $PowerShellFlags[$i] = ([Char[]]$PowerShellFlags[$i] | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
        }
        $CommandlineOptions = ($CommandlineOptions | ForEach-Object {$_ + " "*(Get-Random -Minimum 1 -Maximum 3)}) -Join ''
        $CommandlineOptions = " "*(Get-Random -Minimum 0 -Maximum 3) + $CommandlineOptions + " "*(Get-Random -Minimum 0 -Maximum 3)
        If($PSBoundParameters['Wow64'])
        {
            $CommandLineOutput = "C:\WINDOWS\SysWOW64\WindowsPowerShell\v1.0\powershell.exe $($CommandlineOptions) `"$NewScript`""
        }
        Else
        {
            $CommandLineOutput = "powershell $($CommandlineOptions) `"$NewScript`""
        }
        $CmdMaxLength = 8190
        If($CommandLineOutput.Length -gt $CmdMaxLength)
        {
                Write-Warning "This command exceeds the cmd.exe maximum allowed length of $CmdMaxLength characters! Its length is $($CmdLineOutput.Length) characters."
        }
        $NewScript = $CommandLineOutput
    }
    Return $NewScript
}
#}
#function Out-EncodedSpecialCharOnlyCommand {
function Out-EncodedSpecialCharOnlyCommand
{
    [CmdletBinding(DefaultParameterSetName = 'FilePath')] Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ParameterSetName = 'ScriptBlock')]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]
        $ScriptBlock,
        [Parameter(Position = 0, ParameterSetName = 'FilePath')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,
        [Switch]
        $NoExit,
        [Switch]
        $NoProfile,
        [Switch]
        $NonInteractive,
        [Switch]
        $NoLogo,
        [Switch]
        $Wow64,
        [Switch]
        $Command,
        [ValidateSet('Normal', 'Minimized', 'Maximized', 'Hidden')]
        [String]
        $WindowStyle,
        [ValidateSet('Bypass', 'Unrestricted', 'RemoteSigned', 'AllSigned', 'Restricted')]
        [String]
        $ExecutionPolicy,
        [Switch]
        $PassThru
    )
    If($PSBoundParameters['Path'])
    {
        Get-ChildItem $Path -ErrorAction Stop | Out-Null
        $ScriptString = [IO.File]::ReadAllText((Resolve-Path $Path))
    }
    Else
    {
        $ScriptString = [String]$ScriptBlock
    }
    $VariableInstantiationSyntax  = @()
    $VariableInstantiationSyntax += '${;} = + $( ) ; ${=} = ${;} ; ${+} = ++ ${;} ; ${@} = ++ ${;} ; ${.} = ++ ${;} ; ${[} = ++ ${;} ; ${]} = ++ ${;} ; ${(} = ++ ${;} ; ${)} = ++ ${;} ; ${&} = ++ ${;} ; ${|} = ++ ${;} ; '
    $VariableInstantiationSyntax += '${;} = + $( ) ; ${=} = ${;} ; ${+} = ++ ${;} ; ${@} = ( ${;} = ${;} + ${+} ) ; ${.} = ( ${;} = ${;} + ${+} ) ; ${[} = ( ${;} = ${;} + ${+} ) ; ${]} = ( ${;} = ${;} + ${+} ) ; ${(} = ( ${;} = ${;} + ${+} ) ; ${)} = ( ${;} = ${;} + ${+} ) ; ${&} = ( ${;} = ${;} + ${+} ) ; ${|} = ( ${;} = ${;} + ${+} ) ; '
    $VariableInstantiation = (Get-Random -Input $VariableInstantiationSyntax)
    ${[Char]}              = '${"} = \"[\" + \"$( @{ } ) \"[ ${)} ] + \"$(@{ })\"[ \"${+}${|}\" ] + \"$( @{ } ) \"[ \"${@}${=}\" ] + \"$? \"[ ${+} ] + \"]\" ; '
    $OverloadDefinitions   = '${;} = \"\".(\"$( @{ } ) \"[ \"${+}${[}\" ] + \"$( @{ } ) \"[ \"${+}${(}\" ] + \"$( @{ } ) \"[ ${=} ] + \"$( @{ } ) \"[ ${[} ] + \"$? \"[ ${+} ] + \"$( @{ } ) \"[ ${.} ] ) ; '
    $Iex                   = '${;} = \"$( @{ } ) \"[ \"${+}${[}\" ] + \"$( @{ } ) \"[ ${[} ] + \"${;}\"[ \"${@}${)}\" ] ; '
    If((Get-Random -Input @(0..1)))
    {
        ${[Char]} = ${[Char]}.Replace('}${','}\" + \"${')
    }
    If((Get-Random -Input @(0..1)))
    {
        $OverloadDefinitions = $OverloadDefinitions.Replace('}${','}\" + \"${')
    }
    If((Get-Random -Input @(0..1)))
    {
        $Iex = $Iex.Replace('}${','}\" + \"${')
    }
    $SetupCommand = $VariableInstantiation + ${[Char]} + $OverloadDefinitions + $Iex
    If((Get-Random -Input @(0..1)))
    {
        $NewCharacters = @(';','=','+','@','.','[',']','(',')','-','_','/','\','*','%','$','#','!','``','~')
        Switch(Get-Random -Input @(1..3))
        {
            1 {$RandomChar = (Get-Random -Input $NewCharacters); $RandomString = $RandomChar*(Get-Random -Input @(1..6))}
            default {$RandomString = (Get-Random -Input $NewCharacters -Count (Get-Random -Input @(1..3)))}
        }
        $SetupCommand = '( ' + "'$RandomString'" + ' | % { ' + $SetupCommand.Replace(' ; ',' } { ').Trim(' {') + ' ) ; '
    }
    $CharEncoded = ([Char[]]$ScriptString | ForEach-Object {'${"}'+ ([Int]$_  -Replace "0",'${=}' -Replace "1",'${+}' -Replace "2",'${@}' -Replace "3",'${.}' -Replace "4",'${[}' -Replace "5",'${]}' -Replace "6",'${(}' -Replace "7",'${)}' -Replace "8",'${&}' -Replace "9",'${|}')}) -Join ' + '
    $InvocationSyntax = (Get-Random -Input @('.','&'))
    $CharEncodedSyntax  = @()
    $CharEncodedSyntax += '\" ' + $CharEncoded + ' ^| ${;} \" | ' + $InvocationSyntax + ' ${;} '
    $CharEncodedSyntax += '\" ${;} ( ' + $CharEncoded + ' ) \" | ' + $InvocationSyntax + ' ${;} '
    $CharEncodedSyntax += $InvocationSyntax + ' ${;} ( \" ' + $CharEncoded + ' ^| ${;} \" ) '
    $CharEncodedSyntax += $InvocationSyntax + ' ${;} ( \" ${;} ( ' + $CharEncoded + ' ) \" ) '
    $CharEncodedRandom  = (Get-Random -Input $CharEncodedSyntax)
    $NewScriptTemp = $SetupCommand + $CharEncodedRandom
    $NewScript = ''
    $NewScriptTemp.Split(' ') | ForEach-Object {
        $NewScript += $_ + ' '*(Get-Random -Input @(0,2))
    }
    $DefaultCharacters = @(';','=','+','@','.','[',']','(',')','&','|','"')
    $NewCharacters     = @(';','=','+','@','.','[',']','(',')','-','/',"'",'*','%','$','#','!','``','~',' ')
    $UpperLimit = 1
    Switch(Get-Random -Input @(1..6))
    {
        1 {$RandomChar = (Get-Random -Input $NewCharacters); $NewCharacters = @(1..12) | ForEach-Object {$RandomChar*$_}}
        2 {$NewCharacters = @(1..12) | ForEach-Object {' '*$_}}
        default {$UpperLimit = 3}
    }
    $NewVariableList  = @()
    While($NewVariableList.Count -lt $DefaultCharacters.Count)
    {
        $CurrentVariable = (Get-Random -Input $NewCharacters -Count (Get-Random -Input @(1..$UpperLimit))) -Join ''
        While($NewVariableList -Contains $CurrentVariable)
        {
            $CurrentVariable = (Get-Random -Input $NewCharacters -Count (Get-Random -Input @(1..$UpperLimit))) -Join ''
        }
        $NewVariableList += $CurrentVariable
    }
    $NewCharactersRandomOrder = Get-Random -Input $NewCharacters -Count $DefaultCharacters.Count
    For($i=0; $i -lt $DefaultCharacters.Count; $i++)
    {
        $NewScript = $NewScript.Replace(('${' + $DefaultCharacters[$i] + '}'),('${' + $i + '}'))
    }
    For($i=$DefaultCharacters.Count-1; $i -ge 0; $i--)
    {
        $NewScript = $NewScript.Replace(('${' + $i + '}'),('${' + $NewVariableList[$i]+'}'))
    }
    If($PSBoundParameters['PassThru'])
    {
        If($NewScript.Contains('\"'))
        {
            $NewScript = $NewScript.Replace('\"','"')
        }
        If($NewScript.Contains('^|'))
        {
            $NewScript = $NewScript.Replace('^|','|')
        }
    }
    If(!$PSBoundParameters['PassThru'])
    {
        $PowerShellFlags = @()
        $CommandlineOptions = New-Object String[](0)
        If($PSBoundParameters['NoExit'])
        {
          $FullArgument = "-NoExit";
          $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 4 -Maximum ($FullArgument.Length+1)))
        }
        If($PSBoundParameters['NoProfile'])
        {
          $FullArgument = "-NoProfile";
          $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 4 -Maximum ($FullArgument.Length+1)))
        }
        If($PSBoundParameters['NonInteractive'])
        {
          $FullArgument = "-NonInteractive";
          $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 5 -Maximum ($FullArgument.Length+1)))
        }
        If($PSBoundParameters['NoLogo'])
        {
          $FullArgument = "-NoLogo";
          $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 4 -Maximum ($FullArgument.Length+1)))
        }
        If($PSBoundParameters['WindowStyle'] -OR $WindowsStyle)
        {
            $FullArgument = "-WindowStyle"
            If($WindowsStyle) {$ArgumentValue = $WindowsStyle}
            Else {$ArgumentValue = $PSBoundParameters['WindowStyle']}
            Switch($ArgumentValue.ToLower())
            {
                'normal'    {If(Get-Random -Input @(0..1)) {$ArgumentValue = (Get-Random -Input @('0','n','no','nor','norm','norma'))}}
                'hidden'    {If(Get-Random -Input @(0..1)) {$ArgumentValue = (Get-Random -Input @('1','h','hi','hid','hidd','hidde'))}}
                'minimized' {If(Get-Random -Input @(0..1)) {$ArgumentValue = (Get-Random -Input @('2','mi','min','mini','minim','minimi','minimiz','minimize'))}}
                'maximized' {If(Get-Random -Input @(0..1)) {$ArgumentValue = (Get-Random -Input @('3','ma','max','maxi','maxim','maximi','maximiz','maximize'))}}
                default {Write-Error "An invalid `$ArgumentValue value ($ArgumentValue) was passed to switch block for Out-PowerShellLauncher."; Exit;}
            }
            $PowerShellFlags += $FullArgument.SubString(0,(Get-Random -Minimum 2 -Maximum ($FullArgument.Length+1))) + ' '*(Get-Random -Minimum 1 -Maximum 3) + $ArgumentValue
        }
        If($PSBoundParameters['ExecutionPolicy'] -OR $ExecutionPolicy)
        {
            $FullArgument = "-ExecutionPolicy"
            If($ExecutionPolicy) {$ArgumentValue = $ExecutionPolicy}
            Else {$ArgumentValue = $PSBoundParameters['ExecutionPolicy']}
            $ExecutionPolicyFlags = @()
            $ExecutionPolicyFlags += '-EP'
            For($Index=3; $Index -le $FullArgument.Length; $Index++)
            {
                $ExecutionPolicyFlags += $FullArgument.SubString(0,$Index)
            }
            $ExecutionPolicyFlag = Get-Random -Input $ExecutionPolicyFlags
            $PowerShellFlags += $ExecutionPolicyFlag + ' '*(Get-Random -Minimum 1 -Maximum 3) + $ArgumentValue
        }
        If($CommandlineOptions.Count -gt 1)
        {
            $CommandlineOptions = Get-Random -InputObject $CommandlineOptions -Count $CommandlineOptions.Count
        }
        If($PSBoundParameters['Command'])
        {
            $FullArgument = "-Command"
            $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 2 -Maximum ($FullArgument.Length+1)))
        }
        For($i=0; $i -lt $PowerShellFlags.Count; $i++)
        {
            $PowerShellFlags[$i] = ([Char[]]$PowerShellFlags[$i] | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
        }
        $CommandlineOptions = ($CommandlineOptions | ForEach-Object {$_ + " "*(Get-Random -Minimum 1 -Maximum 3)}) -Join ''
        $CommandlineOptions = " "*(Get-Random -Minimum 0 -Maximum 3) + $CommandlineOptions + " "*(Get-Random -Minimum 0 -Maximum 3)
        If($PSBoundParameters['Wow64'])
        {
            $CommandLineOutput = "C:\WINDOWS\SysWOW64\WindowsPowerShell\v1.0\powershell.exe $($CommandlineOptions) `"$NewScript`""
        }
        Else
        {
            $CommandLineOutput = "powershell $($CommandlineOptions) `"$NewScript`""
        }
        $CmdMaxLength = 8190
        If($CommandLineOutput.Length -gt $CmdMaxLength)
        {
                Write-Warning "This command exceeds the cmd.exe maximum allowed length of $CmdMaxLength characters! Its length is $($CmdLineOutput.Length) characters."
        }
        $NewScript = $CommandLineOutput
    }
    Return $NewScript
}
#}
#function Out-EncodedOctalCommand {
function Out-EncodedOctalCommand
{
    [CmdletBinding(DefaultParameterSetName = 'FilePath')] Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ParameterSetName = 'ScriptBlock')]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]
        $ScriptBlock,
        [Parameter(Position = 0, ParameterSetName = 'FilePath')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,
        [Switch]
        $NoExit,
        [Switch]
        $NoProfile,
        [Switch]
        $NonInteractive,
        [Switch]
        $NoLogo,
        [Switch]
        $Wow64,
        [Switch]
        $Command,
        [ValidateSet('Normal', 'Minimized', 'Maximized', 'Hidden')]
        [String]
        $WindowStyle,
        [ValidateSet('Bypass', 'Unrestricted', 'RemoteSigned', 'AllSigned', 'Restricted')]
        [String]
        $ExecutionPolicy,
        [Switch]
        $PassThru
    )
    $EncodingBase = 8
    If($PSBoundParameters['Path'])
    {
        Get-ChildItem $Path -ErrorAction Stop | Out-Null
        $ScriptString = [IO.File]::ReadAllText((Resolve-Path $Path))
    }
    Else
    {
        $ScriptString = [String]$ScriptBlock
    }
    $RandomDelimiters  = @('_','-',',','{','}','~','!','@','%','&','<','>',';',':')
    @('a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z') | ForEach-Object {$UpperLowerChar = $_; If(((Get-Random -Input @(1..2))-1 -eq 0)) {$UpperLowerChar = $UpperLowerChar.ToUpper()} $RandomDelimiters += $UpperLowerChar}
    $RandomDelimiters = (Get-Random -Input $RandomDelimiters -Count ($RandomDelimiters.Count/4))
    $DelimitedEncodedArray = ''
    ([Char[]]$ScriptString) | ForEach-Object {$DelimitedEncodedArray += ([Convert]::ToString(([Int][Char]$_),$EncodingBase) + (Get-Random -Input $RandomDelimiters))}
    $DelimitedEncodedArray = $DelimitedEncodedArray.SubString(0,$DelimitedEncodedArray.Length-1)
    $RandomDelimitersToPrint = (Get-Random -Input $RandomDelimiters -Count $RandomDelimiters.Length) -Join ''
    $ForEachObject = Get-Random -Input @('ForEach','ForEach-Object','%')
    $StrJoin       = ([Char[]]'[String]::Join'      | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $StrStr        = ([Char[]]'[String]'            | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $Join          = ([Char[]]'-Join'               | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $CharStr       = ([Char[]]'Char'                | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $Int           = ([Char[]]'Int'                 | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $ForEachObject = ([Char[]]$ForEachObject        | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $ToInt16       = ([Char[]]'[Convert]::ToInt16(' | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $RandomDelimitersToPrintForDashSplit = ''
    ForEach($RandomDelimiter in $RandomDelimiters)
    {
        $Split = ([Char[]]'Split' | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
        $RandomDelimitersToPrintForDashSplit += ('-' + $Split + ' '*(Get-Random -Input @(0,1)) + "'" + $RandomDelimiter + "'" + ' '*(Get-Random -Input @(0,1)))
    }
    $RandomDelimitersToPrintForDashSplit = $RandomDelimitersToPrintForDashSplit.Trim()
    $RandomStringSyntax = ([Char[]](Get-Random -Input @('[String]$_','$_.ToString()')) | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $RandomConversionSyntax  = @()
    $RandomConversionSyntax += "[$CharStr]" + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $ToInt16 + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $RandomStringSyntax + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + ',' + $EncodingBase + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + ')'
    $RandomConversionSyntax += $ToInt16 + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $RandomStringSyntax + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + $EncodingBase + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + (Get-Random -Input @('-as','-As','-aS','-AS')) + ' '*(Get-Random -Input @(0,1)) + "[$CharStr]"
    $RandomConversionSyntax = (Get-Random -Input $RandomConversionSyntax)
    $EncodedArray = ''
    ([Char[]]$ScriptString) | ForEach-Object {$EncodedArray += ([Convert]::ToString(([Int][Char]$_),$EncodingBase) + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)))}
    $EncodedArray = ('(' + ' '*(Get-Random -Input @(0,1)) + $EncodedArray.Trim().Trim(',') + ')')
    $SetOfsVarSyntax      = @()
    $SetOfsVarSyntax     += 'Set-Item' + ' '*(Get-Random -Input @(1,2)) + "'Variable:OFS'" + ' '*(Get-Random -Input @(1,2)) + "''"
    $SetOfsVarSyntax     += (Get-Random -Input @('Set-Variable','SV','SET')) + ' '*(Get-Random -Input @(1,2)) + "'OFS'" + ' '*(Get-Random -Input @(1,2)) + "''"
    $SetOfsVar            = (Get-Random -Input $SetOfsVarSyntax)
    $SetOfsVarBackSyntax  = @()
    $SetOfsVarBackSyntax += 'Set-Item' + ' '*(Get-Random -Input @(1,2)) + "'Variable:OFS'" + ' '*(Get-Random -Input @(1,2)) + "' '"
    $SetOfsVarBackSyntax += (Get-Random -Input @('Set-Variable','SV','SET')) + ' '*(Get-Random -Input @(1,2)) + "'OFS'" + ' '*(Get-Random -Input @(1,2)) + "' '"
    $SetOfsVarBack        = (Get-Random -Input $SetOfsVarBackSyntax)
    $SetOfsVar            = ([Char[]]$SetOfsVar     | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $SetOfsVarBack        = ([Char[]]$SetOfsVarBack | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $BaseScriptArray  = @()
    $BaseScriptArray += '(' + ' '*(Get-Random -Input @(0,1)) + "'" + $DelimitedEncodedArray + "'." + $Split + "(" + ' '*(Get-Random -Input @(0,1)) + "'" + $RandomDelimitersToPrint + "'" + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $ForEachObject + ' '*(Get-Random -Input @(0,1)) + '{' + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $RandomConversionSyntax + ')' +  ' '*(Get-Random -Input @(0,1)) + '}' + ' '*(Get-Random -Input @(0,1)) + ')'
    $BaseScriptArray += '(' + ' '*(Get-Random -Input @(0,1)) + "'" + $DelimitedEncodedArray + "'" + ' '*(Get-Random -Input @(0,1)) + $RandomDelimitersToPrintForDashSplit + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $ForEachObject + ' '*(Get-Random -Input @(0,1)) + '{' + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $RandomConversionSyntax + ')' +  ' '*(Get-Random -Input @(0,1)) + '}' + ' '*(Get-Random -Input @(0,1)) + ')'
    $BaseScriptArray += '(' + ' '*(Get-Random -Input @(0,1)) + $EncodedArray + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $ForEachObject + ' '*(Get-Random -Input @(0,1)) + '{' + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $RandomConversionSyntax + ')' +  ' '*(Get-Random -Input @(0,1)) + '}' + ' '*(Get-Random -Input @(0,1)) + ')'
    $NewScriptArray   = @()
    $NewScriptArray  += (Get-Random -Input $BaseScriptArray) + ' '*(Get-Random -Input @(0,1)) + $Join + ' '*(Get-Random -Input @(0,1)) + "''"
    $NewScriptArray  += $Join + ' '*(Get-Random -Input @(0,1)) + (Get-Random -Input $BaseScriptArray)
    $NewScriptArray  += $StrJoin + '(' + ' '*(Get-Random -Input @(0,1)) + "''" + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + (Get-Random -Input $BaseScriptArray) + ' '*(Get-Random -Input @(0,1)) + ')'
    $NewScriptArray  += '"' + ' '*(Get-Random -Input @(0,1)) + '$(' + ' '*(Get-Random -Input @(0,1)) + $SetOfsVar + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '"' + ' '*(Get-Random -Input @(0,1)) + '+' + ' '*(Get-Random -Input @(0,1)) + $StrStr + (Get-Random -Input $BaseScriptArray) + ' '*(Get-Random -Input @(0,1)) + '+' + '"' + ' '*(Get-Random -Input @(0,1)) + '$(' + ' '*(Get-Random -Input @(0,1)) + $SetOfsVarBack + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '"'
    $NewScript = (Get-Random -Input $NewScriptArray)
    $InvokeExpressionSyntax  = @()
    $InvokeExpressionSyntax += (Get-Random -Input @('IEX','Invoke-Expression'))
    $InvocationOperator = (Get-Random -Input @('.','&')) + ' '*(Get-Random -Input @(0,1))
    $InvokeExpressionSyntax += $InvocationOperator + "( `$ShellId[1]+`$ShellId[13]+'x')"
    $InvokeExpressionSyntax += $InvocationOperator + "( `$PSHome[" + (Get-Random -Input @(4,21)) + "]+`$PSHome[" + (Get-Random -Input @(30,34)) + "]+'x')"
    $InvokeExpressionSyntax += $InvocationOperator + "( `$env:ComSpec[4," + (Get-Random -Input @(15,24,26)) + ",25]-Join'')"
    $InvokeExpressionSyntax += $InvocationOperator + "((" + (Get-Random -Input @('Get-Variable','GV','Variable')) + " '*mdr*').Name[3,11,2]-Join'')"
    $InvokeExpressionSyntax += $InvocationOperator + "( " + (Get-Random -Input @('$VerbosePreference.ToString()','([String]$VerbosePreference)')) + "[1,3]+'x'-Join'')"
    $InvokeExpression = (Get-Random -Input $InvokeExpressionSyntax)
    $InvokeExpression = ([Char[]]$InvokeExpression | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $InvokeOptions  = @()
    $InvokeOptions += ' '*(Get-Random -Input @(0,1)) + $InvokeExpression + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $NewScript + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1))
    $InvokeOptions += ' '*(Get-Random -Input @(0,1)) + $NewScript + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $InvokeExpression
    $NewScript = (Get-Random -Input $InvokeOptions)
    If(!$PSBoundParameters['PassThru'])
    {
        $PowerShellFlags = @()
        $CommandlineOptions = New-Object String[](0)
        If($PSBoundParameters['NoExit'])
        {
          $FullArgument = "-NoExit";
          $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 4 -Maximum ($FullArgument.Length+1)))
        }
        If($PSBoundParameters['NoProfile'])
        {
          $FullArgument = "-NoProfile";
          $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 4 -Maximum ($FullArgument.Length+1)))
        }
        If($PSBoundParameters['NonInteractive'])
        {
          $FullArgument = "-NonInteractive";
          $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 5 -Maximum ($FullArgument.Length+1)))
        }
        If($PSBoundParameters['NoLogo'])
        {
          $FullArgument = "-NoLogo";
          $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 4 -Maximum ($FullArgument.Length+1)))
        }
        If($PSBoundParameters['WindowStyle'] -OR $WindowsStyle)
        {
            $FullArgument = "-WindowStyle"
            If($WindowsStyle) {$ArgumentValue = $WindowsStyle}
            Else {$ArgumentValue = $PSBoundParameters['WindowStyle']}
            Switch($ArgumentValue.ToLower())
            {
                'normal'    {If(Get-Random -Input @(0..1)) {$ArgumentValue = (Get-Random -Input @('0','n','no','nor','norm','norma'))}}
                'hidden'    {If(Get-Random -Input @(0..1)) {$ArgumentValue = (Get-Random -Input @('1','h','hi','hid','hidd','hidde'))}}
                'minimized' {If(Get-Random -Input @(0..1)) {$ArgumentValue = (Get-Random -Input @('2','mi','min','mini','minim','minimi','minimiz','minimize'))}}
                'maximized' {If(Get-Random -Input @(0..1)) {$ArgumentValue = (Get-Random -Input @('3','ma','max','maxi','maxim','maximi','maximiz','maximize'))}}
                default {Write-Error "An invalid `$ArgumentValue value ($ArgumentValue) was passed to switch block for Out-PowerShellLauncher."; Exit;}
            }
            $PowerShellFlags += $FullArgument.SubString(0,(Get-Random -Minimum 2 -Maximum ($FullArgument.Length+1))) + ' '*(Get-Random -Minimum 1 -Maximum 3) + $ArgumentValue
        }
        If($PSBoundParameters['ExecutionPolicy'] -OR $ExecutionPolicy)
        {
            $FullArgument = "-ExecutionPolicy"
            If($ExecutionPolicy) {$ArgumentValue = $ExecutionPolicy}
            Else {$ArgumentValue = $PSBoundParameters['ExecutionPolicy']}
            $ExecutionPolicyFlags = @()
            $ExecutionPolicyFlags += '-EP'
            For($Index=3; $Index -le $FullArgument.Length; $Index++)
            {
                $ExecutionPolicyFlags += $FullArgument.SubString(0,$Index)
            }
            $ExecutionPolicyFlag = Get-Random -Input $ExecutionPolicyFlags
            $PowerShellFlags += $ExecutionPolicyFlag + ' '*(Get-Random -Minimum 1 -Maximum 3) + $ArgumentValue
        }
        If($CommandlineOptions.Count -gt 1)
        {
            $CommandlineOptions = Get-Random -InputObject $CommandlineOptions -Count $CommandlineOptions.Count
        }
        If($PSBoundParameters['Command'])
        {
            $FullArgument = "-Command"
            $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 2 -Maximum ($FullArgument.Length+1)))
        }
        For($i=0; $i -lt $PowerShellFlags.Count; $i++)
        {
            $PowerShellFlags[$i] = ([Char[]]$PowerShellFlags[$i] | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
        }
        $CommandlineOptions = ($CommandlineOptions | ForEach-Object {$_ + " "*(Get-Random -Minimum 1 -Maximum 3)}) -Join ''
        $CommandlineOptions = " "*(Get-Random -Minimum 0 -Maximum 3) + $CommandlineOptions + " "*(Get-Random -Minimum 0 -Maximum 3)
        If($PSBoundParameters['Wow64'])
        {
            $CommandLineOutput = "C:\WINDOWS\SysWOW64\WindowsPowerShell\v1.0\powershell.exe $($CommandlineOptions) `"$NewScript`""
        }
        Else
        {
            $CommandLineOutput = "powershell $($CommandlineOptions) `"$NewScript`""
        }
        $CmdMaxLength = 8190
        If($CommandLineOutput.Length -gt $CmdMaxLength)
        {
                Write-Warning "This command exceeds the cmd.exe maximum allowed length of $CmdMaxLength characters! Its length is $($CmdLineOutput.Length) characters."
        }
        $NewScript = $CommandLineOutput
    }
    Return $NewScript
}
#}
#function Out-EncodedBXORCommand {
function Out-EncodedBXORCommand
{
    [CmdletBinding(DefaultParameterSetName = 'FilePath')] Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ParameterSetName = 'ScriptBlock')]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]
        $ScriptBlock,
        [Parameter(Position = 0, ParameterSetName = 'FilePath')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,
        [Switch]
        $NoExit,
        [Switch]
        $NoProfile,
        [Switch]
        $NonInteractive,
        [Switch]
        $NoLogo,
        [Switch]
        $Wow64,
        [Switch]
        $Command,
        [ValidateSet('Normal', 'Minimized', 'Maximized', 'Hidden')]
        [String]
        $WindowStyle,
        [ValidateSet('Bypass', 'Unrestricted', 'RemoteSigned', 'AllSigned', 'Restricted')]
        [String]
        $ExecutionPolicy,
        [Switch]
        $PassThru
    )
    If($PSBoundParameters['Path'])
    {
        Get-ChildItem $Path -ErrorAction Stop | Out-Null
        $ScriptString = [IO.File]::ReadAllText((Resolve-Path $Path))
    }
    Else
    {
        $ScriptString = [String]$ScriptBlock
    }
    $RandomDelimiters  = @('_','-',',','{','}','~','!','@','%','&','<','>')
    @('a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z') | ForEach-Object {$UpperLowerChar = $_; If(((Get-Random -Input @(1..2))-1 -eq 0)) {$UpperLowerChar = $UpperLowerChar.ToUpper()} $RandomDelimiters += $UpperLowerChar}
    $RandomDelimiters = (Get-Random -Input $RandomDelimiters -Count ($RandomDelimiters.Count/4))
    $HexDigitRange = @(0,1,2,3,4,5,6,7,8,9,'a','A','b','B','c','C','d','D','e','E','f','F')
    $BXORValue  = '0x' + (Get-Random -Input @(0..5)) + (Get-Random -Input $HexDigitRange)
    $DelimitedEncodedArray = ''
    ([Char[]]$ScriptString) | ForEach-Object {$DelimitedEncodedArray += ([String]([Int][Char]$_ -BXOR $BXORValue) + (Get-Random -Input $RandomDelimiters))}
    $DelimitedEncodedArray = $DelimitedEncodedArray.SubString(0,$DelimitedEncodedArray.Length-1)
    $RandomDelimitersToPrint = (Get-Random -Input $RandomDelimiters -Count $RandomDelimiters.Length) -Join ''
    $ForEachObject = Get-Random -Input @('ForEach','ForEach-Object','%')
    $StrJoin       = ([Char[]]'[String]::Join' | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $StrStr        = ([Char[]]'[String]'       | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $Join          = ([Char[]]'-Join'          | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $BXOR          = ([Char[]]'-BXOR'          | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $CharStr       = ([Char[]]'Char'           | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $Int           = ([Char[]]'Int'            | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $ForEachObject = ([Char[]]$ForEachObject   | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $RandomDelimitersToPrintForDashSplit = ''
    ForEach($RandomDelimiter in $RandomDelimiters)
    {
        If($ScriptString.Contains('^'))
        {
            $Split = ([Char[]]'Split' | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
            $RandomDelimitersToPrintForDashSplit += '(' + (Get-Random -Input @('-Replace','-CReplace')) + " '^','' -$Split" + ' '*(Get-Random -Input @(0,1)) + "'" + $RandomDelimiter + "'" + ' '*(Get-Random -Input @(0,1))
            $Split = ([Char[]]"Replace('^','').Split" | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
        }
        Else
        {
            $Split = ([Char[]]'Split' | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
            $RandomDelimitersToPrintForDashSplit += ('-' + $Split + ' '*(Get-Random -Input @(0,1)) + "'" + $RandomDelimiter + "'" + ' '*(Get-Random -Input @(0,1)))
        }
        $Split = ([Char[]]$Split | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join '' 
        $RandomDelimitersToPrintForDashSplit = ([Char[]]$RandomDelimitersToPrintForDashSplit | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    }
    $RandomDelimitersToPrintForDashSplit = $RandomDelimitersToPrintForDashSplit.Trim()
    $EncodedArray = ''
    ([Char[]]$ScriptString) | ForEach-Object {$EncodedArray += ([String]([Int][Char]$_ -BXOR $BXORValue)) + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1))}
    $EncodedArray = ('(' + ' '*(Get-Random -Input @(0,1)) + $EncodedArray.Trim().Trim(',') + ')')
    $SetOfsVarSyntax      = @()
    $SetOfsVarSyntax     += 'Set-Item' + ' '*(Get-Random -Input @(1,2)) + "'Variable:OFS'" + ' '*(Get-Random -Input @(1,2)) + "''"
    $SetOfsVarSyntax     += (Get-Random -Input @('Set-Variable','SV','SET')) + ' '*(Get-Random -Input @(1,2)) + "'OFS'" + ' '*(Get-Random -Input @(1,2)) + "''"
    $SetOfsVar            = (Get-Random -Input $SetOfsVarSyntax)
    $SetOfsVarBackSyntax  = @()
    $SetOfsVarBackSyntax += 'Set-Item' + ' '*(Get-Random -Input @(1,2)) + "'Variable:OFS'" + ' '*(Get-Random -Input @(1,2)) + "' '"
    $SetOfsVarBackSyntax += (Get-Random -Input @('Set-Variable','SV','SET')) + ' '*(Get-Random -Input @(1,2)) + "'OFS'" + ' '*(Get-Random -Input @(1,2)) + "' '"
    $SetOfsVarBack        = (Get-Random -Input $SetOfsVarBackSyntax)
    $SetOfsVar            = ([Char[]]$SetOfsVar     | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $SetOfsVarBack        = ([Char[]]$SetOfsVarBack | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $Quotes = Get-Random -Input @('"',"'",' ')
    $BXORSyntax = $BXOR + ' '*(Get-Random -Input @(0,1)) + $Quotes + $BXORValue + $Quotes
    $BXORConversion = '{' + ' '*(Get-Random -Input @(0,1)) + "[$CharStr]" + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + '$_' + ' '*(Get-Random -Input @(0,1)) + $BXORSyntax + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '}'
    $BaseScriptArray  = @()
    $BaseScriptArray += '(' + ' '*(Get-Random -Input @(0,1)) + "[$CharStr[]]" + ' '*(Get-Random -Input @(0,1)) + $EncodedArray + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $ForEachObject + ' '*(Get-Random -Input @(0,1)) + $BXORConversion + ' '*(Get-Random -Input @(0,1)) + ')'
    $BaseScriptArray += '(' + ' '*(Get-Random -Input @(0,1)) + "'" + $DelimitedEncodedArray + "'." + $Split + "(" + ' '*(Get-Random -Input @(0,1)) + "'" + $RandomDelimitersToPrint + "'" + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $ForEachObject + ' '*(Get-Random -Input @(0,1)) + $BXORConversion + ' '*(Get-Random -Input @(0,1)) + ')'
    $BaseScriptArray += '(' + ' '*(Get-Random -Input @(0,1)) + "'" + $DelimitedEncodedArray + "'" + ' '*(Get-Random -Input @(0,1)) + $RandomDelimitersToPrintForDashSplit + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $ForEachObject + ' '*(Get-Random -Input @(0,1)) + $BXORConversion + ' '*(Get-Random -Input @(0,1)) + ')'
    $BaseScriptArray += '(' + ' '*(Get-Random -Input @(0,1)) + $EncodedArray + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $ForEachObject + ' '*(Get-Random -Input @(0,1)) + $BXORConversion + ' '*(Get-Random -Input @(0,1)) + ')'
    $NewScriptArray   = @()
    $NewScriptArray  += (Get-Random -Input $BaseScriptArray) + ' '*(Get-Random -Input @(0,1)) + $Join + ' '*(Get-Random -Input @(0,1)) + "''"
    $NewScriptArray  += $Join + ' '*(Get-Random -Input @(0,1)) + (Get-Random -Input $BaseScriptArray)
    $NewScriptArray  += $StrJoin + '(' + ' '*(Get-Random -Input @(0,1)) + "''" + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + (Get-Random -Input $BaseScriptArray) + ' '*(Get-Random -Input @(0,1)) + ')'
    $NewScriptArray  += '"' + ' '*(Get-Random -Input @(0,1)) + '$(' + ' '*(Get-Random -Input @(0,1)) + $SetOfsVar + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '"' + ' '*(Get-Random -Input @(0,1)) + '+' + ' '*(Get-Random -Input @(0,1)) + $StrStr + (Get-Random -Input $BaseScriptArray) + ' '*(Get-Random -Input @(0,1)) + '+' + '"' + ' '*(Get-Random -Input @(0,1)) + '$(' + ' '*(Get-Random -Input @(0,1)) + $SetOfsVarBack + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '"'
    $NewScript = (Get-Random -Input $NewScriptArray)
    $InvokeExpressionSyntax  = @()
    $InvokeExpressionSyntax += (Get-Random -Input @('IEX','Invoke-Expression'))
    $InvocationOperator = (Get-Random -Input @('.','&')) + ' '*(Get-Random -Input @(0,1))
    $InvokeExpressionSyntax += $InvocationOperator + "( `$ShellId[1]+`$ShellId[13]+'x')"
    $InvokeExpressionSyntax += $InvocationOperator + "( `$PSHome[" + (Get-Random -Input @(4,21)) + "]+`$PSHome[" + (Get-Random -Input @(30,34)) + "]+'x')"
    $InvokeExpressionSyntax += $InvocationOperator + "( `$env:ComSpec[4," + (Get-Random -Input @(15,24,26)) + ",25]-Join'')"
    $InvokeExpressionSyntax += $InvocationOperator + "((" + (Get-Random -Input @('Get-Variable','GV','Variable')) + " '*mdr*').Name[3,11,2]-Join'')"
    $InvokeExpressionSyntax += $InvocationOperator + "( " + (Get-Random -Input @('$VerbosePreference.ToString()','([String]$VerbosePreference)')) + "[1,3]+'x'-Join'')"
    $InvokeExpression = (Get-Random -Input $InvokeExpressionSyntax)
    $InvokeExpression = ([Char[]]$InvokeExpression | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $InvokeOptions  = @()
    $InvokeOptions += ' '*(Get-Random -Input @(0,1)) + $InvokeExpression + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $NewScript + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1))
    $InvokeOptions += ' '*(Get-Random -Input @(0,1)) + $NewScript + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $InvokeExpression
    $NewScript = (Get-Random -Input $InvokeOptions)
    If(!$PSBoundParameters['PassThru'])
    {
        $PowerShellFlags = @()
        $CommandlineOptions = New-Object String[](0)
        If($PSBoundParameters['NoExit'])
        {
          $FullArgument = "-NoExit";
          $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 4 -Maximum ($FullArgument.Length+1)))
        }
        If($PSBoundParameters['NoProfile'])
        {
          $FullArgument = "-NoProfile";
          $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 4 -Maximum ($FullArgument.Length+1)))
        }
        If($PSBoundParameters['NonInteractive'])
        {
          $FullArgument = "-NonInteractive";
          $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 5 -Maximum ($FullArgument.Length+1)))
        }
        If($PSBoundParameters['NoLogo'])
        {
          $FullArgument = "-NoLogo";
          $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 4 -Maximum ($FullArgument.Length+1)))
        }
        If($PSBoundParameters['WindowStyle'] -OR $WindowsStyle)
        {
            $FullArgument = "-WindowStyle"
            If($WindowsStyle) {$ArgumentValue = $WindowsStyle}
            Else {$ArgumentValue = $PSBoundParameters['WindowStyle']}
            Switch($ArgumentValue.ToLower())
            {
                'normal'    {If(Get-Random -Input @(0..1)) {$ArgumentValue = (Get-Random -Input @('0','n','no','nor','norm','norma'))}}
                'hidden'    {If(Get-Random -Input @(0..1)) {$ArgumentValue = (Get-Random -Input @('1','h','hi','hid','hidd','hidde'))}}
                'minimized' {If(Get-Random -Input @(0..1)) {$ArgumentValue = (Get-Random -Input @('2','mi','min','mini','minim','minimi','minimiz','minimize'))}}
                'maximized' {If(Get-Random -Input @(0..1)) {$ArgumentValue = (Get-Random -Input @('3','ma','max','maxi','maxim','maximi','maximiz','maximize'))}}
                default {Write-Error "An invalid `$ArgumentValue value ($ArgumentValue) was passed to switch block for Out-PowerShellLauncher."; Exit;}
            }
            $PowerShellFlags += $FullArgument.SubString(0,(Get-Random -Minimum 2 -Maximum ($FullArgument.Length+1))) + ' '*(Get-Random -Minimum 1 -Maximum 3) + $ArgumentValue
        }
        If($PSBoundParameters['ExecutionPolicy'] -OR $ExecutionPolicy)
        {
            $FullArgument = "-ExecutionPolicy"
            If($ExecutionPolicy) {$ArgumentValue = $ExecutionPolicy}
            Else {$ArgumentValue = $PSBoundParameters['ExecutionPolicy']}
            $ExecutionPolicyFlags = @()
            $ExecutionPolicyFlags += '-EP'
            For($Index=3; $Index -le $FullArgument.Length; $Index++)
            {
                $ExecutionPolicyFlags += $FullArgument.SubString(0,$Index)
            }
            $ExecutionPolicyFlag = Get-Random -Input $ExecutionPolicyFlags
            $PowerShellFlags += $ExecutionPolicyFlag + ' '*(Get-Random -Minimum 1 -Maximum 3) + $ArgumentValue
        }
        If($CommandlineOptions.Count -gt 1)
        {
            $CommandlineOptions = Get-Random -InputObject $CommandlineOptions -Count $CommandlineOptions.Count
        }
        If($PSBoundParameters['Command'])
        {
            $FullArgument = "-Command"
            $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 2 -Maximum ($FullArgument.Length+1)))
        }
        For($i=0; $i -lt $PowerShellFlags.Count; $i++)
        {
            $PowerShellFlags[$i] = ([Char[]]$PowerShellFlags[$i] | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
        }
        $CommandlineOptions = ($CommandlineOptions | ForEach-Object {$_ + " "*(Get-Random -Minimum 1 -Maximum 3)}) -Join ''
        $CommandlineOptions = " "*(Get-Random -Minimum 0 -Maximum 3) + $CommandlineOptions + " "*(Get-Random -Minimum 0 -Maximum 3)
        If($PSBoundParameters['Wow64'])
        {
            $CommandLineOutput = "C:\WINDOWS\SysWOW64\WindowsPowerShell\v1.0\powershell.exe $($CommandlineOptions) `"$NewScript`""
        }
        Else
        {
            $CommandLineOutput = "powershell $($CommandlineOptions) `"$NewScript`""
        }
        $CmdMaxLength = 8190
        If($CommandLineOutput.Length -gt $CmdMaxLength)
        {
                Write-Warning "This command exceeds the cmd.exe maximum allowed length of $CmdMaxLength characters! Its length is $($CmdLineOutput.Length) characters."
        }
        $NewScript = $CommandLineOutput
    }
    Return $NewScript
}
#}
#function Out-EncodedBinaryCommand {
function Out-EncodedBinaryCommand
{
    [CmdletBinding(DefaultParameterSetName = 'FilePath')] Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ParameterSetName = 'ScriptBlock')]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]
        $ScriptBlock,
        [Parameter(Position = 0, ParameterSetName = 'FilePath')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,
        [Switch]
        $NoExit,
        [Switch]
        $NoProfile,
        [Switch]
        $NonInteractive,
        [Switch]
        $NoLogo,
        [Switch]
        $Wow64,
        [Switch]
        $Command,
        [ValidateSet('Normal', 'Minimized', 'Maximized', 'Hidden')]
        [String]
        $WindowStyle,
        [ValidateSet('Bypass', 'Unrestricted', 'RemoteSigned', 'AllSigned', 'Restricted')]
        [String]
        $ExecutionPolicy,
        [Switch]
        $PassThru
    )
    $EncodingBase = 2
    If($PSBoundParameters['Path'])
    {
        Get-ChildItem $Path -ErrorAction Stop | Out-Null
        $ScriptString = [IO.File]::ReadAllText((Resolve-Path $Path))
    }
    Else
    {
        $ScriptString = [String]$ScriptBlock
    }
    $RandomDelimiters  = @('_','-',',','{','}','~','!','@','%','&','<','>',';',':')
    @('a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z') | ForEach-Object {$UpperLowerChar = $_; If(((Get-Random -Input @(1..2))-1 -eq 0)) {$UpperLowerChar = $UpperLowerChar.ToUpper()} $RandomDelimiters += $UpperLowerChar}
    $RandomDelimiters = (Get-Random -Input $RandomDelimiters -Count ($RandomDelimiters.Count/4))
    $DelimitedEncodedArray = ''
    ([Char[]]$ScriptString) | ForEach-Object {$DelimitedEncodedArray += ([Convert]::ToString(([Int][Char]$_),$EncodingBase) + (Get-Random -Input $RandomDelimiters))}
    $DelimitedEncodedArray = $DelimitedEncodedArray.SubString(0,$DelimitedEncodedArray.Length-1)
    $RandomDelimitersToPrint = (Get-Random -Input $RandomDelimiters -Count $RandomDelimiters.Length) -Join ''
    $ForEachObject = Get-Random -Input @('ForEach','ForEach-Object','%')
    $StrJoin       = ([Char[]]'[String]::Join'      | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $StrStr        = ([Char[]]'[String]'            | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $Join          = ([Char[]]'-Join'               | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $CharStr       = ([Char[]]'Char'                | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $Int           = ([Char[]]'Int'                 | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $ForEachObject = ([Char[]]$ForEachObject        | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $ToInt16       = ([Char[]]'[Convert]::ToInt16(' | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $RandomDelimitersToPrintForDashSplit = ''
    ForEach($RandomDelimiter in $RandomDelimiters)
    {
        $Split = ([Char[]]'Split' | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
        $RandomDelimitersToPrintForDashSplit += ('-' + $Split + ' '*(Get-Random -Input @(0,1)) + "'" + $RandomDelimiter + "'" + ' '*(Get-Random -Input @(0,1)))
    }
    $RandomDelimitersToPrintForDashSplit = $RandomDelimitersToPrintForDashSplit.Trim()
    $RandomStringSyntax = ([Char[]](Get-Random -Input @('[String]$_','$_.ToString()')) | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $RandomConversionSyntax  = @()
    $RandomConversionSyntax += "[$CharStr]" + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $ToInt16 + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $RandomStringSyntax + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + ',' + $EncodingBase + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + ')'
    $RandomConversionSyntax += $ToInt16 + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $RandomStringSyntax + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + $EncodingBase + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + (Get-Random -Input @('-as','-As','-aS','-AS')) + ' '*(Get-Random -Input @(0,1)) + "[$CharStr]"
    $RandomConversionSyntax = (Get-Random -Input $RandomConversionSyntax)
    $EncodedArray = ''
    ([Char[]]$ScriptString) | ForEach-Object {
        If([Convert]::ToString(([Int][Char]$_),$EncodingBase).Trim('0123456789').Length -gt 0) {$Quote = "'"}
        Else {$Quote = ''}
        $EncodedArray += ($Quote + [Convert]::ToString(([Int][Char]$_),$EncodingBase) + $Quote + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)))
    }
    $EncodedArray = ('(' + ' '*(Get-Random -Input @(0,1)) + $EncodedArray.Trim().Trim(',') + ')')
    $SetOfsVarSyntax      = @()
    $SetOfsVarSyntax     += 'Set-Item' + ' '*(Get-Random -Input @(1,2)) + "'Variable:OFS'" + ' '*(Get-Random -Input @(1,2)) + "''"
    $SetOfsVarSyntax     += (Get-Random -Input @('Set-Variable','SV','SET')) + ' '*(Get-Random -Input @(1,2)) + "'OFS'" + ' '*(Get-Random -Input @(1,2)) + "''"
    $SetOfsVar            = (Get-Random -Input $SetOfsVarSyntax)
    $SetOfsVarBackSyntax  = @()
    $SetOfsVarBackSyntax += 'Set-Item' + ' '*(Get-Random -Input @(1,2)) + "'Variable:OFS'" + ' '*(Get-Random -Input @(1,2)) + "' '"
    $SetOfsVarBackSyntax += (Get-Random -Input @('Set-Variable','SV','SET')) + ' '*(Get-Random -Input @(1,2)) + "'OFS'" + ' '*(Get-Random -Input @(1,2)) + "' '"
    $SetOfsVarBack        = (Get-Random -Input $SetOfsVarBackSyntax)
    $SetOfsVar            = ([Char[]]$SetOfsVar     | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $SetOfsVarBack        = ([Char[]]$SetOfsVarBack | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $BaseScriptArray  = @()
    $BaseScriptArray += '(' + ' '*(Get-Random -Input @(0,1)) + "'" + $DelimitedEncodedArray + "'." + $Split + "(" + ' '*(Get-Random -Input @(0,1)) + "'" + $RandomDelimitersToPrint + "'" + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $ForEachObject + ' '*(Get-Random -Input @(0,1)) + '{' + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $RandomConversionSyntax + ')' +  ' '*(Get-Random -Input @(0,1)) + '}' + ' '*(Get-Random -Input @(0,1)) + ')'
    $BaseScriptArray += '(' + ' '*(Get-Random -Input @(0,1)) + "'" + $DelimitedEncodedArray + "'" + ' '*(Get-Random -Input @(0,1)) + $RandomDelimitersToPrintForDashSplit + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $ForEachObject + ' '*(Get-Random -Input @(0,1)) + '{' + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $RandomConversionSyntax + ')' +  ' '*(Get-Random -Input @(0,1)) + '}' + ' '*(Get-Random -Input @(0,1)) + ')'
    $BaseScriptArray += '(' + ' '*(Get-Random -Input @(0,1)) + $EncodedArray + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $ForEachObject + ' '*(Get-Random -Input @(0,1)) + '{' + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $RandomConversionSyntax + ')' +  ' '*(Get-Random -Input @(0,1)) + '}' + ' '*(Get-Random -Input @(0,1)) + ')'
    $NewScriptArray   = @()
    $NewScriptArray  += (Get-Random -Input $BaseScriptArray) + ' '*(Get-Random -Input @(0,1)) + $Join + ' '*(Get-Random -Input @(0,1)) + "''"
    $NewScriptArray  += $Join + ' '*(Get-Random -Input @(0,1)) + (Get-Random -Input $BaseScriptArray)
    $NewScriptArray  += $StrJoin + '(' + ' '*(Get-Random -Input @(0,1)) + "''" + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + (Get-Random -Input $BaseScriptArray) + ' '*(Get-Random -Input @(0,1)) + ')'
    $NewScriptArray  += '"' + ' '*(Get-Random -Input @(0,1)) + '$(' + ' '*(Get-Random -Input @(0,1)) + $SetOfsVar + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '"' + ' '*(Get-Random -Input @(0,1)) + '+' + ' '*(Get-Random -Input @(0,1)) + $StrStr + (Get-Random -Input $BaseScriptArray) + ' '*(Get-Random -Input @(0,1)) + '+' + '"' + ' '*(Get-Random -Input @(0,1)) + '$(' + ' '*(Get-Random -Input @(0,1)) + $SetOfsVarBack + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '"'
    $NewScript = (Get-Random -Input $NewScriptArray)
    $InvokeExpressionSyntax  = @()
    $InvokeExpressionSyntax += (Get-Random -Input @('IEX','Invoke-Expression'))
    $InvocationOperator = (Get-Random -Input @('.','&')) + ' '*(Get-Random -Input @(0,1))
    $InvokeExpressionSyntax += $InvocationOperator + "( `$ShellId[1]+`$ShellId[13]+'x')"
    $InvokeExpressionSyntax += $InvocationOperator + "( `$PSHome[" + (Get-Random -Input @(4,21)) + "]+`$PSHome[" + (Get-Random -Input @(30,34)) + "]+'x')"
    $InvokeExpressionSyntax += $InvocationOperator + "( `$env:ComSpec[4," + (Get-Random -Input @(15,24,26)) + ",25]-Join'')"
    $InvokeExpressionSyntax += $InvocationOperator + "((" + (Get-Random -Input @('Get-Variable','GV','Variable')) + " '*mdr*').Name[3,11,2]-Join'')"
    $InvokeExpressionSyntax += $InvocationOperator + "( " + (Get-Random -Input @('$VerbosePreference.ToString()','([String]$VerbosePreference)')) + "[1,3]+'x'-Join'')"
    $InvokeExpression = (Get-Random -Input $InvokeExpressionSyntax)
    $InvokeExpression = ([Char[]]$InvokeExpression | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $InvokeOptions  = @()
    $InvokeOptions += ' '*(Get-Random -Input @(0,1)) + $InvokeExpression + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $NewScript + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1))
    $InvokeOptions += ' '*(Get-Random -Input @(0,1)) + $NewScript + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $InvokeExpression
    $NewScript = (Get-Random -Input $InvokeOptions)
    If(!$PSBoundParameters['PassThru'])
    {
        $PowerShellFlags = @()
        $CommandlineOptions = New-Object String[](0)
        If($PSBoundParameters['NoExit'])
        {
          $FullArgument = "-NoExit";
          $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 4 -Maximum ($FullArgument.Length+1)))
        }
        If($PSBoundParameters['NoProfile'])
        {
          $FullArgument = "-NoProfile";
          $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 4 -Maximum ($FullArgument.Length+1)))
        }
        If($PSBoundParameters['NonInteractive'])
        {
          $FullArgument = "-NonInteractive";
          $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 5 -Maximum ($FullArgument.Length+1)))
        }
        If($PSBoundParameters['NoLogo'])
        {
          $FullArgument = "-NoLogo";
          $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 4 -Maximum ($FullArgument.Length+1)))
        }
        If($PSBoundParameters['WindowStyle'] -OR $WindowsStyle)
        {
            $FullArgument = "-WindowStyle"
            If($WindowsStyle) {$ArgumentValue = $WindowsStyle}
            Else {$ArgumentValue = $PSBoundParameters['WindowStyle']}
            Switch($ArgumentValue.ToLower())
            {
                'normal'    {If(Get-Random -Input @(0..1)) {$ArgumentValue = (Get-Random -Input @('0','n','no','nor','norm','norma'))}}
                'hidden'    {If(Get-Random -Input @(0..1)) {$ArgumentValue = (Get-Random -Input @('1','h','hi','hid','hidd','hidde'))}}
                'minimized' {If(Get-Random -Input @(0..1)) {$ArgumentValue = (Get-Random -Input @('2','mi','min','mini','minim','minimi','minimiz','minimize'))}}
                'maximized' {If(Get-Random -Input @(0..1)) {$ArgumentValue = (Get-Random -Input @('3','ma','max','maxi','maxim','maximi','maximiz','maximize'))}}
                default {Write-Error "An invalid `$ArgumentValue value ($ArgumentValue) was passed to switch block for Out-PowerShellLauncher."; Exit;}
            }
            $PowerShellFlags += $FullArgument.SubString(0,(Get-Random -Minimum 2 -Maximum ($FullArgument.Length+1))) + ' '*(Get-Random -Minimum 1 -Maximum 3) + $ArgumentValue
        }
        If($PSBoundParameters['ExecutionPolicy'] -OR $ExecutionPolicy)
        {
            $FullArgument = "-ExecutionPolicy"
            If($ExecutionPolicy) {$ArgumentValue = $ExecutionPolicy}
            Else {$ArgumentValue = $PSBoundParameters['ExecutionPolicy']}
            $ExecutionPolicyFlags = @()
            $ExecutionPolicyFlags += '-EP'
            For($Index=3; $Index -le $FullArgument.Length; $Index++)
            {
                $ExecutionPolicyFlags += $FullArgument.SubString(0,$Index)
            }
            $ExecutionPolicyFlag = Get-Random -Input $ExecutionPolicyFlags
            $PowerShellFlags += $ExecutionPolicyFlag + ' '*(Get-Random -Minimum 1 -Maximum 3) + $ArgumentValue
        }
        If($CommandlineOptions.Count -gt 1)
        {
            $CommandlineOptions = Get-Random -InputObject $CommandlineOptions -Count $CommandlineOptions.Count
        }
        If($PSBoundParameters['Command'])
        {
            $FullArgument = "-Command"
            $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 2 -Maximum ($FullArgument.Length+1)))
        }
        For($i=0; $i -lt $PowerShellFlags.Count; $i++)
        {
            $PowerShellFlags[$i] = ([Char[]]$PowerShellFlags[$i] | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
        }
        $CommandlineOptions = ($CommandlineOptions | ForEach-Object {$_ + " "*(Get-Random -Minimum 1 -Maximum 3)}) -Join ''
        $CommandlineOptions = " "*(Get-Random -Minimum 0 -Maximum 3) + $CommandlineOptions + " "*(Get-Random -Minimum 0 -Maximum 3)
        If($PSBoundParameters['Wow64'])
        {
            $CommandLineOutput = "C:\WINDOWS\SysWOW64\WindowsPowerShell\v1.0\powershell.exe $($CommandlineOptions) `"$NewScript`""
        }
        Else
        {
            $CommandLineOutput = "powershell $($CommandlineOptions) `"$NewScript`""
        }
        $CmdMaxLength = 8190
        If($CommandLineOutput.Length -gt $CmdMaxLength)
        {
            Write-Warning "This command exceeds the cmd.exe maximum allowed length of $CmdMaxLength characters! Its length is $($CmdLineOutput.Length) characters."
        }
        $NewScript = $CommandLineOutput
    }
    Return $NewScript
}
#}
#function Out-EncodedAsciiCommand {
function Out-EncodedAsciiCommand
{
    [CmdletBinding(DefaultParameterSetName = 'FilePath')] Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ParameterSetName = 'ScriptBlock')]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]
        $ScriptBlock,
        [Parameter(Position = 0, ParameterSetName = 'FilePath')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,
        [Switch]
        $NoExit,
        [Switch]
        $NoProfile,
        [Switch]
        $NonInteractive,
        [Switch]
        $NoLogo,
        [Switch]
        $Wow64,
        [Switch]
        $Command,
        [ValidateSet('Normal', 'Minimized', 'Maximized', 'Hidden')]
        [String]
        $WindowStyle,
        [ValidateSet('Bypass', 'Unrestricted', 'RemoteSigned', 'AllSigned', 'Restricted')]
        [String]
        $ExecutionPolicy,
        [Switch]
        $PassThru
    )
    If($PSBoundParameters['Path'])
    {
        Get-ChildItem $Path -ErrorAction Stop | Out-Null
        $ScriptString = [IO.File]::ReadAllText((Resolve-Path $Path))
    }
    Else
    {
        $ScriptString = [String]$ScriptBlock
    }
    $RandomDelimiters  = @('_','-',',','{','}','~','!','@','%','&','<','>',';',':')
    @('a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z') | ForEach-Object {$UpperLowerChar = $_; If(((Get-Random -Input @(1..2))-1 -eq 0)) {$UpperLowerChar = $UpperLowerChar.ToUpper()} $RandomDelimiters += $UpperLowerChar}
    $RandomDelimiters = (Get-Random -Input $RandomDelimiters -Count ($RandomDelimiters.Count/4))
    $DelimitedEncodedArray = ''
    ([Char[]]$ScriptString) | ForEach-Object {$DelimitedEncodedArray += ([String]([Int][Char]$_) + (Get-Random -Input $RandomDelimiters))}
    $DelimitedEncodedArray = $DelimitedEncodedArray.SubString(0,$DelimitedEncodedArray.Length-1)
    $RandomDelimitersToPrint = (Get-Random -Input $RandomDelimiters -Count $RandomDelimiters.Length) -Join ''
    $ForEachObject = Get-Random -Input @('ForEach','ForEach-Object','%')
    $StrJoin       = ([Char[]]'[String]::Join' | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $StrStr        = ([Char[]]'[String]'       | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $Join          = ([Char[]]'-Join'          | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $CharStr       = ([Char[]]'Char'           | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $Int           = ([Char[]]'Int'            | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $ForEachObject = ([Char[]]$ForEachObject   | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $RandomDelimitersToPrintForDashSplit = ''
    ForEach($RandomDelimiter in $RandomDelimiters)
    {
        $Split = ([Char[]]'Split' | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
        $RandomDelimitersToPrintForDashSplit += ('-' + $Split + ' '*(Get-Random -Input @(0,1)) + "'" + $RandomDelimiter + "'" + ' '*(Get-Random -Input @(0,1)))
    }
    $RandomDelimitersToPrintForDashSplit = $RandomDelimitersToPrintForDashSplit.Trim()
    $RandomConversionSyntax  = @()
    $RandomConversionSyntax += "[$CharStr]" + ' '*(Get-Random -Input @(0,1)) + "[$Int]" + ' '*(Get-Random -Input @(0,1)) + '$_'
    $RandomConversionSyntax += ("[$Int]" + ' '*(Get-Random -Input @(0,1)) + '$_' + ' '*(Get-Random -Input @(0,1)) + (Get-Random -Input @('-as','-As','-aS','-AS')) + ' '*(Get-Random -Input @(0,1)) + "[$CharStr]")
    $RandomConversionSyntax = (Get-Random -Input $RandomConversionSyntax)
    $EncodedArray = ''
    ([Char[]]$ScriptString) | ForEach-Object {$EncodedArray += ([String]([Int][Char]$_) + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)))}
    $EncodedArray = ('(' + ' '*(Get-Random -Input @(0,1)) + $EncodedArray.Trim().Trim(',') + ')')
    $SetOfsVarSyntax      = @()
    $SetOfsVarSyntax     += 'Set-Item' + ' '*(Get-Random -Input @(1,2)) + "'Variable:OFS'" + ' '*(Get-Random -Input @(1,2)) + "''"
    $SetOfsVarSyntax     += (Get-Random -Input @('Set-Variable','SV','SET')) + ' '*(Get-Random -Input @(1,2)) + "'OFS'" + ' '*(Get-Random -Input @(1,2)) + "''"
    $SetOfsVar            = (Get-Random -Input $SetOfsVarSyntax)
    $SetOfsVarBackSyntax  = @()
    $SetOfsVarBackSyntax += 'Set-Item' + ' '*(Get-Random -Input @(1,2)) + "'Variable:OFS'" + ' '*(Get-Random -Input @(1,2)) + "' '"
    $SetOfsVarBackSyntax += (Get-Random -Input @('Set-Variable','SV','SET')) + ' '*(Get-Random -Input @(1,2)) + "'OFS'" + ' '*(Get-Random -Input @(1,2)) + "' '"
    $SetOfsVarBack        = (Get-Random -Input $SetOfsVarBackSyntax)
    $SetOfsVar            = ([Char[]]$SetOfsVar     | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $SetOfsVarBack        = ([Char[]]$SetOfsVarBack | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $BaseScriptArray  = @()
    $BaseScriptArray += "[$CharStr[]]" + ' '*(Get-Random -Input @(0,1)) + $EncodedArray
    $BaseScriptArray += '(' + ' '*(Get-Random -Input @(0,1)) + "'" + $DelimitedEncodedArray + "'." + $Split + "(" + ' '*(Get-Random -Input @(0,1)) + "'" + $RandomDelimitersToPrint + "'" + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $ForEachObject + ' '*(Get-Random -Input @(0,1)) + '{' + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $RandomConversionSyntax + ')' +  ' '*(Get-Random -Input @(0,1)) + '}' + ' '*(Get-Random -Input @(0,1)) + ')'
    $BaseScriptArray += '(' + ' '*(Get-Random -Input @(0,1)) + "'" + $DelimitedEncodedArray + "'" + ' '*(Get-Random -Input @(0,1)) + $RandomDelimitersToPrintForDashSplit + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $ForEachObject + ' '*(Get-Random -Input @(0,1)) + '{' + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $RandomConversionSyntax + ')' +  ' '*(Get-Random -Input @(0,1)) + '}' + ' '*(Get-Random -Input @(0,1)) + ')'
    $BaseScriptArray += '(' + ' '*(Get-Random -Input @(0,1)) + $EncodedArray + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $ForEachObject + ' '*(Get-Random -Input @(0,1)) + '{' + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $RandomConversionSyntax + ')' +  ' '*(Get-Random -Input @(0,1)) + '}' + ' '*(Get-Random -Input @(0,1)) + ')'
    $NewScriptArray   = @()
    $NewScriptArray  += (Get-Random -Input $BaseScriptArray) + ' '*(Get-Random -Input @(0,1)) + $Join + ' '*(Get-Random -Input @(0,1)) + "''"
    $NewScriptArray  += $Join + ' '*(Get-Random -Input @(0,1)) + (Get-Random -Input $BaseScriptArray)
    $NewScriptArray  += $StrJoin + '(' + ' '*(Get-Random -Input @(0,1)) + "''" + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + (Get-Random -Input $BaseScriptArray) + ' '*(Get-Random -Input @(0,1)) + ')'
    $NewScriptArray  += '"' + ' '*(Get-Random -Input @(0,1)) + '$(' + ' '*(Get-Random -Input @(0,1)) + $SetOfsVar + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '"' + ' '*(Get-Random -Input @(0,1)) + '+' + ' '*(Get-Random -Input @(0,1)) + $StrStr + (Get-Random -Input $BaseScriptArray) + ' '*(Get-Random -Input @(0,1)) + '+' + '"' + ' '*(Get-Random -Input @(0,1)) + '$(' + ' '*(Get-Random -Input @(0,1)) + $SetOfsVarBack + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '"'
    $NewScript = (Get-Random -Input $NewScriptArray)
    $InvokeExpressionSyntax  = @()
    $InvokeExpressionSyntax += (Get-Random -Input @('IEX','Invoke-Expression'))
    $InvocationOperator = (Get-Random -Input @('.','&')) + ' '*(Get-Random -Input @(0,1))
    $InvokeExpressionSyntax += $InvocationOperator + "( `$ShellId[1]+`$ShellId[13]+'x')"
    $InvokeExpressionSyntax += $InvocationOperator + "( `$PSHome[" + (Get-Random -Input @(4,21)) + "]+`$PSHome[" + (Get-Random -Input @(30,34)) + "]+'x')"
    $InvokeExpressionSyntax += $InvocationOperator + "( `$env:ComSpec[4," + (Get-Random -Input @(15,24,26)) + ",25]-Join'')"
    $InvokeExpressionSyntax += $InvocationOperator + "((" + (Get-Random -Input @('Get-Variable','GV','Variable')) + " '*mdr*').Name[3,11,2]-Join'')"
    $InvokeExpressionSyntax += $InvocationOperator + "( " + (Get-Random -Input @('$VerbosePreference.ToString()','([String]$VerbosePreference)')) + "[1,3]+'x'-Join'')"
    $InvokeExpression = (Get-Random -Input $InvokeExpressionSyntax)
    $InvokeExpression = ([Char[]]$InvokeExpression | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $InvokeOptions  = @()
    $InvokeOptions += ' '*(Get-Random -Input @(0,1)) + $InvokeExpression + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $NewScript + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1))
    $InvokeOptions += ' '*(Get-Random -Input @(0,1)) + $NewScript + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $InvokeExpression
    $NewScript = (Get-Random -Input $InvokeOptions)
    If(!$PSBoundParameters['PassThru'])
    {
        $PowerShellFlags = @()
        $CommandlineOptions = New-Object String[](0)
        If($PSBoundParameters['NoExit'])
        {
          $FullArgument = "-NoExit";
          $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 4 -Maximum ($FullArgument.Length+1)))
        }
        If($PSBoundParameters['NoProfile'])
        {
          $FullArgument = "-NoProfile";
          $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 4 -Maximum ($FullArgument.Length+1)))
        }
        If($PSBoundParameters['NonInteractive'])
        {
          $FullArgument = "-NonInteractive";
          $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 5 -Maximum ($FullArgument.Length+1)))
        }
        If($PSBoundParameters['NoLogo'])
        {
          $FullArgument = "-NoLogo";
          $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 4 -Maximum ($FullArgument.Length+1)))
        }
        If($PSBoundParameters['WindowStyle'] -OR $WindowsStyle)
        {
            $FullArgument = "-WindowStyle"
            If($WindowsStyle) {$ArgumentValue = $WindowsStyle}
            Else {$ArgumentValue = $PSBoundParameters['WindowStyle']}
            Switch($ArgumentValue.ToLower())
            {
                'normal'    {If(Get-Random -Input @(0..1)) {$ArgumentValue = (Get-Random -Input @('0','n','no','nor','norm','norma'))}}
                'hidden'    {If(Get-Random -Input @(0..1)) {$ArgumentValue = (Get-Random -Input @('1','h','hi','hid','hidd','hidde'))}}
                'minimized' {If(Get-Random -Input @(0..1)) {$ArgumentValue = (Get-Random -Input @('2','mi','min','mini','minim','minimi','minimiz','minimize'))}}
                'maximized' {If(Get-Random -Input @(0..1)) {$ArgumentValue = (Get-Random -Input @('3','ma','max','maxi','maxim','maximi','maximiz','maximize'))}}
                default {Write-Error "An invalid `$ArgumentValue value ($ArgumentValue) was passed to switch block for Out-PowerShellLauncher."; Exit;}
            }
            $PowerShellFlags += $FullArgument.SubString(0,(Get-Random -Minimum 2 -Maximum ($FullArgument.Length+1))) + ' '*(Get-Random -Minimum 1 -Maximum 3) + $ArgumentValue
        }
        If($PSBoundParameters['ExecutionPolicy'] -OR $ExecutionPolicy)
        {
            $FullArgument = "-ExecutionPolicy"
            If($ExecutionPolicy) {$ArgumentValue = $ExecutionPolicy}
            Else {$ArgumentValue = $PSBoundParameters['ExecutionPolicy']}
            $ExecutionPolicyFlags = @()
            $ExecutionPolicyFlags += '-EP'
            For($Index=3; $Index -le $FullArgument.Length; $Index++)
            {
                $ExecutionPolicyFlags += $FullArgument.SubString(0,$Index)
            }
            $ExecutionPolicyFlag = Get-Random -Input $ExecutionPolicyFlags
            $PowerShellFlags += $ExecutionPolicyFlag + ' '*(Get-Random -Minimum 1 -Maximum 3) + $ArgumentValue
        }
        If($CommandlineOptions.Count -gt 1)
        {
            $CommandlineOptions = Get-Random -InputObject $CommandlineOptions -Count $CommandlineOptions.Count
        }
        If($PSBoundParameters['Command'])
        {
            $FullArgument = "-Command"
            $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 2 -Maximum ($FullArgument.Length+1)))
        }
        For($i=0; $i -lt $PowerShellFlags.Count; $i++)
        {
            $PowerShellFlags[$i] = ([Char[]]$PowerShellFlags[$i] | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
        }
        $CommandlineOptions = ($CommandlineOptions | ForEach-Object {$_ + " "*(Get-Random -Minimum 1 -Maximum 3)}) -Join ''
        $CommandlineOptions = " "*(Get-Random -Minimum 0 -Maximum 3) + $CommandlineOptions + " "*(Get-Random -Minimum 0 -Maximum 3)
        If($PSBoundParameters['Wow64'])
        {
            $CommandLineOutput = "C:\WINDOWS\SysWOW64\WindowsPowerShell\v1.0\powershell.exe $($CommandlineOptions) `"$NewScript`""
        }
        Else
        {
            $CommandLineOutput = "powershell $($CommandlineOptions) `"$NewScript`""
        }
        $CmdMaxLength = 8190
        If($CommandLineOutput.Length -gt $CmdMaxLength)
        {
            Write-Warning "This command exceeds the cmd.exe maximum allowed length of $CmdMaxLength characters! Its length is $($CmdLineOutput.Length) characters."
        }
        $NewScript = $CommandLineOutput
    }
    Return $NewScript
}
#}
#function Out-EncodedHexCommand {
function Out-EncodedHexCommand
{
    [CmdletBinding(DefaultParameterSetName = 'FilePath')] Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ParameterSetName = 'ScriptBlock')]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]
        $ScriptBlock,
        [Parameter(Position = 0, ParameterSetName = 'FilePath')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,
        [Switch]
        $NoExit,
        [Switch]
        $NoProfile,
        [Switch]
        $NonInteractive,
        [Switch]
        $NoLogo,
        [Switch]
        $Wow64,
        [Switch]
        $Command,
        [ValidateSet('Normal', 'Minimized', 'Maximized', 'Hidden')]
        [String]
        $WindowStyle,
        [ValidateSet('Bypass', 'Unrestricted', 'RemoteSigned', 'AllSigned', 'Restricted')]
        [String]
        $ExecutionPolicy,
        [Switch]
        $PassThru
    )
    $EncodingBase = 16
    If($PSBoundParameters['Path'])
    {
        Get-ChildItem $Path -ErrorAction Stop | Out-Null
        $ScriptString = [IO.File]::ReadAllText((Resolve-Path $Path))
    }
    Else
    {
        $ScriptString = [String]$ScriptBlock
    }
    $RandomDelimiters  = @('_','-',',','{','}','~','!','@','%','&','<','>',';',':')
    @('g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z') | ForEach-Object {$UpperLowerChar = $_; If(((Get-Random -Input @(1..2))-1 -eq 0)) {$UpperLowerChar = $UpperLowerChar.ToUpper()} $RandomDelimiters += $UpperLowerChar}
    $RandomDelimiters = (Get-Random -Input $RandomDelimiters -Count ($RandomDelimiters.Count/4))
    $DelimitedEncodedArray = ''
    ([Char[]]$ScriptString) | ForEach-Object {$DelimitedEncodedArray += ([Convert]::ToString(([Int][Char]$_),$EncodingBase) + (Get-Random -Input $RandomDelimiters))}
    $DelimitedEncodedArray = $DelimitedEncodedArray.SubString(0,$DelimitedEncodedArray.Length-1)
    $RandomDelimitersToPrint = (Get-Random -Input $RandomDelimiters -Count $RandomDelimiters.Length) -Join ''
    $ForEachObject = Get-Random -Input @('ForEach','ForEach-Object','%')
    $StrJoin       = ([Char[]]'[String]::Join'      | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $StrStr        = ([Char[]]'[String]'            | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $Join          = ([Char[]]'-Join'               | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $CharStr       = ([Char[]]'Char'                | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $Int           = ([Char[]]'Int'                 | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $ForEachObject = ([Char[]]$ForEachObject        | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $ToInt16       = ([Char[]]'[Convert]::ToInt16(' | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $RandomDelimitersToPrintForDashSplit = ''
    ForEach($RandomDelimiter in $RandomDelimiters)
    {
        $Split = ([Char[]]'Split' | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
        $RandomDelimitersToPrintForDashSplit += ('-' + $Split + ' '*(Get-Random -Input @(0,1)) + "'" + $RandomDelimiter + "'" + ' '*(Get-Random -Input @(0,1)))
    }
    $RandomDelimitersToPrintForDashSplit = $RandomDelimitersToPrintForDashSplit.Trim()
    $RandomStringSyntax = ([Char[]](Get-Random -Input @('[String]$_','$_.ToString()')) | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $RandomConversionSyntax  = @()
    $RandomConversionSyntax += "[$CharStr]" + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $ToInt16 + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $RandomStringSyntax + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + ',' + $EncodingBase + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + ')'
    $RandomConversionSyntax += $ToInt16 + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $RandomStringSyntax + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + $EncodingBase + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + (Get-Random -Input @('-as','-As','-aS','-AS')) + ' '*(Get-Random -Input @(0,1)) + "[$CharStr]"
    $RandomConversionSyntax = (Get-Random -Input $RandomConversionSyntax)
    $EncodedArray = ''
    ([Char[]]$ScriptString) | ForEach-Object {
        If([Convert]::ToString(([Int][Char]$_),$EncodingBase).Trim('0123456789').Length -gt 0) {$Quote = "'"}
        Else {$Quote = ''}
        $EncodedArray += ($Quote + [Convert]::ToString(([Int][Char]$_),$EncodingBase) + $Quote + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)))
    }
    $EncodedArray = ('(' + ' '*(Get-Random -Input @(0,1)) + $EncodedArray.Trim().Trim(',') + ')')
    $SetOfsVarSyntax      = @()
    $SetOfsVarSyntax     += 'Set-Item' + ' '*(Get-Random -Input @(1,2)) + "'Variable:OFS'" + ' '*(Get-Random -Input @(1,2)) + "''"
    $SetOfsVarSyntax     += (Get-Random -Input @('Set-Variable','SV','SET')) + ' '*(Get-Random -Input @(1,2)) + "'OFS'" + ' '*(Get-Random -Input @(1,2)) + "''"
    $SetOfsVar            = (Get-Random -Input $SetOfsVarSyntax)
    $SetOfsVarBackSyntax  = @()
    $SetOfsVarBackSyntax += 'Set-Item' + ' '*(Get-Random -Input @(1,2)) + "'Variable:OFS'" + ' '*(Get-Random -Input @(1,2)) + "' '"
    $SetOfsVarBackSyntax += (Get-Random -Input @('Set-Variable','SV','SET')) + ' '*(Get-Random -Input @(1,2)) + "'OFS'" + ' '*(Get-Random -Input @(1,2)) + "' '"
    $SetOfsVarBack        = (Get-Random -Input $SetOfsVarBackSyntax)
    $SetOfsVar            = ([Char[]]$SetOfsVar     | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $SetOfsVarBack        = ([Char[]]$SetOfsVarBack | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $BaseScriptArray  = @()
    $BaseScriptArray += '(' + ' '*(Get-Random -Input @(0,1)) + "'" + $DelimitedEncodedArray + "'." + $Split + "(" + ' '*(Get-Random -Input @(0,1)) + "'" + $RandomDelimitersToPrint + "'" + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $ForEachObject + ' '*(Get-Random -Input @(0,1)) + '{' + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $RandomConversionSyntax + ')' +  ' '*(Get-Random -Input @(0,1)) + '}' + ' '*(Get-Random -Input @(0,1)) + ')'
    $BaseScriptArray += '(' + ' '*(Get-Random -Input @(0,1)) + "'" + $DelimitedEncodedArray + "'" + ' '*(Get-Random -Input @(0,1)) + $RandomDelimitersToPrintForDashSplit + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $ForEachObject + ' '*(Get-Random -Input @(0,1)) + '{' + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $RandomConversionSyntax + ')' +  ' '*(Get-Random -Input @(0,1)) + '}' + ' '*(Get-Random -Input @(0,1)) + ')'
    $BaseScriptArray += '(' + ' '*(Get-Random -Input @(0,1)) + $EncodedArray + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $ForEachObject + ' '*(Get-Random -Input @(0,1)) + '{' + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $RandomConversionSyntax + ')' +  ' '*(Get-Random -Input @(0,1)) + '}' + ' '*(Get-Random -Input @(0,1)) + ')'
    $NewScriptArray   = @()
    $NewScriptArray  += (Get-Random -Input $BaseScriptArray) + ' '*(Get-Random -Input @(0,1)) + $Join + ' '*(Get-Random -Input @(0,1)) + "''"
    $NewScriptArray  += $Join + ' '*(Get-Random -Input @(0,1)) + (Get-Random -Input $BaseScriptArray)
    $NewScriptArray  += $StrJoin + '(' + ' '*(Get-Random -Input @(0,1)) + "''" + ' '*(Get-Random -Input @(0,1)) + ',' + ' '*(Get-Random -Input @(0,1)) + (Get-Random -Input $BaseScriptArray) + ' '*(Get-Random -Input @(0,1)) + ')'
    $NewScriptArray  += '"' + ' '*(Get-Random -Input @(0,1)) + '$(' + ' '*(Get-Random -Input @(0,1)) + $SetOfsVar + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '"' + ' '*(Get-Random -Input @(0,1)) + '+' + ' '*(Get-Random -Input @(0,1)) + $StrStr + (Get-Random -Input $BaseScriptArray) + ' '*(Get-Random -Input @(0,1)) + '+' + '"' + ' '*(Get-Random -Input @(0,1)) + '$(' + ' '*(Get-Random -Input @(0,1)) + $SetOfsVarBack + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1)) + '"'
    $NewScript = (Get-Random -Input $NewScriptArray)
    $InvokeExpressionSyntax  = @()
    $InvokeExpressionSyntax += (Get-Random -Input @('IEX','Invoke-Expression'))
    $InvocationOperator = (Get-Random -Input @('.','&')) + ' '*(Get-Random -Input @(0,1))
    $InvokeExpressionSyntax += $InvocationOperator + "( `$ShellId[1]+`$ShellId[13]+'x')"
    $InvokeExpressionSyntax += $InvocationOperator + "( `$PSHome[" + (Get-Random -Input @(4,21)) + "]+`$PSHome[" + (Get-Random -Input @(30,34)) + "]+'x')"
    $InvokeExpressionSyntax += $InvocationOperator + "( `$env:ComSpec[4," + (Get-Random -Input @(15,24,26)) + ",25]-Join'')"
    $InvokeExpressionSyntax += $InvocationOperator + "((" + (Get-Random -Input @('Get-Variable','GV','Variable')) + " '*mdr*').Name[3,11,2]-Join'')"
    $InvokeExpressionSyntax += $InvocationOperator + "( " + (Get-Random -Input @('$VerbosePreference.ToString()','([String]$VerbosePreference)')) + "[1,3]+'x'-Join'')"
    $InvokeExpression = (Get-Random -Input $InvokeExpressionSyntax)
    $InvokeExpression = ([Char[]]$InvokeExpression | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
    $InvokeOptions  = @()
    $InvokeOptions += ' '*(Get-Random -Input @(0,1)) + $InvokeExpression + ' '*(Get-Random -Input @(0,1)) + '(' + ' '*(Get-Random -Input @(0,1)) + $NewScript + ' '*(Get-Random -Input @(0,1)) + ')' + ' '*(Get-Random -Input @(0,1))
    $InvokeOptions += ' '*(Get-Random -Input @(0,1)) + $NewScript + ' '*(Get-Random -Input @(0,1)) + '|' + ' '*(Get-Random -Input @(0,1)) + $InvokeExpression
    $NewScript = (Get-Random -Input $InvokeOptions)
    If(!$PSBoundParameters['PassThru'])
    {
        $PowerShellFlags = @()
        $CommandlineOptions = New-Object String[](0)
        If($PSBoundParameters['NoExit'])
        {
          $FullArgument = "-NoExit";
          $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 4 -Maximum ($FullArgument.Length+1)))
        }
        If($PSBoundParameters['NoProfile'])
        {
          $FullArgument = "-NoProfile";
          $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 4 -Maximum ($FullArgument.Length+1)))
        }
        If($PSBoundParameters['NonInteractive'])
        {
          $FullArgument = "-NonInteractive";
          $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 5 -Maximum ($FullArgument.Length+1)))
        }
        If($PSBoundParameters['NoLogo'])
        {
          $FullArgument = "-NoLogo";
          $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 4 -Maximum ($FullArgument.Length+1)))
        }
        If($PSBoundParameters['WindowStyle'] -OR $WindowsStyle)
        {
            $FullArgument = "-WindowStyle"
            If($WindowsStyle) {$ArgumentValue = $WindowsStyle}
            Else {$ArgumentValue = $PSBoundParameters['WindowStyle']}
            Switch($ArgumentValue.ToLower())
            {
                'normal'    {If(Get-Random -Input @(0..1)) {$ArgumentValue = (Get-Random -Input @('0','n','no','nor','norm','norma'))}}
                'hidden'    {If(Get-Random -Input @(0..1)) {$ArgumentValue = (Get-Random -Input @('1','h','hi','hid','hidd','hidde'))}}
                'minimized' {If(Get-Random -Input @(0..1)) {$ArgumentValue = (Get-Random -Input @('2','mi','min','mini','minim','minimi','minimiz','minimize'))}}
                'maximized' {If(Get-Random -Input @(0..1)) {$ArgumentValue = (Get-Random -Input @('3','ma','max','maxi','maxim','maximi','maximiz','maximize'))}}
                default {Write-Error "An invalid `$ArgumentValue value ($ArgumentValue) was passed to switch block for Out-PowerShellLauncher."; Exit;}
            }
            $PowerShellFlags += $FullArgument.SubString(0,(Get-Random -Minimum 2 -Maximum ($FullArgument.Length+1))) + ' '*(Get-Random -Minimum 1 -Maximum 3) + $ArgumentValue
        }
        If($PSBoundParameters['ExecutionPolicy'] -OR $ExecutionPolicy)
        {
            $FullArgument = "-ExecutionPolicy"
            If($ExecutionPolicy) {$ArgumentValue = $ExecutionPolicy}
            Else {$ArgumentValue = $PSBoundParameters['ExecutionPolicy']}
            $ExecutionPolicyFlags = @()
            $ExecutionPolicyFlags += '-EP'
            For($Index=3; $Index -le $FullArgument.Length; $Index++)
            {
                $ExecutionPolicyFlags += $FullArgument.SubString(0,$Index)
            }
            $ExecutionPolicyFlag = Get-Random -Input $ExecutionPolicyFlags
            $PowerShellFlags += $ExecutionPolicyFlag + ' '*(Get-Random -Minimum 1 -Maximum 3) + $ArgumentValue
        }
        If($CommandlineOptions.Count -gt 1)
        {
            $CommandlineOptions = Get-Random -InputObject $CommandlineOptions -Count $CommandlineOptions.Count
        }
        If($PSBoundParameters['Command'])
        {
            $FullArgument = "-Command"
            $CommandlineOptions += $FullArgument.SubString(0,(Get-Random -Minimum 2 -Maximum ($FullArgument.Length+1)))
        }
        For($i=0; $i -lt $PowerShellFlags.Count; $i++)
        {
            $PowerShellFlags[$i] = ([Char[]]$PowerShellFlags[$i] | ForEach-Object {$Char = $_.ToString().ToLower(); If(Get-Random -Input @(0..1)) {$Char = $Char.ToUpper()} $Char}) -Join ''
        }
        $CommandlineOptions = ($CommandlineOptions | ForEach-Object {$_ + " "*(Get-Random -Minimum 1 -Maximum 3)}) -Join ''
        $CommandlineOptions = " "*(Get-Random -Minimum 0 -Maximum 3) + $CommandlineOptions + " "*(Get-Random -Minimum 0 -Maximum 3)
        If($PSBoundParameters['Wow64'])
        {
            $CommandLineOutput = "C:\WINDOWS\SysWOW64\WindowsPowerShell\v1.0\powershell.exe $($CommandlineOptions) `"$NewScript`""
        }
        Else
        {
            $CommandLineOutput = "powershell $($CommandlineOptions) `"$NewScript`""
        }
        $CmdMaxLength = 8190
        If($CommandLineOutput.Length -gt $CmdMaxLength)
        {
                Write-Warning "This command exceeds the cmd.exe maximum allowed length of $CmdMaxLength characters! Its length is $($CmdLineOutput.Length) characters."
        }
        $NewScript = $CommandLineOutput
    }
    Return $NewScript
}
if ($Concat) {
$Dpath = (get-item -path ./).FullName
$DName = (Get-ChildItem $args[0] | select -ExpandProperty name).Trim(".ps1")
$OutPath = ($Dpath + '/tmp-obs.ps1')
$OutPath1 = ($Dpath + '/tmp-obs1.ps1')
$OutPath2 = ($Dpath + '/tmp-obs2.ps1')
$OutPath3 = ($Dpath + '/tmp-obs3.ps1')
$OutPath4 = ($DName + 'obs.ps1')
Out-ObfuscatedTokenCommand -Path $args[0] -TokenTypeToObfuscate String -ObfuscationLevel 1 | Out-File $OutPath
Out-ObfuscatedTokenCommand -Path $OutPath -TokenTypeToObfuscate Command -ObfuscationLevel 2 | Out-File $OutPath1
Out-ObfuscatedTokenCommand -Path $OutPath1 -TokenTypeToObfuscate CommandArgument -ObfuscationLevel 3 | Out-File $OutPath2
Out-ObfuscatedTokenCommand -Path $OutPath2 -TokenTypeToObfuscate Member -ObfuscationLevel 3 | Out-File $OutPath3
#Out-ObfuscatedTokenCommand -Path $Path -TokenTypeToObfuscate Variable -ObfuscationLevel 1 | Out-File $OutPath
Out-ObfuscatedTokenCommand -Path $OutPath3 -TokenTypeToObfuscate Type -ObfuscationLevel 1 | Out-File $OutPath4
Remove-Item $OutPath
Remove-Item $OutPath1
Remove-Item $OutPath2
Remove-Item $OutPath3
}
elseif ($Reorder) {
$Dpath = (get-item -path ./).FullName
$DName = (Get-ChildItem $args[0] | select -ExpandProperty name).Trim(".ps1")
$OutPath = ($Dpath + '/tmp-obs.ps1')
$OutPath1 = ($Dpath + '/tmp-obs1.ps1')
$OutPath2 = ($Dpath + '/tmp-obs2.ps1')
$OutPath3 = ($Dpath + '/tmp-obs3.ps1')
$OutPath4 = ($DName + 'obs.ps1')
Out-ObfuscatedTokenCommand -Path $args[0] -TokenTypeToObfuscate String -ObfuscationLevel 2 | Out-File $OutPath
Out-ObfuscatedTokenCommand -Path $OutPath -TokenTypeToObfuscate Command -ObfuscationLevel 3 | Out-File $OutPath1
Out-ObfuscatedTokenCommand -Path $OutPath1 -TokenTypeToObfuscate CommandArgument -ObfuscationLevel 4 | Out-File $OutPath2
Out-ObfuscatedTokenCommand -Path $OutPath2 -TokenTypeToObfuscate Member -ObfuscationLevel 4 | Out-File $OutPath3
#Out-ObfuscatedTokenCommand -Path $Path -TokenTypeToObfuscate Variable -ObfuscationLevel 1 | Out-File $OutPath
Out-ObfuscatedTokenCommand -Path $OutPath3 -TokenTypeToObfuscate Type -ObfuscationLevel 2 | Out-File $OutPath4
Remove-Item $OutPath 
Remove-Item $OutPath1 
Remove-Item $OutPath2 
Remove-Item $OutPath3 
}
