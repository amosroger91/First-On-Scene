<#
.SYNOPSIS
    Manages OpenRouter API token securely using Windows Credential Manager.
.DESCRIPTION
    Provides functions to store, retrieve, and prompt for OpenRouter API tokens
    using Windows Credential Manager for secure storage.
.OUTPUTS
    Returns API token as SecureString or plain text as needed.
#>

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Get", "Set", "Prompt")]
    [string]$Action = "Get"
)

$CredentialTarget = "FirstOnScene_OpenRouter_API"

function Get-StoredAPIToken {
    <#
    .SYNOPSIS
        Retrieves stored API token from Windows Credential Manager.
    #>
    try {
        $credential = Get-StoredCredential -Target $CredentialTarget -ErrorAction Stop
        if ($credential) {
            # Return the password (which is the API token)
            return $credential.GetNetworkCredential().Password
        }
    }
    catch {
        return $null
    }
}

function Set-APIToken {
    <#
    .SYNOPSIS
        Stores API token in Windows Credential Manager.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Token
    )

    try {
        # Create credential object
        $secureToken = ConvertTo-SecureString -String $Token -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential("OpenRouter_API_Token", $secureToken)

        # Store in Windows Credential Manager
        # Use cmdkey for native Windows credential storage
        $null = & cmdkey.exe /generic:$CredentialTarget /user:"OpenRouter_API_Token" /pass:$Token

        if ($LASTEXITCODE -eq 0) {
            Write-Host "API token stored securely in Windows Credential Manager." -ForegroundColor Green
            return $true
        }
        else {
            Write-Warning "Failed to store API token. Exit code: $LASTEXITCODE"
            return $false
        }
    }
    catch {
        Write-Error "Error storing API token: $_"
        return $false
    }
}

function Get-StoredCredential {
    <#
    .SYNOPSIS
        Retrieves credential from Windows Credential Manager using cmdkey.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Target
    )

    try {
        # Query Windows Credential Manager
        $cmdkeyOutput = & cmdkey.exe /list:$Target 2>&1

        if ($cmdkeyOutput -match "Target: (.+)") {
            # Credential exists, now retrieve it using PowerShell's built-in method
            # Note: cmdkey doesn't directly output passwords, we need to use a different approach

            # Use CredentialManager module if available, otherwise use direct Windows API
            if (Get-Module -ListAvailable -Name CredentialManager) {
                Import-Module CredentialManager
                return Get-StoredCredential -Target $Target
            }
            else {
                # Fallback: Use direct registry/credential access
                # For Windows Credential Manager, we'll use a C# helper
                Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public class CredentialHelper
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CREDENTIAL
    {
        public int Flags;
        public int Type;
        public string TargetName;
        public string Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public int CredentialBlobSize;
        public IntPtr CredentialBlob;
        public int Persist;
        public int AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CredRead(string target, int type, int reservedFlag, out IntPtr credentialPtr);

    [DllImport("advapi32.dll")]
    public static extern void CredFree(IntPtr cred);

    public static string GetPassword(string target)
    {
        IntPtr credPtr;
        if (CredRead(target, 1, 0, out credPtr))
        {
            CREDENTIAL cred = (CREDENTIAL)Marshal.PtrToStructure(credPtr, typeof(CREDENTIAL));
            byte[] passwordBytes = new byte[cred.CredentialBlobSize];
            Marshal.Copy(cred.CredentialBlob, passwordBytes, 0, cred.CredentialBlobSize);
            string password = Encoding.Unicode.GetString(passwordBytes);
            CredFree(credPtr);
            return password;
        }
        return null;
    }
}
"@
                $password = [CredentialHelper]::GetPassword($Target)
                if ($password) {
                    $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
                    return New-Object System.Management.Automation.PSCredential("OpenRouter_API_Token", $securePassword)
                }
            }
        }
        return $null
    }
    catch {
        return $null
    }
}

function Prompt-ForAPIToken {
    <#
    .SYNOPSIS
        Prompts user for API token and stores it securely.
    #>
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  OpenRouter API Token Required" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "To use the Qwen3 235B model via OpenRouter, you need an API token."
    Write-Host "Get your free API token at: https://openrouter.ai/keys" -ForegroundColor Yellow
    Write-Host ""

    $token = Read-Host "Please enter your OpenRouter API token (or press Enter to skip)"

    if ([string]::IsNullOrWhiteSpace($token)) {
        Write-Warning "No API token provided. Cannot proceed with AI analysis."
        return $null
    }

    # Validate token format (basic check)
    if ($token.Length -lt 20) {
        Write-Warning "Token appears invalid (too short). Please verify your token."
        $confirm = Read-Host "Continue anyway? (y/n)"
        if ($confirm -ne "y") {
            return $null
        }
    }

    # Store the token
    $stored = Set-APIToken -Token $token

    if ($stored) {
        Write-Host "Token stored successfully!" -ForegroundColor Green
        return $token
    }
    else {
        Write-Warning "Failed to store token, but will use it for this session."
        return $token
    }
}

# Main execution based on action
switch ($Action) {
    "Get" {
        $token = Get-StoredAPIToken
        if ($token) {
            return $token
        }
        else {
            Write-Host "No stored API token found." -ForegroundColor Yellow
            return $null
        }
    }
    "Set" {
        $token = Read-Host "Enter OpenRouter API token"
        Set-APIToken -Token $token
    }
    "Prompt" {
        # Check for existing token first
        $existingToken = Get-StoredAPIToken
        if ($existingToken) {
            Write-Host "Found existing API token." -ForegroundColor Green
            # In non-interactive contexts, Read-Host returns empty string, so we default to "y"
            $useExisting = Read-Host "Use existing token? (y/n) [default: y]"
            # If empty (non-interactive) or "y", use existing token
            if ([string]::IsNullOrWhiteSpace($useExisting) -or $useExisting -eq "y" -or $useExisting -eq "Y") {
                Write-Host "Using stored API token." -ForegroundColor Green
                return $existingToken
            }
        }
        return Prompt-ForAPIToken
    }
}
