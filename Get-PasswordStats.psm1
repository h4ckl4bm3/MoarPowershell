function Get-PasswordStats {
<#
.Synopsis
Provides a set of password statistics useful for reporting.

.Description
This cmdlet is designed to run a number of basic checks over a list of provided passwords, and provide useful data for reporting password
usage following a password dump.

.Example
Get-PasswordStats -filename "passwords.csv" -type "CSV" -delimiter ","

.Link
http://github.com/xpn/MoarPowershell
#>
param( 
[Parameter(Mandatory=$true)]
[string]$filename,

[Parameter(Mandatory=$true)]
[ValidateSet("CSV","TXT")]
[string]$type = "CSV",

[Parameter(Mandatory=$false)]
[string]$delimiter = ",",

[Parameter(Mandatory=$false)]
[string]$wordlist = "",

[Parameter(Mandatory=$false)]
[int]$minPassLen = 8
)
    $contents = Load-PasswordFile -filename $filename -type $type -delimiter $delimiter

    $reuse = Get-PasswordReuse -credentials $contents | Where-Object Count -ge 2
    $short = Get-ShortPasswords -credentials $contents | Where-Object Length -le $minPassLen
    $lower = Get-LowerAlphaPasswords -credentials $contents 
    $lowerUpper = Get-LowerUpperAlphaPasswords -credentials $contents

    if ($wordlist -ne "") {
        Write-Host "Checking passwords against wordlist.. this could take some time..."
        $wordlistPasswords = Get-WordlistPasswords -credentials $contents -wordlist $wordlist
    }

    Write-Host "Password which have been reused between accounts:"
    Write-Host ($reuse | Format-Table | Out-String)

    Write-Host "Short passwords:"
    Write-Host ($short | Format-Table | Out-String)

    Write-Host "Lowercase passwords:"
    Write-Host ($lower | Format-Table | Out-String)

    Write-Host "Lower and Uppercase passwords:"
    Write-Host ($lowerUpper | Format-Table | Out-String)

    if ($wordlist) {
        Write-Host "Passwords found in wordlist:"
        Write-Host ($wordlistPasswords | Format-Table | Out-String)
    }
}

function Load-PasswordFile {
param(
[string]$filename,
[string]$type = "CSV",
[string]$delimiter = ","
)

    switch($type) {
        "CSV" { 
            $contents = Import-CSV -Path $filename -Delimiter $delimiter | Select-Object @{Name="Username";Expression={$_.Username.Trim()}}, @{Name="Password";Expression={$_.Password.Trim()}}
         }
        "TXT" { 
            $contents = Get-Content -Path $filename | Select-Object @{Name="Password";Expression={$_.Trim()}} 
         }
    default { }
    }

    return $contents
}


function Get-PasswordReuse {
param(
[object]$credentials
)
    $credentials | Group-Object {$_.Password} | Sort-Object -Property Count -Descending | Select-Object -Property Name, Count
}


function Get-ShortPasswords {
param(
[object]$credentials
)
    $credentials | Select-Object @{Name="Password";Expression={$_.Password}}, @{Name="Length";Expression={$_.Password.Trim().Length}} | Sort-Object Length
}

function Filter-Passwords {
param(
[object]$credentials,
[string]$filter
)
    $credentials | Where-Object Password -cmatch $filter
}

function Get-LowerAlphaPasswords {
param(
[object]$credentials
)
    Filter-Passwords $credentials "^[a-z]+$" 
}

function Get-LowerUpperAlphaPasswords {
param(
[object]$credentials
)

    Filter-Passwords $credentials "^[a-zA-Z]+$" 
}

function Get-WordlistPasswords {
param(
[object[]]$credentials,
[string]$wordlist
)
    $found = @()

    foreach ($line in [System.IO.File]::ReadLines($wordlist)) { 
        foreach($pass in $credentials.Password) { 
            if ($line -eq "${pass}") {
                if (!$found.Contains($pass)) {
                    $found += $pass
                }
            }
         }
         
         if ($found.Count -eq $credentials.Count) {
            break;
         }
     }

     return $found
}

Export-ModuleMember Get-PasswordStats