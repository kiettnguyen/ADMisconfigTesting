Import-Module ActiveDirectory
function Get-MTUserPasswordPolicy ($Identity)
{
    $Fgpp = (Get-ADUserResultantPasswordPolicy -Identity $Identity).Name
    [string]$Policy = switch ($Fgpp)
    {
        $null {"Default Domain Policy"}
        {!($null)} {$Fgpp}
    }
    
    $Return = New-Object -TypeName PSObject
    $Return | Add-Member -MemberType NoteProperty -Name Identity -Value $Identity
    $Return | Add-Member -MemberType NoteProperty -Name PasswordPolicy -Value $Policy
    
    return $Return
}

Get-ADUser -Filter {Enabled -eq $True} | ForEach-Object {Get-MTUserPasswordPolicy -Identity $_.SamAccountName}
# Get all domains in the forest
$domains = Get-ADForest | Select-Object -ExpandProperty Domains
foreach ($domain in $domains) {
Write-Host "Password Policies for $domain :"
Write-Host "--------------------------------"
# Get the default domain password policy
$defaultDomainPolicy = Get-ADDefaultDomainPasswordPolicy -Server $domain
Write-Host "Default Domain Password Policy:"
Write-Host " Minimum Password Length: $($defaultDomainPolicy.MinPasswordLength)"
Write-Host " Password History Length: $($defaultDomainPolicy.PasswordHistoryCount)"
Write-Host " Maximum Password Age: $($defaultDomainPolicy.MaxPasswordAge.Days) days"
Write-Host " Minimum Password Age: $($defaultDomainPolicy.MinPasswordAge.Days) days"
Write-Host " Complexity Enabled: $($defaultDomainPolicy.ComplexityEnabled)"
Write-Host " Reversible Encryption Enabled: $($defaultDomainPolicy.ReversibleEncryptionEnabled)"
Write-Host ""
}