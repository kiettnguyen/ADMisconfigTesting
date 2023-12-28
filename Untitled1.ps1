$adminSDHolderDN = "CN=AdminSDHolder,CN=System,$((Get-ADRootDSE).defaultNamingContext)"
$securityPrincipal = "FORESTDOMAIN\tknguyen"
$permissions = "FullControl"

$acl = Get-Acl -Path "AD:\$adminSDHolderDN"
$identityReference = New-Object System.Security.Principal.NTAccount($securityPrincipal)
$accessMask = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
$inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
$accessControlType = [System.Security.AccessControl.AccessControlType]::Allow

$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identityReference, $accessMask, $inheritanceType, $null, $accessControlType)
$acl.AddAccessRule($ace)

# Set the modified ACL back to the object
Set-Acl -Path "AD:\$adminSDHolderDN" -AclObject $acl