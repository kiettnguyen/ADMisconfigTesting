Import-Module ActiveDirectory

$adminSDHolderDN = "CN=AdminSDHolder,CN=System,$((Get-ADRootDSE).defaultNamingContext)"

$acl = Get-Acl -Path "AD:\$adminSDHolderDN" 
Write-Host $adminSDHolderDN

# Define the access mask for WriteProperty
$InterestingRights = @(
    [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty
    #[System.DirectoryServices.ActiveDirectoryRights]::WriteDacl,
    #[System.DirectoryServices.ActiveDirectoryRights]::WriteOwner,
    #[System.DirectoryServices.ActiveDirectoryRights]::GenericWrite,
    #[System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
    #[System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
    #[System.DirectoryServices.ActiveDirectoryRights]::CreateChild
)

# Initialize the variable to hold ACEs
$writePropertyACEs = @()

# Loop through each interesting right and filter ACEs
for ($i=0; $i -lt $InterestingRights.Length; $i++) {
    $InterestingACEs = $acl.Access | Where-Object {
        $_.AccessControlType -eq 'Allow' -and ($_.ActiveDirectoryRights -band $InterestingRights[$i] -ne 0)
    }
    Write-Host "Testing " $InterestingRights[$i]
    $InterestingACEs | Select-Object IdentityReference, ActiveDirectoryRights, AccessControlType
    
    
}

# Get the non-admin users from the filtered ACEs
$nonAdminUsers = $writePropertyACEs | Where-Object { $_.IdentityReference.Value -notlike "*Admin*" }

# Display the non-admin users who can write to the AdminSDHolder
$nonAdminUsers | Select-Object IdentityReference, ActiveDirectoryRights, AccessControlType
