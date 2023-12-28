# Get all groups that have "admin" in their name
$adminGroups = Get-ADGroup -Filter {Name -like '*admin*'}

foreach ($group in $adminGroups) {
    # Translate the group's name to Security Identifier (SID)
    $groupSID = $group.SID.Translate([System.Security.Principal.SecurityIdentifier]).Value
    Write-Host "$($group.Name) SID: $groupSID"

    #Add the group SID to the array
    $adminGroupSIDs += $groupSID

    # Get the members of the group
    $groupMembers = Get-ADGroupMember -Identity $group

    if ($groupMembers.count -eq 0){
        continue
    }
    foreach ($member in $groupMembers) {
        if(($member.UserAccountControl -band 0x1000000) -eq 0x1000000){
            Write-Output -ForegroundColor Red "$($user.SamAccountName) in $($group) has 'Account is sensitive and cannot be delegated' selected." 
        } else {
            #Write-Output "$($user.SamAccountName) in $($group) does not have 'Account is sensitive and cannot be delegated' selected." 
        }
        Write-Host "   Member: $($member.Name) ($($member.SamAccountName))"
    }
}

$enterpriseAdminsSID = (New-Object System.Security.Principal.NTAccount("Enterprise Admins")).Translate([System.Security.Principal.SecurityIdentifier]).Value
$DomainAdminsSID = (New-Object System.Security.Principal.NTAccount("Domain Admins")).Translate([System.Security.Principal.SecurityIdentifier]).Value

$EnterprisegroupMembers = Get-ADGroupMember -Identity "Enterprise Admins"
$DomainAdmingroupMembers =  Get-ADGroupMember -Identity "Domain Admins"


# Get the members of the "Enterprise Admins" group
$enterpriseAdminsMembers = Get-ADGroupMember -Identity "Enterprise Admins"

# Iterate through each admin group
foreach ($adminGroupName in $adminGroups) {
    $adminGroupMembers = Get-ADGroupMember -Identity $adminGroupName

    if($adminGroupMembers.Count -eq 0) {
      continue
    }
    # Compare members of "Enterprise Admins" with the current admin group
    $commonMembers = Compare-Object -ReferenceObject $enterpriseAdminsMembers -DifferenceObject $adminGroupMembers -Property SamAccountName -IncludeEqual | Where-Object { $_.SideIndicator -eq '==' }

    # Display the common members
    foreach ($commonMember in $commonMembers) {
        if ($adminGroupName.Name -ne "Enterprise Admins" -and $commonMember.SamAccountName -ne "Administrator"){
            Write-Host -ForegroundColor Red "[HIGH]Membership to the Enterprise Admins group must be restricted to accounts used only to manage the Active Directory Forest."
            Write-Host "User $($commonMember.SamAccountName) is a member of Enterprise Admins and" $adminGroupName.Name 
        }
    }
}


# Get the members of the "Enterprise Admins" group
$DomainAdminMembers = Get-ADGroupMember -Identity "Domain Admins"

# Iterate through each admin group
foreach ($adminGroupName in $adminGroups) {
    $adminGroupMembers = Get-ADGroupMember -Identity $adminGroupName

    if($adminGroupMembers.Count -eq 0) {
      continue
    }
    # Compare members of "Enterprise Admins" with the current admin group
    $commonMembers = Compare-Object -ReferenceObject $DomainAdminMembers -DifferenceObject $adminGroupMembers -Property SamAccountName -IncludeEqual | Where-Object { $_.SideIndicator -eq '==' }

    # Display the common members
    foreach ($commonMember in $commonMembers) {
        if ($adminGroupName.Name -ne "Domain Admins" -and $commonMember.SamAccountName -ne "Administrator"){
            Write-Host -ForegroundColor Red "[HIGH]Membership to the Domain Admins group must be restricted to accounts used only to manage the Active Directory Forest."
            Write-Host "User $($commonMember.SamAccountName) is a member of Domain Admins and" $adminGroupName.Name 
        }
    }
}