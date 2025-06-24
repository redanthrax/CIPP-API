function Test-CIPPUserAccess {
    param(
        $Request,
        $DefaultRoles,
        $BaseRoles,
        [switch]$TenantList
    )
    
    $User = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Request.Headers.'x-ms-client-principal')) | ConvertFrom-Json

    # Check for roles granted via group membership
    if (($User.userRoles | Measure-Object).Count -eq 2 -and $User.userRoles -contains 'authenticated' -and $User.userRoles -contains 'anonymous') {
        $User = Test-CIPPAccessUserRole -User $User
    }

    # Handle 'me' endpoint
    if ($Request.Params.CIPPEndpoint -eq 'me') {
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = (@{ 'clientPrincipal' = $User } | ConvertTo-Json -Depth 5)
        })
        return @{ IsEarlyReturn = $true; Value = $null }
    }

    # Admin/superadmin tenant list handling
    if (($User.userRoles -contains 'admin' -or $User.userRoles -contains 'superadmin') -and $TenantList.IsPresent) {
        return @{ IsEarlyReturn = $true; Value = @('AllTenants') }
    }

    # Get custom roles
    $CustomRoles = $User.userRoles | Where-Object { $DefaultRoles -notcontains $_ }

    # Simplify user roles for base role lookup
    if ($User.userRoles -contains 'superadmin') {
        $User.userRoles = @('superadmin')
    } elseif ($User.userRoles -contains 'admin') {
        $User.userRoles = @('admin')
    }

    # Find base role
    $BaseRole = $null
    foreach ($Role in $BaseRoles.PSObject.Properties) {
        if ($User.userRoles -contains $Role.Name) {
            $BaseRole = $Role
            break
        }
    }

    return @{
        IsEarlyReturn = $false
        CustomRoles = $CustomRoles
        BaseRole = $BaseRole
    }
}
