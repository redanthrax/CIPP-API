function Test-CIPPCustomRoleAccess {
    param(
        $CustomRoles,
        $BaseRole,
        $APIRole,
        $Request,
        $Help,
        [switch]$TenantList
    )
    
    # Admin/superadmin bypass
    if (@('admin', 'superadmin') -contains $BaseRole.Name) {
        return $true
    }
    
    $Tenants = Get-Tenants -IncludeErrors
    $PermissionsFound = $false
    $PermissionSet = @()
    
    # Get permissions for all custom roles
    foreach ($CustomRole in $CustomRoles) {
        try {
            $Permission = Get-CIPPRolePermissions -Role $CustomRole
            $PermissionSet += $Permission
            $PermissionsFound = $true
        } catch {
            Write-Information $_.Exception.Message
            continue
        }
    }
    
    if (!$PermissionsFound) {
        # No permissions found for any roles - allow all
        return if ($TenantList.IsPresent) { @('AllTenants') } else { $true }
    }
    
    # Handle tenant list requests
    if ($TenantList.IsPresent) {
        $LimitedTenantList = @()
        foreach ($Permission in $PermissionSet) {
            if ((($Permission.AllowedTenants | Measure-Object).Count -eq 0 -or $Permission.AllowedTenants -contains 'AllTenants') -and (($Permission.BlockedTenants | Measure-Object).Count -eq 0)) {
                $LimitedTenantList += 'AllTenants'
            } else {
                $AllowedTenants = $Permission.AllowedTenants
                if ($AllowedTenants -contains 'AllTenants') {
                    $AllowedTenants = $Tenants.customerId
                }
                $LimitedTenantList += $AllowedTenants | Where-Object { $Permission.BlockedTenants -notcontains $_ }
            }
        }
        return $LimitedTenantList | Select-Object -Unique
    }
    
    # Validate API and tenant access
    $APIAllowed = $false
    $TenantAllowed = $false
    
    foreach ($Role in $PermissionSet) {
        # Check API permissions
        foreach ($Perm in $Role.Permissions) {
            if ($Perm -match $APIRole) {
                $APIAllowed = $true
                break
            }
        }
        
        if ($APIAllowed) {
            # Get tenant filter from various sources
            $TenantFilter = $Request.Query.tenantFilter ?? 
                           $Request.Body.tenantFilter ?? 
                           $Request.Body.tenantFilter.value ?? 
                           $Request.Query.tenantId ?? 
                           $Request.Body.tenantId ?? 
                           $Request.Body.tenantId.value ?? 
                           $env:TenantID
            
            # Check tenant level access
            if (($Role.BlockedTenants | Measure-Object).Count -eq 0 -and $Role.AllowedTenants -contains 'AllTenants') {
                $TenantAllowed = $true
                break
            } elseif ($TenantFilter -eq 'AllTenants') {
                $TenantAllowed = $false
                continue
            } else {
                $Tenant = ($Tenants | Where-Object { $TenantFilter -eq $_.customerId -or $TenantFilter -eq $_.defaultDomainName }).customerId
                
                $AllowedTenants = if ($Role.AllowedTenants -contains 'AllTenants') { 
                    $Tenants.customerId 
                } else { 
                    $Role.AllowedTenants 
                }
                
                if ($Tenant) {
                    $TenantAllowed = $AllowedTenants -contains $Tenant -and $Role.BlockedTenants -notcontains $Tenant
                    if ($TenantAllowed) { break }
                } else {
                    $TenantAllowed = $true
                    break
                }
            }
        }
    }
    
    if (!$APIAllowed) {
        throw "Access to this CIPP API endpoint is not allowed, you do not have the required permission: $APIRole"
    }
    
    if (!$TenantAllowed -and $Help.Functionality -notmatch 'AnyTenant') {
        throw 'Access to this tenant is not allowed'
    }
    
    return $true
}
