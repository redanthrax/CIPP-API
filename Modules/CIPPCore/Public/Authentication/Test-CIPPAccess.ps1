function Test-CIPPAccess {
    param(
        $Request,
        [switch]$TenantList
    )

    # Early return for ExecSAMSetup endpoint
    if ($Request.Params.CIPPEndpoint -eq 'ExecSAMSetup') { 
        return $true 
    }

    # Get function help and role
    $FunctionName = 'Invoke-{0}' -f $Request.Params.CIPPEndpoint
    try {
        $Help = Get-Help $FunctionName -ErrorAction Stop
    } catch {
        $Help = $null
    }

    $APIRole = $Help.Role
    
    # Early return for public endpoints
    if ($APIRole -eq 'Public') {
        return $true
    }

    # Get default roles from config (only once)
    $CIPPCoreModuleRoot = Get-Module -Name CIPPCore | Select-Object -ExpandProperty ModuleBase
    $CIPPRoot = (Get-Item $CIPPCoreModuleRoot).Parent.Parent
    $BaseRoles = Get-Content -Path $CIPPRoot\Config\cipp-roles.json | ConvertFrom-Json
    $DefaultRoles = @('superadmin', 'admin', 'editor', 'readonly', 'anonymous', 'authenticated')

    # Determine authentication type and get roles
    if ($Request.Headers.'x-ms-client-principal-idp' -eq 'aad' -and $Request.Headers.'x-ms-client-principal-name' -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
        # API Client authentication
        $Type = 'APIClient'
        $Result = Test-CIPPAPIClientAccess -Request $Request -DefaultRoles $DefaultRoles -BaseRoles $BaseRoles
        $CustomRoles = $Result.CustomRoles
        $BaseRole = $Result.BaseRole
    } else {
        # User authentication
        $Type = 'User'
        $Result = Test-CIPPUserAccess -Request $Request -DefaultRoles $DefaultRoles -BaseRoles $BaseRoles -TenantList:$TenantList
        if ($Result.IsEarlyReturn) {
            return $Result.Value
        }
        $CustomRoles = $Result.CustomRoles
        $BaseRole = $Result.BaseRole
    }

    # Validate base role permissions
    if ($null -ne $BaseRole -and !(Test-CIPPBaseRolePermission -BaseRole $BaseRole -APIRole $APIRole)) {
        throw "Access to this CIPP API endpoint is not allowed, the '$($BaseRole.Name)' base role does not have the required permission: $APIRole"
    }

    # Handle cases with no base role and no custom roles for users
    if ($null -eq $BaseRole.Name -and $Type -eq 'User' -and ($CustomRoles | Measure-Object).Count -eq 0) {
        throw 'Access to this CIPP API endpoint is not allowed, the user does not have the required permission'
    }

    # Process custom roles if they exist
    if (($CustomRoles | Measure-Object).Count -gt 0) {
        return Test-CIPPCustomRoleAccess -CustomRoles $CustomRoles -BaseRole $BaseRole -APIRole $APIRole -Request $Request -Help $Help -TenantList:$TenantList
    }

    # Default fallback
    if ($TenantList.IsPresent) {
        return @('AllTenants')
    }
    
    return $true
}
