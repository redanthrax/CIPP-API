function Test-CIPPBaseRolePermission {
    param(
        $BaseRole,
        $APIRole
    )
    
    Write-Information "Base Role: $($BaseRole.Name)"
    
    $BaseRoleAllowed = $false
    
    # Check includes
    foreach ($Include in $BaseRole.Value.include) {
        if ($APIRole -like $Include) {
            $BaseRoleAllowed = $true
            break
        }
    }
    
    # Check excludes (overrides includes)
    foreach ($Exclude in $BaseRole.Value.exclude) {
        if ($APIRole -like $Exclude) {
            $BaseRoleAllowed = $false
            break
        }
    }

    return $BaseRoleAllowed
}
