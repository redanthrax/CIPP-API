function Test-CIPPAPIClientAccess {
    param(
        $Request,
        $DefaultRoles,
        $BaseRoles
    )
    
    # Direct API Access
    $ForwardedFor = $Request.Headers.'x-forwarded-for' -split ',' | Select-Object -First 1
    $IPRegex = '^(?<IP>(?:\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-fA-F:]+\]|[0-9a-fA-F:]+))(?:\d+)?$'
    $IPAddress = $ForwardedFor -replace $IPRegex, '$1' -replace '[\[\]]', ''

    $Client = Get-CippApiClient -AppId $Request.Headers.'x-ms-client-principal-name'
    
    if ($Client) {
        Write-Information "API Access: AppName=$($Client.AppName), AppId=$($Request.Headers.'x-ms-client-principal-name'), IP=$IPAddress"
        
        # Validate IP address
        $IPMatched = $false
        if ($Client.IPRange -notcontains 'Any') {
            foreach ($Range in $Client.IPRange) {
                if ($IPaddress -eq $Range -or (Test-IpInRange -IPAddress $IPAddress -Range $Range)) {
                    $IPMatched = $true
                    break
                }
            }
        } else {
            $IPMatched = $true
        }

        if (!$IPMatched) {
            throw 'Access to this CIPP API endpoint is not allowed, the API Client does not have the required permission'
        }

        # Get roles
        if ($Client.Role) {
            $CustomRoles = $Client.Role | Where-Object { $DefaultRoles -notcontains $_ }
            $BaseRole = $null
            foreach ($Role in $BaseRoles.PSObject.Properties) {
                if ($Client.Role -contains $Role.Name) {
                    $BaseRole = $Role
                    break
                }
            }
        } else {
            $CustomRoles = @('cipp-api')
            $BaseRole = $null
        }
    } else {
        $CustomRoles = @('cipp-api')
        $BaseRole = $null
        Write-Information "API Access: AppId=$($Request.Headers.'x-ms-client-principal-name'), IP=$IPAddress"
    }

    return @{
        CustomRoles = $CustomRoles
        BaseRole = $BaseRole
    }
}
