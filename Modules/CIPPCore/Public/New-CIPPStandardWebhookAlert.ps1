function New-CIPPStandardWebhookAlert {
    <#
    .SYNOPSIS
    Creates a standardized webhook alert JSON body for all CIPP alert types
    
    .DESCRIPTION
    This function standardizes the JSON body format sent to webhooks for alerts,
    ensuring consistency across all alert types while maintaining backward compatibility.
    
    .PARAMETER AlertType
    The type of alert being sent (AuditLog, ScheduledTask, Notification, Log, etc.)
    
    .PARAMETER Title
    The alert title/subject
    
    .PARAMETER Message
    The main alert message/description
    
    .PARAMETER Severity
    Alert severity level (Info, Warning, Error, Critical, Alert)
    
    .PARAMETER TenantFilter
    The tenant domain name
    
    .PARAMETER TenantId
    The tenant GUID
    
    .PARAMETER Data
    The raw data associated with the alert
    
    .PARAMETER ActionUrl
    Optional URL for action button
    
    .PARAMETER ActionText
    Optional text for action button
    
    .PARAMETER ActionsTaken
    Array of actions that were automatically taken
    
    .PARAMETER LocationInfo
    Location information if available
    
    .PARAMETER CIPPURL
    The CIPP instance URL
    
    .EXAMPLE
    $AlertBody = New-CIPPStandardWebhookAlert -AlertType "AuditLog" -Title "New Inbox Rule" -Message "User created suspicious rule" -Severity "Alert" -TenantFilter "contoso.com" -Data $AuditData
    
    .NOTES
    This function creates a consistent webhook JSON format while preserving all necessary data
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('AuditLog', 'ScheduledTask', 'Notification', 'Log', 'Standard', 'PartnerCenter', 'Custom')]
        [string]$AlertType,
        
        [Parameter(Mandatory = $true)]
        [string]$Title,
        
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Critical', 'Alert')]
        [string]$Severity = 'Info',
        
        [Parameter(Mandatory = $false)]
        [string]$TenantFilter,
        
        [Parameter(Mandatory = $false)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $false)]
        [object]$Data,
        
        [Parameter(Mandatory = $false)]
        [string]$ActionUrl,
        
        [Parameter(Mandatory = $false)]
        [string]$ActionText,
        
        [Parameter(Mandatory = $false)]
        [array]$ActionsTaken,
        
        [Parameter(Mandatory = $false)]
        [object]$LocationInfo,
        
        [Parameter(Mandatory = $false)]
        [string]$CIPPURL
    )
    
    # Create standardized webhook alert structure
    $StandardAlert = [PSCustomObject]@{
        # Standard metadata fields (always present)
        alertId       = [string](New-Guid)
        timestamp     = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        version       = '1.0'
        alertType     = $AlertType
        severity      = $Severity
        
        # Core alert content
        title         = $Title
        message       = $Message
        
        # Tenant information
        tenant        = @{
            domain = $TenantFilter
            id     = $TenantId
        }
        
        # Action information (if applicable)
        actions       = @{
            url         = $ActionUrl
            text        = $ActionText
            taken       = @($ActionsTaken)
        }
        
        # Raw data and context
        data          = $Data
        locationInfo  = $LocationInfo
        
        # CIPP metadata
        cipp          = @{
            url     = $CIPPURL
            source  = 'CIPP-API'
        }
    }
    
    # Remove null/empty fields to keep JSON clean
    $CleanedAlert = Remove-EmptyProperties -InputObject $StandardAlert
    
    return $CleanedAlert
}

function Remove-EmptyProperties {
    param([object]$InputObject)
    
    if ($InputObject -is [PSCustomObject]) {
        $CleanedObject = [PSCustomObject]@{}
        foreach ($Property in $InputObject.PSObject.Properties) {
            $Value = $Property.Value
            if ($null -ne $Value) {
                if ($Value -is [PSCustomObject]) {
                    $CleanedValue = Remove-EmptyProperties -InputObject $Value
                    if ($CleanedValue.PSObject.Properties.Count -gt 0) {
                        $CleanedObject | Add-Member -MemberType NoteProperty -Name $Property.Name -Value $CleanedValue
                    }
                } elseif ($Value -is [array] -and $Value.Count -gt 0) {
                    $CleanedObject | Add-Member -MemberType NoteProperty -Name $Property.Name -Value $Value
                } elseif ($Value -is [string] -and -not [string]::IsNullOrWhiteSpace($Value)) {
                    $CleanedObject | Add-Member -MemberType NoteProperty -Name $Property.Name -Value $Value
                } elseif ($Value -is [string] -eq $false) {
                    $CleanedObject | Add-Member -MemberType NoteProperty -Name $Property.Name -Value $Value
                }
            }
        }
        return $CleanedObject
    }
    
    return $InputObject
}
