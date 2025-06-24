using namespace System.Net

function Invoke-ExecAddAlert {
    <#
    .FUNCTIONALITY
        Entrypoint,AnyTenant
    .ROLE
        CIPP.Alert.ReadWrite
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    Write-LogMessage -headers $Headers -API $APIName -message 'Accessed this API' -Sev 'Debug'

    $Severity = 'Alert'

    $Result = if ($Request.Body.sendEmailNow -or $Request.Body.sendWebhookNow -eq $true -or $Request.Body.writeLog -eq $true -or $Request.Body.sendPsaNow -eq $true) {
        $sev = ([pscustomobject]$Request.body.Severity).value -join (',')
        if ($Request.body.email -or $Request.body.webhook) {
            Write-Host 'found config, setting'
            $config = @{
                email             = $Request.body.email
                webhook           = $Request.body.webhook
                onepertenant      = $Request.body.onePerTenant
                logsToInclude     = $Request.body.logsToInclude
                sendtoIntegration = $true
                sev               = $sev
            }
            Write-Host "setting notification config to $($config | ConvertTo-Json)"
            $Results = Set-cippNotificationConfig @Config
            Write-Host $Results
        }
        $Title = 'CIPP Notification Test'
        if ($Request.Body.sendEmailNow -eq $true) {
            $CIPPAlert = @{
                Type        = 'email'
                Title       = $Title
                HTMLContent = $Request.Body.text
            }
            Send-CIPPAlert @CIPPAlert
        }
        if ($Request.Body.sendWebhookNow -eq $true) {
            # Get CIPP URL for action links
            $CippConfigTable = Get-CippTable -tablename Config
            $CippConfig = Get-CIPPAzDataTableEntity @CippConfigTable -Filter "PartitionKey eq 'InstanceProperties' and RowKey eq 'CIPPURL'"
            $CIPPURL = if ($CippConfig.Value) { 'https://{0}' -f $CippConfig.Value } else { $null }
            
            # Create standardized webhook alert
            $StandardAlert = New-CIPPStandardWebhookAlert -AlertType 'Notification' -Title $Title -Message $Request.Body.text -Severity 'Info' -CIPPURL $CIPPURL
            
            $CIPPAlert = @{
                Type        = 'webhook'
                Title       = $Title
                JSONContent = ($StandardAlert | ConvertTo-Json -Depth 20)
            }
            Send-CIPPAlert @CIPPAlert
        }
        if ($Request.Body.sendPsaNow -eq $true) {
            $CIPPAlert = @{
                Type        = 'psa'
                Title       = $Title
                HTMLContent = $Request.Body.text
            }
            Send-CIPPAlert @CIPPAlert
        }

        if ($Request.Body.writeLog -eq $true) {
            Write-LogMessage -headers $Headers -API 'Alerts' -message $Request.Body.text -Sev $Severity
            'Successfully generated alert.'
        }
    } else {
        Write-LogMessage -headers $Headers -API 'Alerts' -message $Request.Body.text -Sev $Severity
        'Successfully generated alert.'
    }
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = $Result
        })
}
