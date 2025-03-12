function Invoke-CIPPStandardIntuneTemplate {
    <#
    .FUNCTIONALITY
        Internal
    .COMPONENT
        (APIName) IntuneTemplate
    .SYNOPSIS
        (Label) Intune Template
    .DESCRIPTION
        (Helptext) Deploy and manage Intune templates across devices.
        (DocsDescription) Deploy and manage Intune templates across devices.
    .NOTES
        CAT
            Templates
        MULTIPLE
            True
        DISABLEDFEATURES

        IMPACT
            High Impact
        ADDEDDATE
            2023-12-30
        ADDEDCOMPONENT
            {"type":"autoComplete","multiple":false,"creatable":false,"name":"TemplateList","label":"Select Intune Template","api":{"url":"/api/ListIntuneTemplates","labelField":"Displayname","valueField":"GUID","queryKey":"languages"}}
            {"name":"AssignTo","label":"Who should this template be assigned to?","type":"radio","options":[{"label":"Do not assign","value":"On"},{"label":"Assign to all users","value":"allLicensedUsers"},{"label":"Assign to all devices","value":"AllDevices"},{"label":"Assign to all users and devices","value":"AllDevicesAndUsers"},{"label":"Assign to Custom Group","value":"customGroup"}]}
            {"type":"textField","required":false,"name":"customGroup","label":"Enter the custom group name if you selected 'Assign to Custom Group'. Wildcards are allowed."}
            {"name":"ExcludeGroup","label":"Exclude Groups","type":"textField","required":false,"helpText":"Enter the group name to exclude from the assignment. Wildcards are allowed."}
        UPDATECOMMENTBLOCK
            Run the Tools\Update-StandardsComments.ps1 script to update this comment block
    .LINK
        https://docs.cipp.app/user-documentation/tenant/standards/list-standards/
    #>
    param($Tenant, $Settings)
    ##$Rerun -Type Standard -Tenant $Tenant -Settings $Settings 'intuneTemplate'
    $Table = Get-CippTable -tablename 'templates'
    $Filter = "PartitionKey eq 'IntuneTemplate'"
    $Request = @{body = $null }
    $TenantList = Get-Tenants -TenantFilter $tenantFilter

    $CompareList = foreach ($Template in $Settings) {
        Write-Host "working on template: $($Template | ConvertTo-Json)"
        $Request.body = (Get-CIPPAzDataTableEntity @Table -Filter $Filter | Where-Object -Property RowKey -Like "$($Template.TemplateList.value)*").JSON | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($Request.body -eq $null) {
            Write-LogMessage -API 'Standards' -tenant $tenant -message "Failed to find template $($Template.TemplateList.value). Has this Intune Template been deleted?" -sev 'Error'
            continue
        }
        $displayname = $request.body.Displayname
        $description = $request.body.Description
        $RawJSON = $Request.body.RawJSON
        $ExistingPolicy = Get-CIPPIntunePolicy -tenantFilter $Tenant -DisplayName $displayname -TemplateType $Request.body.Type
        if ($ExistingPolicy) {
            $ReplaceTable = Get-CIPPTable -tablename 'CippReplacemap'
            $ReplaceMap = Get-CIPPAzDataTableEntity @ReplaceTable -Filter "PartitionKey eq '$tenant'"
            if ($ReplaceMap) {
                foreach ($Replace in $ReplaceMap) {
                    $String = '%{0}%' -f $Replace.RowKey
                    $RawJSON = $RawJSON -replace $String, $Replace.Value
                }
            }
            $RawJSON = $RawJSON -replace '%tenantid%', $TenantList.customerId
            $RawJSON = $RawJSON -replace '%tenantfilter%', $TenantLists.defaultDomainName
            $RawJSON = $RawJSON -replace '%tenantname%', $TenantList.displayName

            $JSONExistingPolicy = $ExistingPolicy.cippconfiguration | ConvertFrom-Json
            $JSONTemplate = $RawJSON | ConvertFrom-Json
            $Compare = Compare-CIPPIntuneObject -ReferenceObject $JSONTemplate -DifferenceObject $JSONExistingPolicy -compareType $Request.body.Type
            if ($Compare) {
                [PSCustomObject]@{
                    MatchFailed  = $true
                    displayname  = $displayname
                    description  = $description
                    compare      = $Compare
                    rawJSON      = $RawJSON
                    body         = $Request.body
                    assignTo     = $Template.AssignTo
                    excludeGroup = $Template.excludeGroup
                    remediate    = $Template.remediate
                }
            } else {
                [PSCustomObject]@{
                    MatchFailed  = $false
                    displayname  = $displayname
                    description  = $description
                    compare      = $Compare
                    rawJSON      = $RawJSON
                    body         = $Request.body
                    assignTo     = $Template.AssignTo
                    excludeGroup = $Template.excludeGroup
                    remediate    = $Template.remediate
                }
            }
        }
    }

    If ($Settings.remediate -eq $true) {
        Write-Host 'starting template deploy'
        foreach ($Template in $CompareList | Where-Object -Property remediate -EQ $true) {
            Write-Host "working on template deploy: $($Template | ConvertTo-Json)"
            try {
                $Template.customGroup ? ($Template.AssignTo = $Template.customGroup) : $null
                Set-CIPPIntunePolicy -TemplateType $Template.body.Type -Description $description -DisplayName $displayname -RawJSON $RawJSON -AssignTo $Template.AssignTo -ExcludeGroup $Template.excludeGroup -tenantFilter $Tenant

            } catch {
                $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
                Write-LogMessage -API 'Standards' -tenant $tenant -message "Failed to create or update Intune Template $PolicyName, Error: $ErrorMessage" -sev 'Error'
            }
        }

    }

    if ($Settings.alert) {
        foreach ($Template in $CompareList) {
            if ($Template.compare) {
                Write-LogMessage -API 'Standards' -tenant $Tenant -message "Template $($Template.displayname) does not match the expected configuration: $($template.compare | ConvertTo-Json)" -sev Alert
            } else {
                $ExistingPolicy ? (Write-LogMessage -API 'Standards' -tenant $Tenant -message "Template $($Template.displayname) has the correct configuration." -sev Info) : (Write-LogMessage -API 'Standards' -tenant $Tenant -message "Template $($Template.displayname) is missing." -sev Alert)
            }
        }
    }

    if ($Settings.report) {
        #think about how to store this.
        Add-CIPPBPAField -FieldName "policy-$displayname" -FieldValue $Compare -StoreAs bool -Tenant $tenant
    }
}
