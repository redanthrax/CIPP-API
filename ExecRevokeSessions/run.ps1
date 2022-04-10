using namespace System.Net

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

$APIName = $TriggerMetadata.FunctionName
Log-Request -user $request.headers.'x-ms-client-principal' -API $APINAME  -message "Accessed this API" -Sev "Debug"

# Interact with query parameters or the body of the request.
$TenantFilter = $Request.Query.TenantFilter
try {
      $GraphRequest = New-GraphPostRequest -uri "https://graph.microsoft.com/beta/users/$($Request.query.ID)/invalidateAllRefreshTokens" -tenantid $TenantFilter -type GET  -verbose
      $Results = [pscustomobject]@{"Results" = "Success. All sessions by this user have been revoked" }
      Log-Request -user $request.headers.'x-ms-client-principal' -API $APINAME  -message "Revoked sessions for $($Request.Query.id)" -Sev "Info"

}
catch {
      $Results = [pscustomobject]@{"Results" = "Failed. $($_.Exception.Message)" }
}

# Associate values to output bindings by calling 'Push-OutputBinding'.
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = $Results
      })