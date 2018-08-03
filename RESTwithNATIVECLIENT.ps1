# Load ADAL
Add-Type -Path "..\ADAL\Microsoft.IdentityModel.Clients.ActiveDirectory.dll"

# Output Token and Response from AAD Graph API
$accessToken = ".\Token.txt"
$output = ".\Output.json"

# Application and Tenant Configuration
$clientId = "3d61f00d-796e-43cf-820a-af2d76923d9d"
$tenantId = "72f988bf-86f1-41af-91ab-2d7cd011db47"
$resourceId = "https://graph.windows.net"
$redirectUri = New-Object system.uri("https://localhost:44300/callback")
$login = "https://login.microsoftonline.com"
$objectId = "78fe2512-dea9-4aae-8515-3f334ade9805"

#ADAL Prompt Behavior Configuration (Always, Auto, Never)
$promptBehavior = [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Auto

# Get an Access Token with ADAL
$authContext = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext ("{0}/{1}" -f $login,$tenantId)
$authenticationResult = $authContext.AcquireToken($resourceId, $clientID,$redirectUri, $promptBehavior) 
($token = $authenticationResult.AccessToken) | Out-File $accessToken

# Call the AAD Graph API
$headers = @{ 
    "Authorization" = ("Bearer {0}" -f $token);
    "Content-Type" = "application/json";
}

# Output response as a JSON file
Invoke-RestMethod -Method Get -Uri ("{0}/{1}/users?api-version=1.6" -f $resourceId, $tenantId) -Headers $headers -OutFile $output
Invoke-RestMethod -Method Get -Uri ("{0}/{1}/users/{2}?api-version=1.6" -f $resourceId, $tenantId,"yemrea@microsoft.com") -Headers $headers -OutFile $output
