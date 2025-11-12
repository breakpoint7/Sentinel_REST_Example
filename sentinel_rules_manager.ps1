# Comprehensive Sentinel Rules Management Script
param(
    [string]$Action = "",
    [string]$JsonFile = "",
    [string]$RuleId = "",
    [switch]$ListAll = $false,
    [switch]$ListCustomDetection = $false,
    [switch]$ListAnalytics = $false,
    [switch]$CreateFromJson = $false,
    [switch]$Help = $false,
    [string]$SubscriptionId = "",
    [string]$ResourceGroupName = "",
    [string]$WorkspaceName = ""
)

function Get-EnvConfig {
    $envPath = Join-Path $PSScriptRoot ".env"
    $config = @{}
    if (Test-Path $envPath) {
        Get-Content $envPath | ForEach-Object {
            if ($_ -match '^([^=]+)=(.*)$' -and -not ($_ -match '^\s*#')) {
                $key = $matches[1].Trim()
                $value = $matches[2].Trim() -replace '^"(.*)"$','$1' -replace "^'(.*)'$",'$1'
                $config[$key] = $value
            }
        }
    }
    return $config
}

function Get-AccessToken {
    param($config, [string]$scope = "https://graph.microsoft.com/.default")
    
    $tokenUrl = "https://login.microsoftonline.com/$($config.AZURE_TENANT_ID)/oauth2/v2.0/token"
    $body = @{
        client_id     = $config.AZURE_CLIENT_ID
        client_secret = $config.AZURE_CLIENT_SECRET
        scope         = $scope
        grant_type    = "client_credentials"
    }
    
    Write-Host "Getting access token for scope: $scope..." -ForegroundColor Yellow
    try {
        $response = Invoke-RestMethod -Uri $tokenUrl -Method POST -Body $body -ContentType "application/x-www-form-urlencoded"
        Write-Host "Token obtained successfully" -ForegroundColor Green
        return $response.access_token
    }
    catch {
        Write-Host "Failed to get access token: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}

function Get-CustomDetectionRules {
    param($token)
    
    Write-Host "`n=== CUSTOM DETECTION RULES (Microsoft Graph API) ===" -ForegroundColor Cyan
    
    $uri = "https://graph.microsoft.com/beta/security/rules/detectionRules"
    $headers = @{
        "Authorization" = "Bearer $token"
        "Content-Type"  = "application/json"
    }
    
    try {
        Write-Host "Querying custom detection rules..." -ForegroundColor Yellow
        Write-Host "URI: $uri" -ForegroundColor DarkGray
        
        $result = Invoke-RestMethod -Uri $uri -Method GET -Headers $headers
        
        if ($result.value -and $result.value.Count -gt 0) {
            Write-Host "Found $($result.value.Count) custom detection rule(s)" -ForegroundColor Green
            
            foreach ($rule in $result.value) {
                Write-Host ""
                Write-Host "Rule ID: $($rule.id)" -ForegroundColor Yellow
                Write-Host "Display Name: $($rule.displayName)" -ForegroundColor White
                Write-Host "Description: $($rule.description)" -ForegroundColor Gray
                Write-Host "Enabled: $($rule.isEnabled)" -ForegroundColor $(if ($rule.isEnabled) { "Green" } else { "Red" })
                Write-Host "Created: $($rule.createdDateTime)" -ForegroundColor DarkGray
                Write-Host "Modified: $($rule.lastModifiedDateTime)" -ForegroundColor DarkGray
                
                if ($rule.detectionAction) {
                    Write-Host "Detection Action: $($rule.detectionAction)" -ForegroundColor Gray
                }
                
                if ($rule.queryCondition) {
                    Write-Host "Query Condition:" -ForegroundColor Gray
                    Write-Host "  Query: $($rule.queryCondition.queryText)" -ForegroundColor DarkGray
                    if ($rule.queryCondition.lookbackDuration) {
                        Write-Host "  Lookback: $($rule.queryCondition.lookbackDuration)" -ForegroundColor DarkGray
                    }
                }
                
                Write-Host "-" * 80 -ForegroundColor DarkGray
            }
        } else {
            Write-Host "No custom detection rules found" -ForegroundColor Yellow
        }
        
        return $result.value
    }
    catch {
        Write-Host "Failed to get custom detection rules: $($_.Exception.Message)" -ForegroundColor Red
        if ($_.Exception.Response) {
            $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
            $responseText = $reader.ReadToEnd()
            $reader.Close()
            Write-Host "Response: $responseText" -ForegroundColor Red
        }
        return @()
    }
}

function Get-AnalyticsRules {
    param($token, $subscriptionId, $resourceGroupName, $workspaceName)
    
    Write-Host "`n=== ANALYTICS RULES (Azure Management API) ===" -ForegroundColor Cyan
    
    if (-not $subscriptionId -or -not $resourceGroupName -or -not $workspaceName) {
        Write-Host "Subscription ID, Resource Group Name, and Workspace Name are required for analytics rules" -ForegroundColor Red
        return @()
    }
    
    $uri = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/alertRules?api-version=2023-02-01"
    $headers = @{
        "Authorization" = "Bearer $token"
        "Content-Type"  = "application/json"
    }
    
    try {
        Write-Host "Querying analytics rules..." -ForegroundColor Yellow
        Write-Host "Subscription: $subscriptionId" -ForegroundColor DarkGray
        Write-Host "Resource Group: $resourceGroupName" -ForegroundColor DarkGray
        Write-Host "Workspace: $workspaceName" -ForegroundColor DarkGray
        Write-Host "URI: $uri" -ForegroundColor DarkGray
        
        $result = Invoke-RestMethod -Uri $uri -Method GET -Headers $headers
        
        if ($result.value -and $result.value.Count -gt 0) {
            Write-Host "Found $($result.value.Count) analytics rule(s)" -ForegroundColor Green
            
            # Group by rule type
            $rulesByType = $result.value | Group-Object { $_.kind }
            
            foreach ($typeGroup in $rulesByType) {
                Write-Host "`n--- $($typeGroup.Name.ToUpper()) RULES ($($typeGroup.Count)) ---" -ForegroundColor Magenta
                
                foreach ($rule in $typeGroup.Group) {
                    Write-Host ""
                    Write-Host "Rule ID: $($rule.name)" -ForegroundColor Yellow
                    Write-Host "Display Name: $($rule.properties.displayName)" -ForegroundColor White
                    Write-Host "Description: $($rule.properties.description)" -ForegroundColor Gray
                    Write-Host "Enabled: $($rule.properties.enabled)" -ForegroundColor $(if ($rule.properties.enabled) { "Green" } else { "Red" })
                    Write-Host "Severity: $($rule.properties.severity)" -ForegroundColor Gray
                    
                    if ($rule.properties.tactics) {
                        Write-Host "Tactics: $($rule.properties.tactics -join ', ')" -ForegroundColor Gray
                    }
                    
                    if ($rule.properties.techniques) {
                        Write-Host "Techniques: $($rule.properties.techniques -join ', ')" -ForegroundColor Gray
                    }
                    
                    if ($rule.properties.query) {
                        $queryPreview = if ($rule.properties.query.Length -gt 100) {
                            $rule.properties.query.Substring(0, 100) + "..."
                        } else {
                            $rule.properties.query
                        }
                        Write-Host "Query Preview: $queryPreview" -ForegroundColor DarkGray
                    }
                    
                    Write-Host "-" * 60 -ForegroundColor DarkGray
                }
            }
        } else {
            Write-Host "No analytics rules found" -ForegroundColor Yellow
        }
        
        return $result.value
    }
    catch {
        Write-Host "Failed to get analytics rules: $($_.Exception.Message)" -ForegroundColor Red
        if ($_.Exception.Response) {
            try {
                $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
                $responseText = $reader.ReadToEnd()
                $reader.Close()
                $errorObj = $responseText | ConvertFrom-Json
                Write-Host "Error Code: $($errorObj.error.code)" -ForegroundColor Red
                Write-Host "Error Message: $($errorObj.error.message)" -ForegroundColor Red
            }
            catch {
                Write-Host "Response: $responseText" -ForegroundColor Red
            }
        }
        return @()
    }
}

function Get-JsonPayloadFiles {
    $payloadsDir = Join-Path $PSScriptRoot "json_payloads"
    
    if (-not (Test-Path $payloadsDir)) {
        Write-Host "json_payloads directory not found at: $payloadsDir" -ForegroundColor Red
        return @()
    }
    
    $jsonFiles = Get-ChildItem -Path $payloadsDir -Filter "*.json" -File
    return $jsonFiles
}

function Show-JsonPayloadFiles {
    Write-Host "`n=== AVAILABLE JSON PAYLOAD FILES ===" -ForegroundColor Cyan
    
    $jsonFiles = Get-JsonPayloadFiles
    
    if ($jsonFiles.Count -eq 0) {
        Write-Host "No JSON payload files found in json_payloads directory" -ForegroundColor Yellow
        return
    }
    
    Write-Host "Found $($jsonFiles.Count) JSON payload file(s):" -ForegroundColor Green
    
    for ($i = 0; $i -lt $jsonFiles.Count; $i++) {
        Write-Host "[$($i + 1)] $($jsonFiles[$i].Name)" -ForegroundColor White
        
        try {
            $content = Get-Content $jsonFiles[$i].FullName -Raw | ConvertFrom-Json
            if ($content.displayName) {
                Write-Host "    Display Name: $($content.displayName)" -ForegroundColor Gray
            }
            if ($content.description) {
                $desc = if ($content.description.Length -gt 80) {
                    $content.description.Substring(0, 80) + "..."
                } else {
                    $content.description
                }
                Write-Host "    Description: $desc" -ForegroundColor Gray
            }
        }
        catch {
            Write-Host "    (Invalid JSON format)" -ForegroundColor Red
        }
        Write-Host ""
    }
}

function Create-CustomDetectionRule {
    param($token, $jsonFilePath)
    
    Write-Host "`n=== CREATING CUSTOM DETECTION RULE ===" -ForegroundColor Cyan
    
    if (-not (Test-Path $jsonFilePath)) {
        Write-Host "JSON file not found: $jsonFilePath" -ForegroundColor Red
        return $false
    }
    
    try {
        $jsonContent = Get-Content $jsonFilePath -Raw
        Write-Host "Loading JSON from: $jsonFilePath" -ForegroundColor Yellow
        
        # Validate JSON
        $ruleData = $jsonContent | ConvertFrom-Json
        Write-Host "JSON validated successfully" -ForegroundColor Green
        Write-Host "Rule: $($ruleData.displayName)" -ForegroundColor White
        
        $uri = "https://graph.microsoft.com/beta/security/rules/detectionRules"
        $headers = @{
            "Authorization" = "Bearer $token"
            "Content-Type"  = "application/json"
        }
        
        Write-Host "Creating custom detection rule..." -ForegroundColor Yellow
        Write-Host "URI: $uri" -ForegroundColor DarkGray
        
        $result = Invoke-RestMethod -Uri $uri -Method POST -Body $jsonContent -Headers $headers
        
        Write-Host ""
        Write-Host "SUCCESS! Custom detection rule created:" -ForegroundColor Green
        Write-Host "Rule ID: $($result.id)" -ForegroundColor Yellow
        Write-Host "Display Name: $($result.displayName)" -ForegroundColor White
        Write-Host "Enabled: $($result.isEnabled)" -ForegroundColor $(if ($result.isEnabled) { "Green" } else { "Red" })
        Write-Host "Created: $($result.createdDateTime)" -ForegroundColor Gray
        
        return $true
    }
    catch {
        Write-Host ""
        Write-Host "FAILED to create custom detection rule!" -ForegroundColor Red
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        
        if ($_.Exception.Response) {
            try {
                $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
                $responseText = $reader.ReadToEnd()
                $reader.Close()
                $errorObj = $responseText | ConvertFrom-Json
                Write-Host "API Error: $($errorObj.error.code)" -ForegroundColor Red
                Write-Host "Message: $($errorObj.error.message)" -ForegroundColor Red
                if ($errorObj.error.details) {
                    Write-Host "Details:" -ForegroundColor Red
                    $errorObj.error.details | ForEach-Object {
                        Write-Host "  - $($_.message)" -ForegroundColor Red
                    }
                }
            }
            catch {
                Write-Host "Raw response: $responseText" -ForegroundColor Red
            }
        }
        
        return $false
    }
}



function Show-InteractiveMenu {
    param($config)
    
    Write-Host "`n=== SENTINEL RULES MANAGER - INTERACTIVE MODE ===" -ForegroundColor Green
    
    do {
        Write-Host ""
        Write-Host "Available Actions:" -ForegroundColor Yellow
        Write-Host "1. List All Custom Detection Rules" -ForegroundColor White
        Write-Host "2. List All Analytics Rules" -ForegroundColor White
        Write-Host "3. List Both Custom Detection and Analytics Rules" -ForegroundColor White
        Write-Host "4. Create Custom Detection Rule from JSON" -ForegroundColor White
        Write-Host "5. Show Available JSON Payload Files" -ForegroundColor White
        Write-Host "6. Exit" -ForegroundColor White
        Write-Host ""
        
        $choice = Read-Host "Select an option (1-6)"
        
        switch ($choice) {
            "1" {
                $graphToken = Get-AccessToken -config $config -scope "https://graph.microsoft.com/.default"
                Get-CustomDetectionRules -token $graphToken
                break
            }
            "2" {
                $mgmtToken = Get-AccessToken -config $config -scope "https://management.azure.com/.default"
                Get-AnalyticsRules -token $mgmtToken -subscriptionId $config.AZURE_SUBSCRIPTION_ID -resourceGroupName $config.AZURE_RESOURCE_GROUP -workspaceName $config.SENTINEL_WORKSPACE_NAME
                break
            }
            "3" {
                $graphToken = Get-AccessToken -config $config -scope "https://graph.microsoft.com/.default"
                $mgmtToken = Get-AccessToken -config $config -scope "https://management.azure.com/.default"
                Get-CustomDetectionRules -token $graphToken
                Get-AnalyticsRules -token $mgmtToken -subscriptionId $config.AZURE_SUBSCRIPTION_ID -resourceGroupName $config.AZURE_RESOURCE_GROUP -workspaceName $config.SENTINEL_WORKSPACE_NAME
                break
            }
            "4" {
                Show-JsonPayloadFiles
                $jsonFiles = Get-JsonPayloadFiles
                if ($jsonFiles.Count -gt 0) {
                    $fileChoice = Read-Host "Select JSON file number (1-$($jsonFiles.Count))"
                    if ($fileChoice -match '^\d+$' -and [int]$fileChoice -ge 1 -and [int]$fileChoice -le $jsonFiles.Count) {
                        $selectedFile = $jsonFiles[[int]$fileChoice - 1]
                        $graphToken = Get-AccessToken -config $config -scope "https://graph.microsoft.com/.default"
                        Create-CustomDetectionRule -token $graphToken -jsonFilePath $selectedFile.FullName
                    } else {
                        Write-Host "Invalid file selection" -ForegroundColor Red
                    }
                }
                break
            }
            "5" {
                Show-JsonPayloadFiles
                break
            }
            "6" {
                Write-Host "Exiting..." -ForegroundColor Yellow
                return
            }
            default {
                Write-Host "Invalid choice. Please select 1-6." -ForegroundColor Red
                continue
            }
        }
        
        Write-Host ""
        Write-Host "Press Enter to continue..." -ForegroundColor DarkGray
        Read-Host | Out-Null
        Write-Host ""
        
    } while ($choice -ne "6")
}

function Show-Usage {
    Write-Host "Sentinel Rules Manager" -ForegroundColor Green
    Write-Host "Manages Custom Detection Rules (Graph API) and queries Analytics Rules (Management API)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Interactive Mode:" -ForegroundColor Cyan
    Write-Host "  .\sentinel_rules_manager.ps1" -ForegroundColor Gray
    Write-Host ""
    Write-Host "List Operations:" -ForegroundColor Cyan
    Write-Host "  .\sentinel_rules_manager.ps1 -ListAll" -ForegroundColor Gray
    Write-Host "  .\sentinel_rules_manager.ps1 -ListCustomDetection" -ForegroundColor Gray
    Write-Host "  .\sentinel_rules_manager.ps1 -ListAnalytics" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Create Operations:" -ForegroundColor Cyan
    Write-Host "  .\sentinel_rules_manager.ps1 -CreateFromJson -JsonFile 'json_payloads\credential_dumping_detection.json'" -ForegroundColor Gray
    Write-Host "  .\sentinel_rules_manager.ps1 -Action CreateCustomDetection -JsonFile 'json_payloads\phishing_email_detection.json'" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Override Configuration:" -ForegroundColor Cyan
    Write-Host "  .\sentinel_rules_manager.ps1 -ListAnalytics -SubscriptionId <id> -ResourceGroupName <rg> -WorkspaceName <ws>" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Available JSON Files:" -ForegroundColor Yellow
    Show-JsonPayloadFiles
    Write-Host ""
    Write-Host "Examples:" -ForegroundColor Yellow
    Write-Host "  # Interactive menu (recommended for first-time users)" -ForegroundColor Gray
    Write-Host "  .\sentinel_rules_manager.ps1" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  # List all rules from both APIs" -ForegroundColor Gray
    Write-Host "  .\sentinel_rules_manager.ps1 -ListAll" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  # Create a custom detection rule" -ForegroundColor Gray
    Write-Host "  .\sentinel_rules_manager.ps1 -CreateFromJson -JsonFile 'json_payloads\malicious_file_hash_detection.json'" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  # List analytics rules only" -ForegroundColor Gray
    Write-Host "  .\sentinel_rules_manager.ps1 -ListAnalytics" -ForegroundColor Gray
}

# Main execution
try {
    Write-Host "Sentinel Rules Manager v1.0" -ForegroundColor Green
    Write-Host "================================" -ForegroundColor Green
    
    if ($Help) {
        Show-Usage
        exit 0
    }
    
    # Load configuration
    $config = Get-EnvConfig
    
    if (-not $config.AZURE_TENANT_ID) {
        throw "Missing configuration in .env file. Please ensure AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET are set."
    }
    
    # Use overrides if provided
    if ($SubscriptionId) { $config.AZURE_SUBSCRIPTION_ID = $SubscriptionId }
    if ($ResourceGroupName) { $config.AZURE_RESOURCE_GROUP = $ResourceGroupName }
    if ($WorkspaceName) { $config.SENTINEL_WORKSPACE_NAME = $WorkspaceName }
    
    # Validate workspace configuration for analytics rules operations
    $canUseAnalytics = $config.AZURE_SUBSCRIPTION_ID -and $config.AZURE_RESOURCE_GROUP -and $config.SENTINEL_WORKSPACE_NAME
    
    if (-not $canUseAnalytics -and ($ListAnalytics -or $ListAll)) {
        Write-Host "WARNING: Analytics rules operations require AZURE_SUBSCRIPTION_ID, AZURE_RESOURCE_GROUP, and SENTINEL_WORKSPACE_NAME in .env file" -ForegroundColor Yellow
    }
    
    # Execute based on parameters
    if ($ListAll) {
        # List both custom detection and analytics rules
        $graphToken = Get-AccessToken -config $config -scope "https://graph.microsoft.com/.default"
        Get-CustomDetectionRules -token $graphToken
        
        if ($canUseAnalytics) {
            $mgmtToken = Get-AccessToken -config $config -scope "https://management.azure.com/.default"
            Get-AnalyticsRules -token $mgmtToken -subscriptionId $config.AZURE_SUBSCRIPTION_ID -resourceGroupName $config.AZURE_RESOURCE_GROUP -workspaceName $config.SENTINEL_WORKSPACE_NAME
        }
    }
    elseif ($ListCustomDetection) {
        # List custom detection rules only
        $graphToken = Get-AccessToken -config $config -scope "https://graph.microsoft.com/.default"
        Get-CustomDetectionRules -token $graphToken
    }
    elseif ($ListAnalytics) {
        # List analytics rules only
        if ($canUseAnalytics) {
            $mgmtToken = Get-AccessToken -config $config -scope "https://management.azure.com/.default"
            Get-AnalyticsRules -token $mgmtToken -subscriptionId $config.AZURE_SUBSCRIPTION_ID -resourceGroupName $config.AZURE_RESOURCE_GROUP -workspaceName $config.SENTINEL_WORKSPACE_NAME
        } else {
            Write-Host "Cannot list analytics rules without workspace configuration" -ForegroundColor Red
        }
    }
    elseif ($CreateFromJson -and $JsonFile) {
        # Create rule from JSON file (auto-detect type or prompt)
        $fullPath = if ([System.IO.Path]::IsPathRooted($JsonFile)) {
            $JsonFile
        } else {
            Join-Path (Join-Path $PSScriptRoot "json_payloads") $JsonFile
        }
        
        if (-not (Test-Path $fullPath)) {
            Write-Host "JSON file not found: $fullPath" -ForegroundColor Red
            Show-JsonPayloadFiles
            exit 1
        }
        
        Write-Host "Select rule type:" -ForegroundColor Yellow
        Write-Host "1. Custom Detection Rule (Graph API)" -ForegroundColor White
        Write-Host "2. Analytics Rule (Management API)" -ForegroundColor White
        $ruleTypeChoice = Read-Host "Enter choice (1 or 2)"
        
        if ($ruleTypeChoice -eq "1") {
            $graphToken = Get-AccessToken -config $config -scope "https://graph.microsoft.com/.default"
            Create-CustomDetectionRule -token $graphToken -jsonFilePath $fullPath
        }
        elseif ($ruleTypeChoice -eq "2") {
            if ($canUseAnalytics) {
                $mgmtToken = Get-AccessToken -config $config -scope "https://management.azure.com/.default"
                Create-AnalyticsRule -token $mgmtToken -subscriptionId $config.AZURE_SUBSCRIPTION_ID -resourceGroupName $config.AZURE_RESOURCE_GROUP -workspaceName $config.SENTINEL_WORKSPACE_NAME -jsonFilePath $fullPath
            } else {
                Write-Host "Cannot create analytics rules without workspace configuration" -ForegroundColor Red
            }
        }
        else {
            Write-Host "Invalid choice" -ForegroundColor Red
        }
    }
    elseif ($Action -eq "CreateCustomDetection" -and $JsonFile) {
        # Create custom detection rule
        $fullPath = if ([System.IO.Path]::IsPathRooted($JsonFile)) {
            $JsonFile
        } else {
            Join-Path (Join-Path $PSScriptRoot "json_payloads") $JsonFile
        }
        
        $graphToken = Get-AccessToken -config $config -scope "https://graph.microsoft.com/.default"
        Create-CustomDetectionRule -token $graphToken -jsonFilePath $fullPath
    }

    else {
        # Interactive mode
        Show-InteractiveMenu -config $config
    }
}
catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "Use -Help for usage information" -ForegroundColor Yellow
}