# Sentinel REST Example

A PowerShell script for managing Microsoft Sentinel detection rules using REST APIs.

## What It Does

`sentinel_rules_manager.ps1` allows you to:
- **List** custom detection rules (via Microsoft Graph API)
- **List** analytics rules (via Azure Management API)
- **Create** custom detection rules from JSON templates

The script can run in interactive mode (menu-driven) or via command-line arguments for automation.

## Prerequisites

- PowerShell 5.1 or later
- Azure AD App Registration with appropriate permissions:
  - `CustomDetection.ReadWrite.All` (for custom detection rules)
  - Contributor access to Azure subscription (for analytics rules)

## Quick Start

### 1. Configure Environment

Copy the example environment file and fill in your Azure credentials:

```powershell
# Copy the example file
Copy-Item .env.example .env

# Edit .env with your favorite text editor
notepad .env
```

### 2. Required Configuration

At minimum, populate these values in your `.env` file:

```
AZURE_CLIENT_ID=your-app-id-here
AZURE_CLIENT_SECRET=your-app-secret-here
AZURE_TENANT_ID=your-tenant-id-here
```

For analytics rules, also configure:
```
AZURE_SUBSCRIPTION_ID=your-subscription-id-here
AZURE_RESOURCE_GROUP=your-resource-group-here
SENTINEL_WORKSPACE_NAME=your-sentinel-workspace-here
```

### 3. Run the Script

**Interactive Mode** (recommended for first-time users):
```powershell
.\sentinel_rules_manager.ps1
```

**Command-Line Examples**:
```powershell
# List all custom detection rules
.\sentinel_rules_manager.ps1 -ListCustomDetection

# List all analytics rules
.\sentinel_rules_manager.ps1 -ListAnalytics

# Create a rule from JSON
.\sentinel_rules_manager.ps1 -CreateFromJson -JsonFile "json_payloads\credential_dumping_detection.json"

# Show help
.\sentinel_rules_manager.ps1 -Help
```

## JSON Payloads

The `json_payloads` directory contains example detection rules you can use as templates or deploy directly.

## Additional Help

For detailed setup instructions and troubleshooting, see the comments in `.env.example`.
