# Microsoft Defender Cloud App Discovery → Microsoft Sentinel
## Automated Risk Catalog with Azure Logic App

This guide walks you through setting up an Azure Logic App that automatically:
- Fetches **SaaS app discovery data** from Microsoft Defender for Cloud Apps via Microsoft Graph API
- Writes all app data daily into a **custom Microsoft Sentinel / Log Analytics table** (`CloudAppRiskCatalog_CL`)
- Filters apps by **AI categories** (Generative AI, AI - Model Provider, AI - MCP Server)
- Sends a **monthly email report** with a CSV attachment via Microsoft Graph API (limited to AI and MCP)

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Prerequisites](#prerequisites)
3. [Step 1: Create the Log Analytics Custom Table](#step-1-create-the-log-analytics-custom-table)
4. [Step 2: Note DCR and DCE Details](#step-2-note-dcr-and-dce-details)
5. [Step 3: Create the Logic App](#step-3-create-the-logic-app)
6. [Step 4: Assign Permissions](#step-4-assign-permissions)
7. [Step 5: Configure the Logic App Workflow](#step-5-configure-the-logic-app-workflow)
8. [Step 6: Test and Verify](#step-6-test-and-verify)
9. [KQL Queries](#kql-queries)
10. [Troubleshooting](#troubleshooting)

---

## Architecture Overview

```
Microsoft Defender for Cloud Apps
         │
         │  Graph API (aggregatedAppsDetails)
         ▼
   Azure Logic App  ──── Managed Identity Auth ────►  Log Analytics / Sentinel
         │                                              (CloudAppRiskCatalog_CL)
         │
         │  (1st of month only)
         ▼
   Graph API sendMail
         │
         ▼
   Email recipients (CSV attachment with AI apps)
```

<img width="1164" height="2643" alt="image" src="https://github.com/user-attachments/assets/40a7dea7-fca8-4b15-a188-049ef3133579" />


**Key components:**
- **Logic App (Consumption)** – orchestrates the workflow, runs daily at 04:00
- **Managed Identity** – passwordless authentication to Graph API and Azure Monitor
- **Data Collection Endpoint (DCE)** – receives data from Logic App
- **Data Collection Rule (DCR)** – routes data to the correct table
- **Log Analytics Workspace** – stores the data in `CloudAppRiskCatalog_CL`

---

## Prerequisites

- Azure subscription with the following resources:
  - **Microsoft Defender for Cloud Apps** (with Cloud App Discovery enabled and at least one uploaded stream / endpoint agent)
  - **Log Analytics Workspace** (linked to Microsoft Sentinel)
  - **Contributor** or **Owner** rights on the resource group
- A mailbox (shared mailbox or user) to send emails from, e.g. `noreply-azureautomation@yourdomain.com`
- PowerShell with the `Az` module installed (for permission assignments)

---

## Step 1: Create the Log Analytics Custom Table

The custom table stores all discovered cloud apps. It must be created before the Logic App can write data.

### 1.1 Prepare the Sample JSON

Save the following as `sample.json`. This file defines the table schema — every field must exactly match what the Logic App sends.

```json
[
    {
        "TimeGenerated": "2026-05-04T10:00:00Z",
        "AppId": "12345",
        "AppName": "ChatGPT",
        "Category": "Generative AI",
        "RiskScore": 7,
        "Tags": "Sanctioned",
        "Description": "",
        "Domains": "chat.openai.com, openai.com",
        "downloadNetworkTrafficInBytes": 10485760,
        "uploadNetworkTrafficInBytes": 204800,
        "Transactions": 1500,
        "Users": 42,
        "IpAddresses": 5,
        "Devices": 30,
        "ConnectedApps": 2,
        "LastSeen": "2026-05-04T08:00:00Z",
        "StreamName": "XYZ Managed Endpoints",
        "StreamId": "abc123-def456-ghi789"
    }
]
```

### 1.2 Create the Table in Azure Portal

1. Go to **Azure Portal** → your **Log Analytics Workspace**
2. Navigate to **Tables** → **+ Create** → **New custom log (DCR-based)**
3. Click **+ Create a new data collection rule** (or select an existing DCR)
4. Give the DCR a meaningful name, e.g. `dcr-cloudappriskcatalog`
5. On the **Schema and transformation** page:
   - Upload `sample.json` as the sample file
   - The wizard will auto-generate all columns from the JSON
6. Set the **Transformation** to:
   ```
   source
   ```
   > `TimeGenerated` is already included in the data sent by the Logic App, so no transformation is needed.
7. Set the **Table name** to `CloudAppRiskCatalog` (the `_CL` suffix is added automatically)
8. Complete the wizard and save

### 1.3 Verify the Table Schema

Run the following KQL query to confirm all columns are present:

```kusto
CloudAppRiskCatalog_CL
| getschema
```

You should see columns including: `AppId`, `AppName`, `Category`, `RiskScore`, `Domains`, `Tags`, `Users`, `Devices`, `Transactions`, `downloadNetworkTrafficInBytes`, `uploadNetworkTrafficInBytes`, `ConnectedApps`, `LastSeen`, `StreamName`, `StreamId`.

---

## Step 2: Note DCR and DCE Details

After creating the table, note down the following values — you will need them in the Logic App configuration.

### 2.1 DCR Immutable ID

1. Go to **Azure Portal** → **Monitor** → **Data Collection Rules**
2. Select the DCR created in Step 1 (e.g. `dcr-cloudappriskcatalog`)
3. Click **JSON View** (top right)
4. Copy the `immutableId` value, e.g.:
   ```
   dcr-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
   ```

### 2.2 DCE Endpoint URL

1. In the same DCR view, note the **Data Collection Endpoint** name
2. Go to **Monitor** → **Data Collection Endpoints** → select your DCE
3. Copy the **Logs Ingestion** URL, e.g.:
   ```
   https://<your-dce-name>.ingest.monitor.azure.com
   ```

### 2.3 Stream Name

The stream name is always:
```
Custom-CloudAppRiskCatalog_CL
```

### 2.4 Ingestion URL

Combine the above into the full ingestion URL used in the Logic App:
```
https://<DCE-ENDPOINT>/dataCollectionRules/<DCR-IMMUTABLE-ID>/streams/Custom-CloudAppRiskCatalog_CL?api-version=2023-01-01
```

---

## Step 3: Create the Logic App

### 3.1 Create a Consumption Logic App

1. Go to **Azure Portal** → **Logic Apps** → **+ Add**
2. Select **Consumption** plan
3. Fill in the details:
   - **Subscription**: your subscription
   - **Resource Group**: your resource group
   - **Name**: e.g. `la-cloudappdiscovery-sentinel`
   - **Region**: your preferred region
4. Click **Review + create** → **Create**

### 3.2 Enable System-Assigned Managed Identity

1. Open the newly created Logic App
2. Go to **Settings** → **Identity**
3. Under **System assigned**, toggle to **On**
4. Click **Save** → confirm with **Yes**
5. Note the **Object (principal) ID** — you will need it for permission assignments

---

## Step 4: Assign Permissions

All authentication uses the Logic App's **Managed Identity** — no credentials or secrets required.

### 4.1 Graph API – Cloud App Discovery (Read)

Assign the `CloudApp.Read.All` (or equivalent) application permission via PowerShell:

```powershell
# Connect to Azure AD
Connect-AzureAD

# Variables – replace with your values
$ManagedIdentityObjectId = "<LOGIC-APP-MANAGED-IDENTITY-OBJECT-ID>"
$GraphAppId = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph

# Get the service principal for Graph
$GraphSP = Get-AzureADServicePrincipal -Filter "appId eq '$GraphAppId'"

# Find the required permission
$Permission = $GraphSP.AppRoles | Where-Object { $_.Value -eq "CloudApp.Read.All" }

# Get the Logic App's service principal
$ManagedIdentitySP = Get-AzureADServicePrincipal -ObjectId $ManagedIdentityObjectId

# Assign the permission
New-AzureADServiceAppRoleAssignment `
    -ObjectId $ManagedIdentitySP.ObjectId `
    -PrincipalId $ManagedIdentitySP.ObjectId `
    -ResourceId $GraphSP.ObjectId `
    -Id $Permission.Id
```

> **Note:** After assigning permissions, it can take up to 60 minutes for them to take effect.

### 4.2 DCR – Monitoring Metrics Publisher

The Logic App needs the `Monitoring Metrics Publisher` role on both the **DCR** and the **DCE** to write data.

```powershell
# Variables
$ManagedIdentityObjectId = "<LOGIC-APP-MANAGED-IDENTITY-OBJECT-ID>"
$ResourceGroupName = "<YOUR-RESOURCE-GROUP>"
$SubscriptionId = "<YOUR-SUBSCRIPTION-ID>"
$DcrName = "<YOUR-DCR-NAME>"
$DceName = "<YOUR-DCE-NAME>"

# Assign on DCR
$DcrResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Insights/dataCollectionRules/$DcrName"
New-AzRoleAssignment `
    -ObjectId $ManagedIdentityObjectId `
    -RoleDefinitionName "Monitoring Metrics Publisher" `
    -Scope $DcrResourceId

# Assign on DCE
$DceResourceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Insights/dataCollectionEndpoints/$DceName"
New-AzRoleAssignment `
    -ObjectId $ManagedIdentityObjectId `
    -RoleDefinitionName "Monitoring Metrics Publisher" `
    -Scope $DceResourceId
```

### 4.3 Graph API – Mail.Send

To send emails via the Graph API `sendMail` endpoint, assign the `Mail.Send` application permission:

```powershell
# Variables
$ManagedIdentityObjectId = "<LOGIC-APP-MANAGED-IDENTITY-OBJECT-ID>"
$GraphAppId = "00000003-0000-0000-c000-000000000000"

$GraphSP = Get-AzureADServicePrincipal -Filter "appId eq '$GraphAppId'"
$MailPermission = $GraphSP.AppRoles | Where-Object { $_.Value -eq "Mail.Send" }
$ManagedIdentitySP = Get-AzureADServicePrincipal -ObjectId $ManagedIdentityObjectId

New-AzureADServiceAppRoleAssignment `
    -ObjectId $ManagedIdentitySP.ObjectId `
    -PrincipalId $ManagedIdentitySP.ObjectId `
    -ResourceId $GraphSP.ObjectId `
    -Id $MailPermission.Id
```

> **Important:** The sender mailbox (e.g. `noreply-azureautomation@yourdomain.com`) must exist in your Microsoft 365 tenant. A shared mailbox is sufficient.

---

## Step 5: Configure the Logic App Workflow

### 5.1 Open the Code Editor

1. Open your Logic App in the Azure Portal
2. Go to **Logic app code view** (under Development Tools)
3. Replace the entire content with the JSON below

### 5.2 Update the Placeholders

Before saving, replace the following values:

| Placeholder | Description | Example |
|---|---|---|
| `<DCE-ENDPOINT>` | Data Collection Endpoint URL | `https://my-dce.ingest.monitor.azure.com` |
| `<DCR-IMMUTABLE-ID>` | DCR immutable ID from Step 2.1 | `dcr-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` |
| `<SENDER-EMAIL>` | Email sender address | `noreply-azureautomation@yourdomain.com` |
| `<RECIPIENT-1>` | First email recipient | `admin@yourdomain.com` |
| `<RECIPIENT-2>` | Second email recipient (optional, remove if not needed) | `security@yourdomain.com` |

### 5.3 Complete Logic App JSON

```json
{
    "definition": {
        "metadata": {
            "notes": {}
        },
        "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
        "contentVersion": "1.0.0.0",
        "triggers": {
            "Recurrence": {
                "type": "Recurrence",
                "recurrence": {
                    "interval": 24,
                    "frequency": "Hour",
                    "timeZone": "W. Europe Standard Time",
                    "startTime": "2026-01-19T10:00:00Z"
                }
            }
        },
        "actions": {
            "HTTP": {
                "type": "Http",
                "inputs": {
                    "uri": "https://graph.microsoft.com/beta/security/dataDiscovery/cloudAppDiscovery/uploadedStreams",
                    "method": "GET",
                    "headers": {
                        "Content-Type": "application/json"
                    },
                    "authentication": {
                        "type": "ManagedServiceIdentity",
                        "audience": "https://graph.microsoft.com"
                    }
                },
                "runAfter": {},
                "runtimeConfiguration": {
                    "contentTransfer": {
                        "transferMode": "Chunked"
                    }
                }
            },
            "Parse_JSON": {
                "type": "ParseJson",
                "inputs": {
                    "content": "@body('HTTP')",
                    "schema": {
                        "type": "object",
                        "properties": {
                            "@@odata.context": {
                                "type": "string"
                            },
                            "value": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "id": {
                                            "type": "string"
                                        },
                                        "displayName": {
                                            "type": "string"
                                        }
                                    },
                                    "required": [
                                        "id",
                                        "displayName"
                                    ]
                                }
                            }
                        }
                    }
                },
                "runAfter": {
                    "HTTP": [
                        "Succeeded"
                    ]
                }
            },
            "Initialize_BatchIndex": {
                "type": "InitializeVariable",
                "inputs": {
                    "variables": [
                        {
                            "name": "EnableEmailReport",
                            "type": "boolean",
                            "value": true
                        },
                        {
                            "name": "EmailRecipients",
                            "type": "array",
                            "value": [
                                {
                                    "emailAddress": {
                                        "address": "benjamin.zulliger@fhnw.ch"
                                    }
                                },
                                {
                                    "emailAddress": {
                                        "address": "nicola.elsener@fhnw.ch"
                                    }
                                },
                                {
                                    "emailAddress": {
                                        "address": "dominik.hof@fhnw.ch"
                                    }
                                }
                            ]
                        },
                        {
                            "name": "BatchIndex",
                            "type": "integer",
                            "value": 0
                        }
                    ]
                },
                "runAfter": {
                    "Parse_JSON": [
                        "Succeeded"
                    ]
                }
            },
            "For_each": {
                "type": "Foreach",
                "foreach": "@outputs('Parse_JSON')?['body']?['value']",
                "actions": {
                    "Condition": {
                        "type": "If",
                        "expression": {
                            "and": [
                                {
                                    "contains": [
                                        "@item()?['displayName']",
                                        "managed endpoints"
                                    ]
                                }
                            ]
                        },
                        "actions": {
                            "Compose": {
                                "type": "Compose",
                                "inputs": "@{item()?['displayName']}@{item()?['id']}"
                            },
                            "HTTP_Get_App_Details": {
                                "type": "Http",
                                "inputs": {
                                    "uri": "https://graph.microsoft.com/beta/security/dataDiscovery/cloudAppDiscovery/uploadedStreams/@{item()?['id']}/microsoft.graph.security.aggregatedAppsDetails(period=duration'P30D')",
                                    "method": "GET",
                                    "authentication": {
                                        "type": "ManagedServiceIdentity",
                                        "audience": "https://graph.microsoft.com"
                                    },
                                    "retryPolicy": {
                                        "type": "exponential",
                                        "count": 5,
                                        "interval": "PT60S",
                                        "minimumInterval": "PT60S",
                                        "maximumInterval": "PT1H"
                                    }
                                },
                                "runAfter": {
                                    "Compose": [
                                        "Succeeded"
                                    ]
                                },
                                "runtimeConfiguration": {
                                    "contentTransfer": {
                                        "transferMode": "Chunked"
                                    },
                                    "paginationPolicy": {
                                        "minimumItemCount": 9000
                                    }
                                }
                            },
                            "Parse_App_Details": {
                                "type": "ParseJson",
                                "inputs": {
                                    "content": "@body('HTTP_Get_App_Details')",
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "@@odata.context": {
                                                "type": "string"
                                            },
                                            "value": {
                                                "type": "array",
                                                "items": {
                                                    "type": "object",
                                                    "properties": {
                                                        "id": {
                                                            "type": "string"
                                                        },
                                                        "displayName": {
                                                            "type": "string"
                                                        },
                                                        "riskScore": {
                                                            "type": "integer"
                                                        },
                                                        "category": {
                                                            "type": "string"
                                                        },
                                                        "tags": {
                                                            "type": "array",
                                                            "items": {
                                                                "type": "string"
                                                            }
                                                        },
                                                        "domains": {
                                                            "type": "array",
                                                            "items": {
                                                                "type": "string"
                                                            }
                                                        },
                                                        "downloadNetworkTrafficInBytes": {
                                                            "type": "number"
                                                        },
                                                        "uploadNetworkTrafficInBytes": {
                                                            "type": "number"
                                                        },
                                                        "transactionCount": {
                                                            "type": "number"
                                                        },
                                                        "userCount": {
                                                            "type": "integer"
                                                        },
                                                        "ipAddressCount": {
                                                            "type": "integer"
                                                        },
                                                        "deviceCount": {
                                                            "type": "integer"
                                                        },
                                                        "lastSeenDateTime": {
                                                            "type": "string"
                                                        },
                                                        "connectedAppCount": {
                                                            "type": "integer"
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                },
                                "runAfter": {
                                    "HTTP_Get_App_Details": [
                                        "Succeeded"
                                    ]
                                }
                            },
                            "Select_Transform": {
                                "type": "Select",
                                "inputs": {
                                    "from": "@body('Parse_App_Details')?['value']",
                                    "select": {
                                        "TimeGenerated": "@utcNow()",
                                        "AppName": "@item()?['displayName']",
                                        "AppId": "@item()?['id']",
                                        "Category": "@item()?['category']",
                                        "RiskScore": "@coalesce(item()?['riskScore'], 0)",
                                        "Tags": "@join(coalesce(item()?['tags'], createArray()), ', ')",
                                        "Description": "",
                                        "Domains": "@join(coalesce(item()?['domains'], createArray()), ', ')",
                                        "downloadNetworkTrafficInBytes": "@coalesce(item()?['downloadNetworkTrafficInBytes'], 0)",
                                        "uploadNetworkTrafficInBytes": "@coalesce(item()?['uploadNetworkTrafficInBytes'], 0)",
                                        "Transactions": "@coalesce(item()?['transactionCount'], 0)",
                                        "Users": "@coalesce(item()?['userCount'], 0)",
                                        "IpAddresses": "@coalesce(item()?['ipAddressCount'], 0)",
                                        "Devices": "@coalesce(item()?['deviceCount'], 0)",
                                        "ConnectedApps": "@coalesce(item()?['connectedAppCount'], 0)",
                                        "LastSeen": "@item()?['lastSeenDateTime']",
                                        "StreamName": "@items('For_each')?['displayName']",
                                        "StreamId": "@items('For_each')?['id']"
                                    }
                                },
                                "runAfter": {
                                    "Parse_App_Details": [
                                        "Succeeded"
                                    ]
                                }
                            },
                            "Set_BatchIndex": {
                                "type": "SetVariable",
                                "inputs": {
                                    "name": "BatchIndex",
                                    "value": 0
                                },
                                "runAfter": {
                                    "Select_Transform": [
                                        "Succeeded"
                                    ]
                                }
                            },
                            "Post_In_Batches": {
                                "type": "Until",
                                "expression": "@greaterOrEquals(variables('BatchIndex'), length(body('Select_Transform')))",
                                "limit": {
                                    "count": 100,
                                    "timeout": "PT1H"
                                },
                                "actions": {
                                    "HTTP_Post_Batch": {
                                        "type": "Http",
                                        "inputs": {
                                            "uri": "https://p-dce-testingnginx-01-qlfe.switzerlandnorth-1.ingest.monitor.azure.com/dataCollectionRules/dcr-3e3d0fa978d64c829a49f9b17557c290/streams/Custom-CloudAppRiskCatalog_CL?api-version=2023-01-01",
                                            "method": "POST",
                                            "headers": {
                                                "Content-Type": "application/json"
                                            },
                                            "body": "@take(skip(body('Select_Transform'), variables('BatchIndex')), 500)",
                                            "authentication": {
                                                "type": "ManagedServiceIdentity",
                                                "audience": "https://monitor.azure.com"
                                            }
                                        }
                                    },
                                    "Increment_BatchIndex": {
                                        "type": "IncrementVariable",
                                        "inputs": {
                                            "name": "BatchIndex",
                                            "value": 500
                                        },
                                        "runAfter": {
                                            "HTTP_Post_Batch": [
                                                "Succeeded"
                                            ]
                                        }
                                    }
                                },
                                "runAfter": {
                                    "Set_BatchIndex": [
                                        "Succeeded"
                                    ]
                                }
                            },
                            "Filter_AI_Apps": {
                                "type": "Query",
                                "inputs": {
                                    "from": "@body('Select_Transform')",
                                    "where": "@or(or(or(contains(toLower(string(coalesce(item()?['category'], ''))), 'generative'), contains(toLower(string(coalesce(item()?['category'], ''))), 'aiModelProvider')), contains(toLower(string(coalesce(item()?['category'], ''))), 'mcp')), contains(toLower(string(coalesce(item()?['category'], ''))), 'ai - '))"
                                },
                                "runAfter": {
                                    "Post_In_Batches": [
                                        "Succeeded"
                                    ]
                                }
                            },
                            "Check_First_Of_Month": {
                                "type": "If",
                                "expression": {
                                    "and": [
                                        {
                                            "equals": [
                                                "@dayOfMonth(utcNow())",
                                                1
                                            ]
                                        }
                                    ]
                                },
                                "actions": {
                                    "Create_CSV_Rows": {
                                        "type": "Select",
                                        "inputs": {
                                            "from": "@body('Filter_AI_Apps')",
                                            "select": "@{item()?['AppName']},@{item()?['AppId']},@{item()?['Category']},@{item()?['RiskScore']},@{item()?['Users']},@{item()?['Devices']},@{item()?['Transactions']},@{item()?['downloadNetworkTrafficInBytes']},@{item()?['Domains']},@{item()?['LastSeen']}"
                                        }
                                    },
                                    "Compose_CSV": {
                                        "type": "Compose",
                                        "inputs": "AppName,AppId,Category,RiskScore,Users,Devices,Transactions,DownloadTrafficBytes,Domains,LastSeen\n@{join(body('Create_CSV_Rows'), '\n')}",
                                        "runAfter": {
                                            "Create_CSV_Rows": [
                                                "Succeeded"
                                            ]
                                        }
                                    },
                                    "Send_Email_Graph": {
                                        "type": "Http",
                                        "inputs": {
                                            "uri": "https://graph.microsoft.com/v1.0/users/noreply-azureautomation@fhnw.ch/sendMail",
                                            "method": "POST",
                                            "headers": {
                                                "Content-Type": "application/json"
                                            },
                                            "body": {
                                                "message": {
                                                    "subject": "AI Apps Report - @{utcNow('yyyy-MM-dd')}",
                                                    "body": {
                                                        "contentType": "HTML",
                                                        "content": "<p>Guten Tag</p><p>Im Anhang finden Sie den aktuellen AI Apps Report vom <strong>@{utcNow('dd.MM.yyyy')}</strong>.</p><p>Enthaltene Kategorien:<br>- Generative AI<br>- AI - Model Provider<br>- AI - MCP Server</p><p>Anzahl gefundene Apps: <strong>@{length(body('Filter_AI_Apps'))}</strong></p><br><p>Diese E-Mail wurde automatisch generiert.</p>"
                                                    },
                                                    "toRecipients": "@variables('EmailRecipients')",
                                                    "attachments": [
                                                        {
                                                            "@@odata.type": "#microsoft.graph.fileAttachment",
                                                            "name": "AI_Apps_@{utcNow('yyyy-MM-dd')}.csv",
                                                            "contentType": "text/csv",
                                                            "contentBytes": "@{base64(outputs('Compose_CSV'))}"
                                                        }
                                                    ]
                                                },
                                                "saveToSentItems": false
                                            },
                                            "authentication": {
                                                "type": "ManagedServiceIdentity",
                                                "audience": "https://graph.microsoft.com"
                                            }
                                        },
                                        "runAfter": {
                                            "Compose_CSV": [
                                                "Succeeded"
                                            ]
                                        }
                                    }
                                },
                                "else": {
                                    "actions": {}
                                },
                                "runAfter": {
                                    "Filter_AI_Apps": [
                                        "Succeeded"
                                    ]
                                }
                            }
                        },
                        "else": {
                            "actions": {}
                        }
                    }
                },
                "runAfter": {
                    "Initialize_BatchIndex": [
                        "Succeeded"
                    ]
                }
            }
        },
        "outputs": {},
        "parameters": {
            "$connections": {
                "type": "Object",
                "defaultValue": {}
            }
        }
    },
    "parameters": {
        "$connections": {
            "type": "Object",
            "value": {}
        }
    }
}
```

### 5.4 Stream Filter

The Logic App processes only streams whose `displayName` contains `"managed endpoints"` (case-insensitive). If your stream has a different name, update this condition in the `Condition` action:

```json
"contains": [
    "@toLower(item()?['displayName'])",
    "managed endpoints"   ← change this to match your stream name
]
```

To find your stream names, run this API call or check the Defender portal under **Settings → Cloud App Discovery → Automatic log upload**.

---

## Step 6: Test and Verify

### 6.1 Enable and Run the Logic App

1. Open the Logic App → **Overview**
2. Ensure the status is **Enabled** (click **Enable** if not)
3. Click **Run Trigger** → **Recurrence** to trigger a manual run

### 6.2 Monitor the Run

1. Go to **Run History** (under Monitoring)
2. Click the latest run to inspect each action
3. Expected runtime: **20–60 minutes** depending on the number of discovered apps

### 6.3 Verify Data in Sentinel

```kusto
// Check latest records
CloudAppRiskCatalog_CL
| where TimeGenerated > ago(2h)
| take 20

// Count unique apps (deduplicated by AppName)
CloudAppRiskCatalog_CL
| summarize arg_max(TimeGenerated, *) by AppName
| count

// Check all columns are populated
CloudAppRiskCatalog_CL
| where TimeGenerated > ago(2h)
| project AppName, Category, RiskScore, Domains, Users, Devices
| take 10
```
### 6.4 Enable or disable the Email CSV Report
if you don't need the E-Mail Report you can disable it in the LogicApp Designer UI Initialize BatchIndex-->Parameters-->EnableEmailReport
- true: the E-Mail Report will be sent to the defined Recipients in the LogicApp Designer UI Initialize BatchIndex-->Parameters-->EmailRecipients. You are also able to change the value direct in the Logic App JSON
```json
            "Initialize_BatchIndex": {
                "type": "InitializeVariable",
                "inputs": {
                    "variables": [
                        {
							"name": "EnableEmailReport",
							"type": "boolean",
							"value": true,
              "description": "If true, the Email CSV Report is sent"
						},
```
- false: the E-Mail Report will not be sent. You can change the value direct in the Logic App JSON
```json
            "Initialize_BatchIndex": {
                "type": "InitializeVariable",
                "inputs": {
                    "variables": [
                        {
							"name": "EnableEmailReport",
							"type": "boolean",
							"value": false,
              "description": "If false, the Email CSV Report is not sent"
						},
```
---

## KQL Queries

### All Apps – Latest Run (Deduplicated)

```kusto
CloudAppRiskCatalog_CL
| summarize arg_max(TimeGenerated, *) by AppName
| project AppName, Category, RiskScore, Users, Devices, Domains, Tags
| sort by RiskScore asc
```

### High-Risk Apps (RiskScore < 5)

```kusto
CloudAppRiskCatalog_CL
| summarize arg_max(TimeGenerated, *) by AppName
| where toint(RiskScore) < 5
| project AppName, Category, RiskScore, Users, Domains
| sort by RiskScore asc
```

### AI Apps Only

```kusto
CloudAppRiskCatalog_CL
| summarize arg_max(TimeGenerated, *) by AppName
| where Category has_any ("Generative", "AI - Model", "AI - MCP")
| project AppName, Category, RiskScore, Users, Devices, Domains
| sort by Users desc
```

### Top 20 Apps by Traffic

```kusto
CloudAppRiskCatalog_CL
| summarize arg_max(TimeGenerated, *) by AppName
| top 20 by downloadNetworkTrafficInBytes desc
| project AppName, Category, RiskScore,
    DownloadGB = round(todouble(downloadNetworkTrafficInBytes) / 1073741824, 2),
    UploadGB = round(todouble(uploadNetworkTrafficInBytes) / 1073741824, 2),
    Users, Devices
```

### Apps per Category

```kusto
CloudAppRiskCatalog_CL
| summarize arg_max(TimeGenerated, *) by AppName
| summarize AppCount = count() by Category
| sort by AppCount desc
```

### New Apps Since Last Week

```kusto
let lastWeek = ago(7d);
let thisWeek = CloudAppRiskCatalog_CL
    | where TimeGenerated > lastWeek
    | summarize by AppName;
let prevWeek = CloudAppRiskCatalog_CL
    | where TimeGenerated between (ago(14d) .. lastWeek)
    | summarize by AppName;
thisWeek
| join kind=leftanti prevWeek on AppName
| project AppName
```

### Piechart by Category with Traffic in %
<img width="638" height="397" alt="image" src="https://github.com/user-attachments/assets/3fa1a387-6d42-4df0-90dd-289c09e2c57c" />

```kusto
CloudAppRiskCatalog_CL
| summarize TotalTrafficGB = sum(downloadNetworkTrafficInBytes + uploadNetworkTrafficInBytes) / 1024 / 1024 / 1024 by Category
| render piechart with (title="Datenverkehr nach Kategorie (in GB)")
```

### Piechart of AI Agents with Riskscore (added 2026-06-08)
<img width="649" height="336" alt="image" src="https://github.com/user-attachments/assets/e0ab306c-b1fd-4419-823f-99e7bbc2735b" />

 
```kusto
let SourceData = 
    ExposureGraphEdges
    | where SourceNodeLabel == "endpointAiAgent"
    | summarize Count = count() by SourceNodeName
    | extend FirstWordSource = tolower(split(SourceNodeName, " ")[0])
    | extend DummyKey = 1;
let Catalog = 
    CloudAppRiskCatalog_CL 
    | extend FirstWordCatalog = tolower(split(AppName, " ")[0])
    | extend DummyKey = 1;
SourceData
| join kind=inner Catalog on DummyKey
| where AppName has FirstWordSource or SourceNodeName has FirstWordCatalog
| summarize arg_max(Count, *) by SourceNodeName
| extend DiagrammLabel = strcat(SourceNodeName, " | Risk: ", RiskScore, " | (", Count, "x)")
| project DiagrammLabel, Count
| render piechart with (title="AI Agents Overview")
```
 
---

## Troubleshooting

### 403 Forbidden on Graph API

**Symptom:** `HTTP_Get_App_Details` or `HTTP` action fails with 403.

**Fix:** Verify the Managed Identity has the `CloudApp.Read.All` Graph API permission. Permissions can take up to 60 minutes to propagate after assignment.

### 403 Forbidden on Sentinel Ingestion

**Symptom:** `HTTP_Post_Batch` fails with 403.

**Fix:** Assign `Monitoring Metrics Publisher` role to the Managed Identity on both the DCR and DCE (see Step 4.2).

### 429 Too Many Requests

**Symptom:** Graph API returns 429 after a while.

**Fix:** The Logic App already has exponential retry configured (up to 5 retries, starting at 60 seconds). This is expected behaviour — the Logic App will retry automatically.

### Data Appears in Table but Columns Are Empty

**Symptom:** `TimeGenerated` and one or two columns are filled, all others are empty.

**Cause:** The DCR `streamDeclarations` only knows about the columns that were in the original sample JSON when the table was created.

**Fix:** Delete the table and recreate it using the complete sample JSON from Step 1.1, making sure all fields are included.

### CSV Email Is Empty

**Symptom:** Email arrives but the CSV attachment has only the header row.

**Cause:** `Filter_AI_Apps` found no apps matching the AI category filter. The actual category values in your environment may differ.

**Fix:** Check what categories exist in your data:
```kusto
CloudAppRiskCatalog_CL
| summarize arg_max(TimeGenerated, *) by AppName
| summarize count() by Category
| sort by count_ desc
```
Then update the `Filter_AI_Apps` `where` condition in the Logic App to match the actual category names returned by your Defender environment.

### Logic App Takes Too Long

**Expected runtime:** 20–60 minutes is normal for environments with 3,000–5,000 discovered apps. The bottleneck is usually:
1. The initial Graph API call fetching all apps (pagination)
2. The Until loop posting 500 apps per batch to the DCE

The Logic App timeout is set to 2 hours (`PT2H`) which should be sufficient for most environments.

### RiskScore Filter Not Working in KQL

**Symptom:** `where RiskScore < 5` returns no results or an error.

**Fix:** Use explicit type conversion:
```kusto
| where toint(RiskScore) < 5
```

---

## Notes

- **Data period:** The Logic App fetches discovery data for the last **30 days** (`P30D`). Adjust in the `HTTP_Get_App_Details` URL if needed.
- **Email schedule:** The email is sent only on the **1st of each month**. The Sentinel table is updated **daily**.
- **Stream filter:** Only streams whose display name contains `"managed endpoints"` are processed. Adjust the `Condition` action if your environment uses different stream names.
- **Authentication:** All API calls use Managed Identity — no client secrets or certificates required.


---

*Developed and tested with Microsoft Defender for Cloud Apps, Azure Logic Apps (Consumption), and Microsoft Sentinel.*
