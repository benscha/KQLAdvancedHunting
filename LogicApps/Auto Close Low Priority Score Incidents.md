**Description**

Azure Logic App to automatically close low-priority Microsoft Defender incidents based on the Priority Score. Incidents below a configurable threshold are resolved via Microsoft Graph API, reducing SOC noise and alert fatigue while preserving traceability through custom tags.

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
                    "frequency": "Minute",
                    "interval": 5,
                    "timeZone": "W. Europe Standard Time"
                }
            }
        },
        "actions": {
            "HTTP": {
                "type": "Http",
                "inputs": {
                    "uri": "https://graph.microsoft.com/v1.0/security/incidents",
                    "method": "GET",
                    "queries": {
                        "$filter": "status eq 'Active'"
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
            "For_each": {
                "type": "Foreach",
                "foreach": "@body('HTTP')['value']",
                "actions": {
                    "Condition_PriorityScore_below_25": {
                        "type": "If",
                        "expression": {
                            "and": [
                                {
                                    "not": {
                                        "equals": [
                                            "@item()?['priorityScore']",
                                            null
                                        ]
                                    }
                                },
                                {
                                    "less": [
                                        "@item()?['priorityScore']",
                                        25
                                    ]
                                }
                            ]
                        },
                        "actions": {
                            "HTTP_PATCH_Close_Incident": {
                                "type": "Http",
                                "inputs": {
                                    "uri": "https://graph.microsoft.com/v1.0/security/incidents/@{item()?['id']}",
                                    "method": "PATCH",
                                    "headers": {
                                        "Content-Type": "application/json"
                                    },
                                    "body": {
                                        "status": "resolved",
                                        "resolvingComment": "Auto-closed: priorityScore below threshold (25)",
                                        "customTags": "@union(item()?['customTags'], createArray('LowPrioScore'))"
                                    },
                                    "authentication": {
                                        "type": "ManagedServiceIdentity",
                                        "audience": "https://graph.microsoft.com"
                                    }
                                }
                            }
                        },
                        "else": {
                            "actions": {}
                        }
                    }
                },
                "runAfter": {
                    "HTTP": [
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
