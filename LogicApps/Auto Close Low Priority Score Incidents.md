<img width="1279" height="720" alt="image" src="https://github.com/user-attachments/assets/aa964c5c-ef2e-47c3-94a0-76e0d75da0d0" />


**Description**

Azure Logic App to automatically close low-priority Microsoft Defender incidents based on the Priority Score. Incidents below a configurable threshold are resolved via Microsoft Graph API, reducing SOC noise and alert fatigue while preserving traceability through custom tags.

Link to Full Article: https://www.linkedin.com/pulse/use-microsoft-defender-priority-score-reduce-noise-benjamin-zulliger-ja3re/

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
            "Initialize_Variable_ExcludedTitleKeywords": {
                "type": "InitializeVariable",
                "inputs": {
                    "variables": [
                        {
                            "name": "excludedTitleKeywords",
                            "type": "Array",
                            "value": [
                                "Anomalous Token usage",
                                "demo",
                                "false positive"
                            ]
                        }
                    ]
                },
                "runAfter": {
                    "HTTP": [
                        "Succeeded"
                    ]
                }
            },
            "For_each": {
                "type": "Foreach",
                "foreach": "@body('HTTP')['value']",
                "actions": {
                    "Filter_Excluded_Titles": {
                        "type": "Query",
                        "inputs": {
                            "from": "@variables('excludedTitleKeywords')",
                            "where": "@contains(toLower(items('For_each')?['displayName']), toLower(item()))"
                        }
                    },
                    "Condition_Title_Not_Excluded": {
                        "type": "If",
                        "expression": {
                            "equals": [
                                "@length(body('Filter_Excluded_Titles'))",
                                0
                            ]
                        },
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
                        "else": {
                            "actions": {}
                        },
                        "runAfter": {
                            "Filter_Excluded_Titles": [
                                "Succeeded"
                            ]
                        }
                    }
                },
                "runAfter": {
                    "Initialize_Variable_ExcludedTitleKeywords": [
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
