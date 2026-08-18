# KQLSearch MCP Integration in GitHub Copilot (VS Code)

This guide explains how to integrate the hosted KQLSearch MCP server into GitHub Copilot in Visual Studio Code.

- MCP endpoint: `https://www.kqlsearch.com/mcp`
- Transport: HTTP (Streamable HTTP)
- Authentication: none (no API key, no OAuth)

## What you get

After setup, Copilot can call KQLSearch MCP tools from chat to find and reuse community KQL examples.

Common tools exposed by the server include:

- `search_kql_queries`
- `get_kql_query`
- `list_kql_metadata`

## Prerequisites

1. Visual Studio Code (recent version).
2. GitHub Copilot extension installed and signed in.
3. MCP support available in your VS Code/Copilot setup.

## Option A: Guided setup in VS Code (recommended)

Use this if you want the easiest installation flow.

1. Open the Command Palette (`Ctrl+Shift+P`).
2. Run `MCP: Add Server`.
3. In the prompt that appears, choose the server type or setup flow offered by VS Code for an HTTP MCP server.
4. Enter the URL: `https://www.kqlsearch.com/mcp`.
6. Enter a server name/ID, for example: `kql-search`.
7. Save and confirm trust when VS Code prompts you.
8. Start (or restart) the server if needed via `MCP: List Servers`.

## Option B: Manual setup via mcp.json

Use this when you prefer direct config control.

### User-level configuration (global for all workspaces)

Use this if you want the KQLSearch MCP server available in every project and not only in one repository.

On Windows, the global VS Code config is stored here:

`C:\Users\benjamin.zulliger\AppData\Roaming\Code\User\mcp.json`

1. Open Command Palette (`Ctrl+Shift+P`).
2. Run `MCP: Open User Configuration`.
3. Add this configuration to `mcp.json`:

```json
{
	"servers": {
		"kql-search": {
			"type": "http",
			"url": "https://www.kqlsearch.com/mcp"
		}
	}
}
```

4. Save the file.
5. Run `MCP: List Servers` and start `kql-search` if it is not already running.

<img width="792" height="162" alt="MCP: List Server" src="https://github.com/user-attachments/assets/b0b64e9a-b73d-4fb7-8a86-2df8609e55c4" />

<img width="603" height="89" alt="Add MCP Server" src="https://github.com/user-attachments/assets/6af07473-3e18-4a15-9f5a-dba266c3eb62" />

<img width="617" height="67" alt="Start Server" src="https://github.com/user-attachments/assets/f03d66ed-b6e3-4ed6-b566-a679e407cf5d" />

<img width="669" height="436" alt="Console Output Server starting" src="https://github.com/user-attachments/assets/59d25c68-a5c4-4398-9a52-191dff799c87" />

<img width="731" height="771" alt="MCP Server Test" src="https://github.com/user-attachments/assets/8488d3df-49aa-4b35-a1bd-a1962013eb1a" />


### Workspace-level configuration (only for one project)

Use this if the MCP should be available only in a specific repository or workspace.

1. In your project, create or open `.vscode/mcp.json`.
2. Add the same JSON configuration shown above.
3. Save and commit `.vscode/mcp.json` if you want teammates to reuse it.

This project-scoped variant is the one stored under:

`.vscode/mcp.json`

Use the user-scoped file in `C:\Users\benjamin.zulliger\AppData\Roaming\Code\User\mcp.json` when you want the server globally across all projects.

## Verify the integration

1. Open Copilot Chat in VS Code.
2. Ensure `kql-search` is enabled in tool configuration.
3. Run a test prompt like:

```text
Use the kql-search MCP tools to find KQL queries for failed sign-ins in Entra ID,
then propose a production-ready query with explanations.
```

4. Confirm Copilot invokes KQLSearch tools and returns KQL examples/metadata.

### Optional low-level protocol check (PowerShell)

Use this if you want to verify the endpoint independent of the VS Code UI.

```powershell
$headers = @{
	'Accept' = 'application/json, text/event-stream'
	'MCP-Protocol-Version' = '2025-03-26'
}

$init = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"mcp-test","version":"1.0"}}}'
Invoke-WebRequest -Uri 'https://www.kqlsearch.com/mcp' -Method Post -Headers $headers -ContentType 'application/json' -Body $init
```

Expected result:

- HTTP status `200`
- `Content-Type: text/event-stream`
- JSON-RPC `result` with server info (for example `"name":"kql-search"`)

You can also list tools:

```powershell
$tools = '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
Invoke-WebRequest -Uri 'https://www.kqlsearch.com/mcp' -Method Post -Headers $headers -ContentType 'application/json' -Body $tools
```

Expected tools include:

- `search_kql_queries`
- `get_kql_query`
- `list_kql_metadata`

## Troubleshooting

If tools do not appear or are not called:

1. Check server status with `MCP: List Servers`.
2. Open logs:
	 - Chat error indicator -> `Show Output`, or
	 - `MCP: List Servers` -> select `kql-search` -> `Show Output`.
3. Verify URL exactly matches:
	 - `https://www.kqlsearch.com/mcp`
4. If you run low-level HTTP checks, include:
	 - `Accept: application/json, text/event-stream`
	 - `MCP-Protocol-Version: 2025-03-26`
5. Confirm the server is enabled (not disabled for current workspace/profile).
6. Restart VS Code after config changes.
7. Re-run `MCP: Reset Trust` and trust the server again if trust state is broken.

## Security and data handling notes

- KQLSearch MCP is read-only and returns reference content.
- Retrieved KQL should be treated as untrusted input and reviewed before production use.
- Do not add secrets to this MCP configuration; this endpoint does not require credentials.

## Maintenance

- To disable temporarily: use `MCP: List Servers` -> disable `kql-search`.
- To remove permanently: delete the `kql-search` entry from `mcp.json`.
- To share across devices: enable Settings Sync for MCP server configuration.

## Quick reference

- Name: `kql-search`
- Type: `http`
- URL: `https://www.kqlsearch.com/mcp`
- Auth: `none`

