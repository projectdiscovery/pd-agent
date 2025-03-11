## Setup

## Pdtm-Agent Setup
Start a local instance of punchhole from https://github.com/projectdiscovery/aurora/pull/1741 
```
mzack@m punch-hole % pwd     
/Users/mzack/go/src/github.com/projectdiscovery/aurora/cmd/punch-hole
mzack@m punch-hole % go run .
```

Run pdtm-agent from https://github.com/projectdiscovery/pdtm-agent/pull/1 in mcp mode

```console
PDCP_API_KEY=xxx PDCP_TEAM_ID=yyy PDCP_API_SERVER=https://api.dev.projectdiscovery.io PUNCH_HOLE_HOST=127.0.0.1 PUNCH_HOLE_HTTP_PORT=8880 go run . -agent -agent-output test -mcp
```

## Claude Setup
- Edit if existing or create `claude_desktop_config.json` in `/Users/<username>/Library/Application Support/Claude`

Compile `openapi-mcp` in `cmd/openapi-mcp`
```console
$ go build -o openapi-mcp
```

Adjust the path of `command` and `open-api` config file in the json:
```json
{
    "mcpServers": {
        "openapi-mcp": {
            "command": "/path/to/openapi-mcp",
            "args": [
                "-openapi",
                "/path/to/open-api/yaml/openapi-pdtm.yaml",
                "-url",
                "http://localhost:54321"
            ]
        }
	}
}
```

## Example dialogues with Claude:
```
Prompt:
I want to make a scan of targets:
scanme.sh
with the template
"http/technologies/tech-detect.yaml"
the name of the scan should be:
claude [pdtm-agent]

Response:
Great news! The scan has been successfully created. Here are the details:

Scan ID: cv85a39e5k6c73c9tl6g
Name: claude [pdtm-agent]
Target: scanme.sh
Template: http/technologies/tech-detect.yaml
Status: Successfully triggered

The scan is now running in the system. Would you like me to check the status of all tasks to see if your scan is showing up in the running tasks?

Prompt:
Yes

Response:
Let me check the current status of all tasks, which should include your scan.

Completed Tasks:

Task cu3922ljomjs73airo20-2025-03-11 16:35:00 +0000 UTC: {}
Task cv83km1p47mc7383jj5g-0001-01-01 00:00:00 +0000 UTC: {}
Task cv84dtpp47mc7383jj6g-0001-01-01 00:00:00 +0000 UTC: {}

Running Tasks:

I've checked the status of all tasks, and here's what I found:
Queued Tasks:

None currently in queue

Completed Tasks:

Task cu3922ljomjs73airo20 (completed at 2025-03-11 16:35:00 UTC) - This appears to be a recent task
Task cv83km1p47mc7383jj5g (completed at 0001-01-01 00:00:00 UTC)
Task cv84dtpp47mc7383jj6g (completed at 0001-01-01 00:00:00 UTC)

Running Tasks:
Task cv85a39e5k6c73c9tl6g

your scan with ID cv85a39e5k6c73c9tl6g is still running.

Would you like me to try checking the status again in a moment to see if there are any changes?
```