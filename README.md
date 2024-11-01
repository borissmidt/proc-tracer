# Proc tracer

Proc tracer tracks the processes running in the system and logs the time and arg of the command.

this project uses auqa for cli tool management:
https://aquaproj.github.io/

usage:
```bash
go generate ./...
sudo go run .
# for jsons logging 1 json per line
sudo go run . --json
```