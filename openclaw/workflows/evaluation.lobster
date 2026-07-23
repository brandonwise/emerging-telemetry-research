name: threat-radar-evaluation
args:
  suite:
    default: "weekly-production-retrospective"
steps:
  - id: prepare
    command: threat-radar eval prepare --suite "$LOBSTER_ARG_SUITE" --json
  - id: replay
    command: threat-radar eval replay --json
    stdin: $prepare.json
  - id: injection
    command: threat-radar eval injection --json
    stdin: $prepare.json
  - id: reliability
    command: threat-radar eval reliability --json
    stdin: $prepare.json
  - id: score
    command: threat-radar eval score --json
    stdin: $replay.json
  - id: publish
    command: threat-radar eval report --json
    stdin: $score.json
