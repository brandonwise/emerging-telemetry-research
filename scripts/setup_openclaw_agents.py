#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class RoleAgent:
    agent_id: str
    workspace: str
    model: str | None


DENIED_TOOLS = [
    "exec",
    "process",
    "read",
    "write",
    "edit",
    "apply_patch",
    "browser",
    "web_search",
    "web_fetch",
    "message",
    "discord",
    "cron",
    "gateway",
    "nodes",
    "canvas",
    "image",
    "memory_search",
    "memory_get",
    "sessions_spawn",
    "subagents",
]


def expected_agents(repo_root: Path, *, model: str | None = None) -> tuple[RoleAgent, ...]:
    return (
        RoleAgent(
            "research-specialist",
            str(repo_root / "openclaw/agents/specialist"),
            model,
        ),
        RoleAgent(
            "research-impact",
            str(repo_root / "openclaw/agents/impact"),
            model,
        ),
        RoleAgent(
            "research-skeptic",
            str(repo_root / "openclaw/agents/skeptic"),
            model,
        ),
        RoleAgent(
            "research-verifier",
            str(repo_root / "openclaw/agents/verifier"),
            model,
        ),
        RoleAgent(
            "research-chief",
            str(repo_root / "openclaw/agents/coordinator"),
            model,
        ),
    )


def _openclaw_executable() -> str:
    executable = shutil.which("openclaw")
    if executable is None:
        raise RuntimeError("openclaw CLI is not installed or not on PATH")
    return executable


def _run_json(*args: str) -> Any:
    completed = subprocess.run(  # noqa: S603 - executable is resolved from PATH; args are fixed.
        (_openclaw_executable(), *args),
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


def _agent_map() -> dict[str, dict[str, Any]]:
    agents = _run_json("agents", "list", "--json")
    if not isinstance(agents, list):
        raise RuntimeError("OpenClaw agent list returned an unexpected payload")
    return {
        str(agent["id"]): agent
        for agent in agents
        if isinstance(agent, dict) and isinstance(agent.get("id"), str)
    }


def _configured_agents() -> list[dict[str, Any]]:
    agents = _run_json("config", "get", "agents.list", "--json")
    if not isinstance(agents, list):
        raise RuntimeError("OpenClaw agent configuration returned an unexpected payload")
    return [agent for agent in agents if isinstance(agent, dict)]


def _expected_security() -> dict[str, Any]:
    return {
        "tools": {
            "allow": ["session_status"],
            "deny": DENIED_TOOLS,
        },
        "skills": [],
        "memorySearch": {"enabled": False},
    }


def _audit(repo_root: Path, *, model: str | None = None) -> list[str]:
    issues: list[str] = []
    listed = _agent_map()
    configured = {
        str(agent.get("id")): agent
        for agent in _configured_agents()
        if isinstance(agent.get("id"), str)
    }
    security = _expected_security()
    for expected in expected_agents(repo_root, model=model):
        visible = listed.get(expected.agent_id)
        config = configured.get(expected.agent_id)
        if visible is None or config is None:
            issues.append(f"{expected.agent_id}: missing")
            continue
        if visible.get("workspace") != expected.workspace:
            issues.append(f"{expected.agent_id}: workspace mismatch")
        if expected.model is not None and visible.get("model") != expected.model:
            issues.append(f"{expected.agent_id}: model mismatch")
        for key, value in security.items():
            if config.get(key) != value:
                issues.append(f"{expected.agent_id}: {key} policy mismatch")
    return issues


def _install(repo_root: Path, *, model: str | None = None) -> None:
    listed = _agent_map()
    for expected in expected_agents(repo_root, model=model):
        if expected.agent_id in listed:
            continue
        model_arguments = ("--model", expected.model) if expected.model is not None else ()
        subprocess.run(  # noqa: S603 - executable and role arguments are repository constants.
            (
                _openclaw_executable(),
                "agents",
                "add",
                expected.agent_id,
                "--workspace",
                expected.workspace,
                *model_arguments,
                "--non-interactive",
                "--json",
            ),
            check=True,
        )
    configured = _configured_agents()
    indices = {
        str(agent.get("id")): index
        for index, agent in enumerate(configured)
        if isinstance(agent.get("id"), str)
    }
    security = _expected_security()
    operations: list[dict[str, Any]] = []
    for expected in expected_agents(repo_root, model=model):
        index = indices.get(expected.agent_id)
        if index is None:
            raise RuntimeError(f"OpenClaw did not register {expected.agent_id}")
        operations.extend(
            (
                {"path": f"agents.list[{index}].workspace", "value": expected.workspace},
                {"path": f"agents.list[{index}].tools", "value": security["tools"]},
                {"path": f"agents.list[{index}].skills", "value": security["skills"]},
                {
                    "path": f"agents.list[{index}].memorySearch",
                    "value": security["memorySearch"],
                },
            )
        )
        if expected.model is not None:
            operations.append(
                {"path": f"agents.list[{index}].model", "value": expected.model}
            )
    subprocess.run(  # noqa: S603 - executable and config paths are repository constants.
        (
            _openclaw_executable(),
            "config",
            "set",
            "--batch-json",
            json.dumps(operations, separators=(",", ":")),
        ),
        check=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check or install Telemetry Research's isolated OpenClaw role agents."
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Create missing agents and apply the reviewed workspace/model/security policy.",
    )
    parser.add_argument(
        "--model",
        default=os.environ.get("ETR_AGENT_MODEL") or None,
        help="Optional approved model override. Omit it to preserve the OpenClaw default.",
    )
    args = parser.parse_args()
    repo_root = Path(__file__).resolve().parent.parent
    initial_issues = _audit(repo_root, model=args.model)
    changed = bool(args.apply and initial_issues)
    if changed:
        _install(repo_root, model=args.model)
    issues = _audit(repo_root, model=args.model)
    if issues:
        print("OpenClaw role-agent audit failed:")
        for issue in issues:
            print(f"- {issue}")
        if not args.apply:
            print("Run `make openclaw-agents-install` to apply the scoped configuration.")
        return 1
    if changed:
        print("Configuration changed; restart the OpenClaw gateway before running agent evals.")
    elif args.apply:
        print("OpenClaw role-agent configuration already matched; no changes were made.")
    print(
        "OpenClaw role-agent audit passed: "
        "5 agents, isolated workspaces, scoped tool/memory policy."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
