#!/usr/bin/env python3
"""Plan and merge reusable Terminal-Bench trial directories."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TERMINALBENCH_TASK_PREFIX = "terminal-bench/"


def display_task_name(value: str) -> str:
    return value.strip().removeprefix(TERMINALBENCH_TASK_PREFIX)


def load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def iso_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def normalize_optional(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def same_float(left: Any, right: float) -> bool:
    try:
        return abs(float(left) - right) < 1e-9
    except (TypeError, ValueError):
        return False


def iter_run_json_paths(results_dir: Path, sources: list[Path]) -> list[Path]:
    if sources:
        paths: list[Path] = []
        for source in sources:
            if source.is_file() and source.name == "run.json":
                paths.append(source)
            elif source.is_dir() and (source / "run.json").exists():
                paths.append(source / "run.json")
            else:
                raise SystemExit(
                    f"error: --reuse-from expects a structured run dir or run.json: {source}"
                )
        return paths
    return sorted(results_dir.glob("runs/*/run.json"))


def run_sort_key(run: dict[str, Any], path: Path) -> str:
    timing = run.get("timing") if isinstance(run.get("timing"), dict) else {}
    return (
        str(timing.get("finished_at") or "")
        or str(run.get("exported_at") or "")
        or path.parent.name
    )


def params_match(params: dict[str, Any], args: argparse.Namespace) -> tuple[bool, str | None]:
    expected = {
        "agent": args.agent,
        "dataset": args.dataset,
        "execution_mode": args.execution_mode,
        "requested_model": normalize_optional(args.requested_model),
        "variant": normalize_optional(args.variant),
        "context_approach": normalize_optional(args.context_approach),
        "harbor_env": args.harbor_env,
        "attempts": args.attempts,
        "extra_args": args.extra_arg,
    }
    for key, expected_value in expected.items():
        actual = params.get(key)
        if key == "attempts":
            if int(actual or 0) != int(expected_value):
                return False, f"{key} mismatch"
        elif actual != expected_value:
            return False, f"{key} mismatch"

    if not same_float(params.get("timeout_multiplier"), args.timeout_multiplier):
        return False, "timeout_multiplier mismatch"

    if args.agent_version:
        if params.get("agent_version") != args.agent_version:
            return False, "agent_version mismatch"

    if args.provider_kind:
        provider = params.get("provider") if isinstance(params.get("provider"), dict) else {}
        if provider.get("active_provider") != args.provider_kind:
            return False, "provider mismatch"

    task_scope = params.get("task_scope") if isinstance(params.get("task_scope"), dict) else {}
    if task_scope.get("scope_mismatch"):
        return False, "source run has task scope mismatch"

    return True, None


def collect_source_runs(args: argparse.Namespace) -> list[tuple[Path, dict[str, Any]]]:
    candidates: list[tuple[Path, dict[str, Any]]] = []
    for run_json_path in iter_run_json_paths(args.results_dir, args.reuse_from):
        run = load_json(run_json_path)
        params = run.get("params") if isinstance(run.get("params"), dict) else {}
        matched, _reason = params_match(params, args)
        if not matched:
            continue
        source_job_dir = Path(str(run.get("source_job_dir") or ""))
        if not source_job_dir.exists():
            continue
        candidates.append((run_json_path, run))
    candidates.sort(key=lambda item: run_sort_key(item[1], item[0]), reverse=True)
    return candidates


def plan_reuse(args: argparse.Namespace) -> dict[str, Any]:
    requested_tasks = {display_task_name(task) for task in args.requested_task if task.strip()}
    attempts = int(args.attempts)
    selected: dict[str, list[dict[str, Any]]] = {}
    matched_sources: list[str] = []

    for run_json_path, run in collect_source_runs(args):
        matched_sources.append(str(run_json_path.parent))
        source_job_dir = Path(str(run.get("source_job_dir")))
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for trial in run.get("trials") or []:
            if not isinstance(trial, dict):
                continue
            task_name_raw = trial.get("task_name")
            trial_name = trial.get("trial_name")
            if not isinstance(task_name_raw, str) or not isinstance(trial_name, str):
                continue
            task_name = display_task_name(task_name_raw)
            if requested_tasks and task_name not in requested_tasks:
                continue
            if task_name in selected:
                continue
            if trial.get("status") not in {"pass", "fail"}:
                continue
            if not isinstance(trial.get("reward"), (float, int)):
                continue
            source_trial_dir = source_job_dir / trial_name
            if not (source_trial_dir / "result.json").exists():
                continue
            grouped[task_name].append(
                {
                    "task_name": task_name,
                    "trial_name": trial_name,
                    "status": trial.get("status"),
                    "reward": trial.get("reward"),
                    "source_run_dir": str(run_json_path.parent),
                    "source_job_dir": str(source_job_dir),
                    "source_trial_dir": str(source_trial_dir),
                }
            )

        for task_name, trials in sorted(grouped.items()):
            if task_name in selected:
                continue
            if len(trials) >= attempts:
                selected[task_name] = sorted(trials, key=lambda item: item["trial_name"])[:attempts]

    reusable_tasks = sorted(selected)
    plan = {
        "schema_version": 1,
        "created_at": iso_now(),
        "settings": {
            "agent": args.agent,
            "dataset": args.dataset,
            "execution_mode": args.execution_mode,
            "requested_model": normalize_optional(args.requested_model),
            "variant": normalize_optional(args.variant),
            "context_approach": normalize_optional(args.context_approach),
            "provider_kind": normalize_optional(args.provider_kind),
            "agent_version": normalize_optional(args.agent_version),
            "harbor_env": args.harbor_env,
            "attempts": attempts,
            "timeout_multiplier": args.timeout_multiplier,
            "extra_args": args.extra_arg,
            "requested_tasks": sorted(requested_tasks),
        },
        "sources_matched": matched_sources,
        "reusable_tasks": reusable_tasks,
        "reused_trial_count": sum(len(trials) for trials in selected.values()),
        "tasks": selected,
    }
    args.plan_path.parent.mkdir(parents=True, exist_ok=True)
    args.plan_path.write_text(json.dumps(plan, indent=2) + "\n")
    return plan


def scrub_copied_trial(dst: Path) -> None:
    config_path = dst / "agent" / "lash-home" / "config.json"
    try:
        config_path.unlink(missing_ok=True)
    except OSError:
        pass


def synthesize_job_files(target_job_dir: Path, plan: dict[str, Any]) -> None:
    if not (target_job_dir / "result.json").exists():
        payload = {
            "started_at": plan.get("created_at") or iso_now(),
            "finished_at": iso_now(),
            "reused_only": True,
            "reused_trial_count": plan.get("reused_trial_count", 0),
        }
        (target_job_dir / "result.json").write_text(json.dumps(payload, indent=2) + "\n")
    if not (target_job_dir / "config.json").exists():
        settings = plan.get("settings") if isinstance(plan.get("settings"), dict) else {}
        payload = {
            "job_name": target_job_dir.name,
            "reused_only": True,
            "n_attempts": settings.get("attempts"),
            "timeout_multiplier": settings.get("timeout_multiplier"),
            "agent": settings.get("agent"),
            "dataset": settings.get("dataset"),
        }
        (target_job_dir / "config.json").write_text(json.dumps(payload, indent=2) + "\n")


def merge_reuse(args: argparse.Namespace) -> dict[str, Any]:
    plan = load_json(args.plan_path)
    target_job_dir = args.target_job_dir
    target_job_dir.mkdir(parents=True, exist_ok=True)

    copied: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for task_name, trials in sorted((plan.get("tasks") or {}).items()):
        if not isinstance(trials, list):
            continue
        for trial in trials:
            if not isinstance(trial, dict):
                continue
            source = Path(str(trial.get("source_trial_dir") or ""))
            trial_name = str(trial.get("trial_name") or "")
            target = target_job_dir / trial_name
            if not source.exists() or not trial_name:
                skipped.append({**trial, "reason": "source missing"})
                continue
            if target.exists():
                skipped.append({**trial, "reason": "target exists"})
                continue
            shutil.copytree(source, target)
            scrub_copied_trial(target)
            copied.append({**trial, "target_trial_dir": str(target)})

    manifest = {
        "schema_version": 1,
        "merged_at": iso_now(),
        "plan_path": str(args.plan_path),
        "copied_trial_count": len(copied),
        "skipped_trial_count": len(skipped),
        "reused_tasks": sorted({trial["task_name"] for trial in copied}),
        "copied_trials": copied,
        "skipped_trials": skipped,
    }
    (target_job_dir / "reused-trials.json").write_text(json.dumps(manifest, indent=2) + "\n")
    synthesize_job_files(target_job_dir, plan)
    return manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan = subparsers.add_parser("plan")
    plan.add_argument("--results-dir", type=Path, required=True)
    plan.add_argument("--plan-path", type=Path, required=True)
    plan.add_argument("--agent", required=True)
    plan.add_argument("--dataset", required=True)
    plan.add_argument("--execution-mode", required=True)
    plan.add_argument("--requested-model")
    plan.add_argument("--variant")
    plan.add_argument("--context-approach")
    plan.add_argument("--provider-kind")
    plan.add_argument("--agent-version")
    plan.add_argument("--harbor-env", required=True)
    plan.add_argument("--attempts", type=int, required=True)
    plan.add_argument("--timeout-multiplier", type=float, required=True)
    plan.add_argument("--extra-arg", action="append", default=[])
    plan.add_argument("--requested-task", action="append", default=[])
    plan.add_argument("--reuse-from", type=Path, action="append", default=[])

    merge = subparsers.add_parser("merge")
    merge.add_argument("--plan-path", type=Path, required=True)
    merge.add_argument("--target-job-dir", type=Path, required=True)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "plan":
        plan = plan_reuse(args)
        for task_name in plan["reusable_tasks"]:
            print(task_name)
        print(
            f"reuse plan: {plan['reused_trial_count']} trials across "
            f"{len(plan['reusable_tasks'])} tasks",
            file=sys.stderr,
        )
        return 0
    if args.command == "merge":
        manifest = merge_reuse(args)
        print(
            f"merged reused trials: copied={manifest['copied_trial_count']} "
            f"skipped={manifest['skipped_trial_count']}"
        )
        return 0
    raise AssertionError(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
