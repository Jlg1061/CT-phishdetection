#!/usr/bin/env python3
"""Automated grading harness for CSEC 520/620 project repos.

Runs the OBJECTIVE checks a grading agent needs as evidence, then writes
grading/auto_report.json. The agent reads that file, adds qualitative judgment
(report quality, correctness, security relevance), and produces the final grade
per grading/AGENT_GRADING.md.

Stdlib only. Run from the repo root:  python grading/grade.py

Project-specific checks: set `project: p5` in config.yaml (or pass --project p5)
to grade Project 5 (the SVM bonus project) against grading/rubric_p5.yaml and the
results schema in grading/P5_METRICS.md. Without it, the generic checks below run
unchanged.
"""
from __future__ import annotations
import argparse, json, os, re, subprocess, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REQUIRED = ["config.yaml", "src/train.py", "src/data.py", "src/model.py",
            "src/evaluate.py", "README.md", "requirements.txt"]
METRIC_KEYS = {"accuracy", "precision", "recall", "f1", "roc_auc"}

# Prefer the project venv if it exists, so the harness works whether or not it's activated.
_venv = ROOT / ".venv" / "bin" / "python"
PYEXE = str(_venv) if _venv.exists() else sys.executable


def run(cmd, timeout=900):
    """Run a command from ROOT; return (returncode, tail_of_output)."""
    try:
        p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                           timeout=timeout)
        out = (p.stdout + p.stderr)[-4000:]
        return p.returncode, out
    except subprocess.TimeoutExpired:
        return 124, f"TIMEOUT after {timeout}s"
    except FileNotFoundError as e:
        return 127, str(e)


def check_structure(required=REQUIRED):
    missing = [f for f in required if not (ROOT / f).exists()]
    return {"id": "structure", "status": "pass" if not missing else "fail",
            "evidence": "all present" if not missing else f"missing: {missing}"}


def check_tests():
    rc, out = run([PYEXE, "-m", "pytest", "-q"], timeout=300)
    status = "pass" if rc == 0 else ("dep_missing" if "No module named" in out else "fail")
    return {"id": "tests", "status": status, "returncode": rc, "evidence": out[-800:]}


def check_reproduce(cmd=None, timeout=900):
    cmd = cmd or [PYEXE, "-m", "src.train", "--config", "config.yaml"]
    rc, out = run(cmd, timeout=timeout)
    if rc == 0:
        status = "pass"
    elif "No module named" in out:
        status = "dep_missing"   # e.g., torch not installed in grader env
    else:
        status = "fail"
    return {"id": "reproduce_runs", "status": status, "returncode": rc,
            "evidence": out[-1200:]}


def check_metrics():
    p = ROOT / "results" / "metrics.json"
    if not p.exists():
        return {"id": "metrics_present", "status": "fail",
                "evidence": "results/metrics.json not found"}
    try:
        m = json.loads(p.read_text())
    except Exception as e:
        return {"id": "metrics_present", "status": "fail", "evidence": f"invalid JSON: {e}"}
    missing = METRIC_KEYS - set(m)
    bad = {k: v for k, v in m.items() if isinstance(v, (int, float)) and not (0 <= v <= 1)}
    ok = not missing and not bad
    return {"id": "metrics_present", "status": "pass" if ok else "fail",
            "evidence": {"metrics": m, "missing_keys": sorted(missing), "out_of_range": bad}}


def check_leakage():
    """Heuristic scan for common data-leakage patterns (agent should confirm)."""
    hits = []
    patterns = [r"fit_transform\s*\(\s*X\s*\)", r"\.fit\s*\(\s*X\s*[\),]",
                r"StandardScaler\(\)\.fit\(X\)"]
    for pyf in (ROOT / "src").glob("*.py"):
        text = pyf.read_text(errors="ignore")
        for pat in patterns:
            for m in re.finditer(pat, text):
                hits.append(f"{pyf.name}: {m.group(0)}")
    return {"id": "leakage_scan",
            "status": "review" if hits else "clean",
            "evidence": hits or "no obvious full-data fit before split (heuristic only)"}


def check_report():
    rdir = ROOT / "report"
    files = [p.name for p in rdir.glob("**/*") if p.suffix.lower() in {".tex", ".pdf", ".md"}] if rdir.exists() else []
    has_real = any(f.lower().endswith((".tex", ".pdf")) for f in files)
    return {"id": "report_present",
            "status": "pass" if has_real else "review",
            "evidence": f"report files: {files}" if files else "no report/ .tex or .pdf found"}


def check_git_hygiene():
    gi = (ROOT / ".gitignore")
    txt = gi.read_text() if gi.exists() else ""
    committed_data = [p.name for p in (ROOT / "data").glob("*")
                      if p.name not in {"README.md", ".gitkeep"}] if (ROOT / "data").exists() else []
    ok = "data/" in txt and "results/" in txt
    return {"id": "git_hygiene", "status": "pass" if ok else "review",
            "evidence": {"gitignore_covers_data_results": ok,
                         "possible_committed_data": committed_data}}


# ---------------------------------------------------------------------------
# Project 5 (bonus): SVMs for intrusion detection on UNSW-NB15
# ---------------------------------------------------------------------------
P5_REQUIRED = ["config.yaml", "README.md", "requirements.txt", "Makefile", "SUBMISSION.md"]
P5_LINEAR_C = (0.01, 0.1, 1, 10, 100)
P5_RBF_C = (0.1, 1, 10, 100)
P5_RBF_GAMMA = (0.001, 0.01, 0.1, 1)
P5_NU = (0.01, 0.05, 0.1)
P5_METRICS = ("precision", "recall", "f1", "fpr")
P5_CATEGORIES = ("analysis", "backdoor", "dos", "exploits", "fuzzers", "generic",
                 "reconnaissance", "shellcode", "worms")
P5_OFFICIAL = {"train_rows": 175341, "test_rows": 82332, "subsample_rows": 20000}
TOL = 1e-3


def _num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _in01(v):
    return _num(v) and 0 <= v <= 1


def _same(a, b):
    return _num(a) and _num(b) and abs(float(a) - float(b)) <= 1e-9 * max(1.0, abs(float(b)))


def _result(cid, problems, review, data):
    status = "fail" if problems else ("review" if review else "pass")
    ev = {"problems": problems, "review": review}
    ev.update(data)
    return {"id": cid, "status": status, "evidence": ev}


def _metric_block(block, where, problems):
    if not isinstance(block, dict):
        problems.append(f"{where}: missing or not an object")
        return
    for k in P5_METRICS:
        if not _in01(block.get(k)):
            problems.append(f"{where}.{k}: missing or outside [0, 1]")


def _load_metrics():
    p = ROOT / "results" / "metrics.json"
    if not p.exists():
        return None, "results/metrics.json not found"
    try:
        return json.loads(p.read_text()), None
    except Exception as e:
        return None, f"invalid JSON: {e}"


def check_p5_data(m):
    problems, review = [], []
    d = m.get("data")
    if not isinstance(d, dict):
        return _result("p5_data", ["data: missing block (see grading/P5_METRICS.md)"], [], {})
    for k in ("train_rows", "test_rows", "subsample_rows", "seed", "n_features"):
        if not isinstance(d.get(k), int) or isinstance(d.get(k), bool):
            problems.append(f"data.{k}: missing or not an integer")
    if d.get("source") == "synthetic":
        problems.append("data.source is 'synthetic': these are dry-run numbers; run make reproduce on UNSW-NB15")
    for k, v in P5_OFFICIAL.items():
        if isinstance(d.get(k), int) and d[k] != v:
            review.append(f"data.{k} = {d[k]}, expected {v} (official partition / handout); "
                          "confirm the student explains the difference")
    return _result("p5_data", problems, review, {"data": d})


def check_p5_linear(m):
    problems, review = [], []
    b = m.get("linear")
    if not isinstance(b, dict):
        return _result("p5_linear", ["linear: missing block"], [], {})
    _metric_block(b, "linear", problems)
    sweep = b.get("sweep")
    by_c = {}
    if not isinstance(sweep, list):
        problems.append("linear.sweep: missing list")
    else:
        for i, row in enumerate(sweep):
            if not isinstance(row, dict) or not _num(row.get("C")):
                problems.append(f"linear.sweep[{i}]: needs a numeric C")
                continue
            _metric_block(row.get("train"), f"linear.sweep[C={row['C']}].train", problems)
            _metric_block(row.get("test"), f"linear.sweep[C={row['C']}].test", problems)
            by_c[float(row["C"])] = row
        missing = [c for c in P5_LINEAR_C if float(c) not in by_c]
        if missing:
            problems.append(f"linear.sweep: missing C values {missing}; required {list(P5_LINEAR_C)}")
    c = b.get("C")
    if not _num(c):
        problems.append("linear.C: the chosen C is missing")
    elif float(c) not in by_c:
        problems.append(f"linear.C = {c} is not one of the swept values")
    else:
        test = by_c[float(c)].get("test") or {}
        off = [k for k in P5_METRICS if _num(test.get(k)) and _num(b.get(k)) and abs(test[k] - b[k]) > TOL]
        if off:
            review.append(f"linear summary metrics {off} differ from the sweep's test metrics at C={c}")
    tf = b.get("top_features")
    if not isinstance(tf, list) or len(tf) != 10 or not all(
            isinstance(x, dict) and isinstance(x.get("feature"), str) and _num(x.get("weight")) for x in tf):
        problems.append("linear.top_features: needs exactly 10 {feature, weight} entries")
    else:
        w = [abs(x["weight"]) for x in tf]
        if w != sorted(w, reverse=True):
            review.append("linear.top_features is not sorted by |weight|, largest first")
    if not _num(b.get("train_seconds")) or b["train_seconds"] < 0:
        problems.append("linear.train_seconds: missing (needed for the time comparison)")
    return _result("p5_linear", problems, review,
                   {"chosen_C": c, "swept_C": sorted(by_c), "test_f1": b.get("f1")})


def check_p5_rbf(m):
    problems, review = [], []
    b = m.get("rbf")
    if not isinstance(b, dict):
        return _result("p5_rbf", ["rbf: missing block"], [], {})
    _metric_block(b, "rbf", problems)
    grid = b.get("grid")
    cells = {}
    if not isinstance(grid, list):
        problems.append("rbf.grid: missing list")
    else:
        for i, row in enumerate(grid):
            if not isinstance(row, dict) or not _num(row.get("C")) or not _num(row.get("gamma")):
                problems.append(f"rbf.grid[{i}]: needs numeric C and gamma")
                continue
            for k in ("train_f1", "cv_f1"):
                if not _in01(row.get(k)):
                    problems.append(f"rbf.grid[C={row['C']}, gamma={row['gamma']}].{k}: missing or outside [0, 1]")
            cells[(float(row["C"]), float(row["gamma"]))] = row
        missing = [(c, g) for c in P5_RBF_C for g in P5_RBF_GAMMA if (float(c), float(g)) not in cells]
        if missing:
            problems.append(f"rbf.grid: missing {len(missing)} of 16 (C, gamma) settings, e.g. {missing[:4]}")
    c, g = b.get("C"), b.get("gamma")
    if not (_num(c) and _num(g)):
        problems.append("rbf.C / rbf.gamma: the chosen setting is missing")
    elif (float(c), float(g)) not in cells:
        problems.append(f"rbf chosen setting (C={c}, gamma={g}) is not in the grid")
    else:
        valid = [r for r in cells.values() if _in01(r.get("cv_f1"))]
        if valid:
            best = max(r["cv_f1"] for r in valid)
            if cells[(float(c), float(g))].get("cv_f1", -1) < best - TOL:
                review.append(f"rbf chosen setting has cv_f1 {cells[(float(c), float(g))].get('cv_f1')} "
                              f"but the grid's best is {best}; the handout asks for the best CV setting")
    gaps = sorted(((r["train_f1"] - r["cv_f1"], k) for k, r in cells.items()
                   if _in01(r.get("train_f1")) and _in01(r.get("cv_f1"))), reverse=True)
    nsv = b.get("n_support_vectors")
    sub = (m.get("data") or {}).get("subsample_rows")
    if not isinstance(nsv, int) or isinstance(nsv, bool) or nsv <= 0:
        problems.append("rbf.n_support_vectors: missing or not a positive integer")
    elif isinstance(sub, int) and nsv > sub:
        problems.append(f"rbf.n_support_vectors = {nsv} exceeds the training subsample ({sub})")
    if not _num(b.get("train_seconds")) or b["train_seconds"] < 0:
        problems.append("rbf.train_seconds: missing (needed for the time comparison)")
    return _result("p5_rbf", problems, review,
                   {"chosen": {"C": c, "gamma": g}, "grid_cells": len(cells), "test_f1": b.get("f1"),
                    "largest_train_cv_gaps": [{"C": k[0], "gamma": k[1], "gap": round(v, 4)} for v, k in gaps[:3]],
                    "n_support_vectors": nsv})


def check_p5_one_class(m):
    problems, review = [], []
    b = m.get("one_class")
    if not isinstance(b, dict):
        return _result("p5_one_class", ["one_class: missing block"], [], {})
    _metric_block(b, "one_class", problems)
    runs = b.get("runs")
    by_nu = {}
    if not isinstance(runs, list):
        problems.append("one_class.runs: missing list")
    else:
        for i, row in enumerate(runs):
            if not isinstance(row, dict) or not _num(row.get("nu")):
                problems.append(f"one_class.runs[{i}]: needs a numeric nu")
                continue
            nu = row["nu"]
            for k in ("detection_rate", "fpr"):
                if not _in01(row.get(k)):
                    problems.append(f"one_class.runs[nu={nu}].{k}: missing or outside [0, 1]")
            pc = row.get("per_category")
            if not isinstance(pc, dict) or not pc:
                problems.append(f"one_class.runs[nu={nu}].per_category: missing")
            else:
                bad = [k for k, v in pc.items() if not _in01(v)]
                if bad:
                    problems.append(f"one_class.runs[nu={nu}].per_category: values outside [0, 1] for {bad}")
                have = {k.strip().lower() for k in pc}
                miss = [c for c in P5_CATEGORIES if c not in have]
                if miss:
                    review.append(f"one_class.runs[nu={nu}].per_category is missing attack categories {miss}")
                if "normal" in have:
                    review.append(f"one_class.runs[nu={nu}].per_category includes 'normal'; it should list attack categories only")
            by_nu[float(nu)] = row
        missing = [n for n in P5_NU if float(n) not in by_nu]
        if missing:
            problems.append(f"one_class.runs: missing nu values {missing}; required {list(P5_NU)}")
    nu = b.get("nu")
    if not _num(nu):
        problems.append("one_class.nu: the chosen nu is missing")
    elif float(nu) not in by_nu:
        problems.append(f"one_class.nu = {nu} is not one of the runs")
    else:
        run = by_nu[float(nu)]
        if _num(run.get("detection_rate")) and _num(b.get("recall")) and abs(run["detection_rate"] - b["recall"]) > TOL:
            review.append("one_class.recall differs from the chosen run's detection_rate")
        if _num(run.get("fpr")) and _num(b.get("fpr")) and abs(run["fpr"] - b["fpr"]) > TOL:
            review.append("one_class.fpr differs from the chosen run's fpr")
    return _result("p5_one_class", problems, review,
                   {"chosen_nu": nu, "nu_runs": sorted(by_nu),
                    "detection_rates": {n: by_nu[n].get("detection_rate") for n in sorted(by_nu)}})


def check_p5_figures():
    rdir = ROOT / "results"
    figs = sorted(p.name for p in rdir.glob("**/*") if p.suffix.lower() in {".png", ".pdf", ".svg"}) if rdir.exists() else []
    return {"id": "p5_figures", "status": "pass" if len(figs) >= 3 else "review",
            "evidence": {"figures": figs,
                         "expected": "C sweep plot, C x gamma heatmap, per-category detection figure or table"}}


def p5_checks(before_mtime):
    m, err = _load_metrics()
    if m is None:
        ids = ("p5_metrics_fresh", "p5_data", "p5_linear", "p5_rbf", "p5_one_class")
        return [{"id": i, "status": "fail", "evidence": err} for i in ids]
    p = ROOT / "results" / "metrics.json"
    after = p.stat().st_mtime
    fresh = {"id": "p5_metrics_fresh",
             "status": "pass" if before_mtime is None or after > before_mtime else "review",
             "evidence": ("results/metrics.json was written by make reproduce"
                          if before_mtime is None or after > before_mtime else
                          "results/metrics.json was NOT rewritten by make reproduce; the reported numbers "
                          "may be stale. Check that the Makefile regenerates them.")}
    return [fresh, check_p5_data(m), check_p5_linear(m), check_p5_rbf(m), check_p5_one_class(m),
            check_p5_figures()]


def detect_project(cli):
    if cli:
        return cli.lower()
    cfg = ROOT / "config.yaml"
    if cfg.exists():
        mt = re.search(r"^project:\s*['\"]?([A-Za-z0-9_-]+)", cfg.read_text(), re.M)
        if mt:
            return mt.group(1).lower()
    return "generic"


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--project", help="project id, e.g. p5 (default: config.yaml `project:`)")
    ap.add_argument("--skip-reproduce", action="store_true",
                    help="check the existing results without running make reproduce (for students iterating)")
    args = ap.parse_args()
    project = detect_project(args.project)
    started = time.strftime("%Y-%m-%d %H:%M:%S")
    if project == "p5":
        mp = ROOT / "results" / "metrics.json"
        before = mp.stat().st_mtime if mp.exists() else None
        if args.skip_reproduce:
            repro = {"id": "reproduce_runs", "status": "skipped",
                     "evidence": "--skip-reproduce given; run without it before submitting"}
            before = None
        else:
            # The RBF grid search can take 5-20 minutes on a laptop.
            repro = check_reproduce(["make", "reproduce", f"PY={PYEXE}"], timeout=2700)
        tests = check_tests()
        if tests["returncode"] == 5:   # pytest: no tests collected; tests are optional for P5
            tests["status"] = "review"
        checks = [check_structure(P5_REQUIRED), tests, repro, *p5_checks(before),
                  check_leakage(), check_report(), check_git_hygiene()]
        rubric = "grading/rubric_p5.yaml"
    else:
        checks = [check_structure(), check_tests(), check_reproduce(), check_metrics(),
                  check_leakage(), check_report(), check_git_hygiene()]
        rubric = "grading/rubric.yaml"
    report = {
        "generated": started,
        "repo": str(ROOT.name),
        "project": project,
        "rubric": rubric,
        "checks": checks,
        "note_for_agent": (
            "These are OBJECTIVE signals only. status 'dep_missing' means the grader "
            "environment lacked a dependency (e.g., torch) — set up the env and re-run "
            "before penalizing reproducibility. Confirm heuristic flags (leakage_scan) "
            "by reading the code. Then score every criterion in the rubric named above, "
            "per AGENT_GRADING.md."
        ),
    }
    out = ROOT / "grading" / "auto_report.json"
    out.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    print(f"\nWrote {out}")


if __name__ == "__main__":
    main()
