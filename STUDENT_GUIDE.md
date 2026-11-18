# Student Guide — Using the Project Template & Submitting

This guide explains how to start a CSEC 520/620 project from the template, work in it,
and submit your deliverables. Read it once before you begin.

> **The golden rule:** a grader must recreate your results with **one command**,
> `make reproduce`. Everything below serves that rule.

---

## 1. Get your team's copy

1. Go to the template repo: **https://github.com/byuan/csec-520-620-project-template**
2. Click **"Use this template" → Create a new repository**.
3. Name it `csec-520-620-<project>-<team>` (e.g., `csec-520-620-p1-team3`).
4. Set visibility to **Private**.
5. Add your teammates **and the instructor (`@byuan`)** as collaborators:
   your repo → **Settings → Collaborators → Add people**.

Do this once per project (or once for the semester-long capstone).

## 2. Set up (one time)

```bash
git clone git@github.com:<you>/<your-repo>.git
cd <your-repo>
make setup            # creates .venv and installs requirements
source .venv/bin/activate
make reproduce        # sanity check: runs on the synthetic dataset
```

If `results/metrics.json` and the two figures appear, you're ready.

## 3. Do the work

- **Change settings in `config.yaml`, not the code.** Seeds, epochs, model size, and the
  dataset path all live there.
- **Keep your pipeline in `src/`** so `make reproduce` always regenerates results. Use
  notebooks/scratch for exploration only — anything that produces graded results must run
  from `src/`.
- **Add your dataset** by editing `data/README.md` (where it comes from + how to download)
  and setting `data.source: csv` + `data.csv_path` in `config.yaml`. **Do not commit the
  data itself** — it's git-ignored on purpose.
- **Commit often** with clear messages; push regularly so your team stays in sync.

## 4. Self-check before you submit

Run these and fix anything that isn't clean:

```bash
make reproduce            # must succeed and write results/
make test                 # smoke tests pass
python grading/grade.py   # objective checks (structure, metrics, leakage, ...)
```

Then:

- [ ] The numbers in your report **match** `results/metrics.json`.
- [ ] Evaluation reports **precision, recall, F1, and ROC-AUC** — not just accuracy.
- [ ] No data leakage (scaling/fitting done on the training split only).
- [ ] `SUBMISSION.md` is filled in (team, dataset, claimed results, AI-use note).
- [ ] Your report PDF is in `report/`.

## 5. Deliverables

Every project submission includes:

1. **Your code**, in the repo, reproducible via `make reproduce`.
2. **A report** (IEEE conference format) in `report/` — abstract, introduction,
   literature review, implementation, data analysis & performance discussion,
   conclusion, references, appendix.
3. **A completed `SUBMISSION.md`.**
4. **(Capstone, P3 only)** a presentation/demo, plus the milestone deliverables
   (proposal, checkpoint) on their due dates.

## 6. How to submit

Your GitHub repo *is* the submission. To submit, freeze the exact commit that should be
graded by **tagging a release**:

```bash
git add -A && git commit -m "Final submission for <project>"
git push
git tag <project>-final          # e.g., p1-final
git push origin <project>-final
```

Then, on the course **[myCourses dropbox]**, submit:

- your **repository URL**, and
- the **tag** (or commit SHA) you tagged above, and
- your **report PDF**.

The tag freezes what we grade, so you can keep working afterward without affecting your
submission. **Submit by the posted deadline** — late work follows the syllabus late policy.

## 7. How you're graded (it's transparent)

Projects are graded against the **public rubric** in `grading/rubric.yaml` (weights are
visible to you), by an AI agent following `grading/AGENT_GRADING.md`, then reviewed by the
instructor. Read the rubric before you start — it tells you exactly what earns points.
**Reproducibility is graded**, so make sure `make reproduce` works from a clean clone.

## 8. Common pitfalls

- Results only exist in a notebook → they won't reproduce. Put them in `src/`.
- Committed the dataset or `.venv` → don't; they're git-ignored for a reason.
- Report numbers don't match `results/metrics.json` → re-run and update before submitting.
- Forgot to add `@byuan` as a collaborator on a private repo → we can't grade it.

Per the syllabus **AI-use policy**, you may use AI assistants as aids, but acknowledge
substantive use and don't submit AI-generated implementations for from-scratch tasks.
