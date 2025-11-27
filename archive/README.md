# Archive: Unreferenced / Duplicate Files

This directory contains files and a duplicate project copy that were moved out of the active tree
because they are not referenced by the main application and were increasing repository clutter.

Moved items:
- `apt-detection-system/` — duplicate copy of the project (contains an alternate `app.py`, `ml_models/`, `blockchain/`, `utils/`, etc.). Not imported by the main code.
- `generate_traffic.py` — utility script (moved to archive). If you need to generate custom traffic, keep this; otherwise it can be removed.
- `simulate_attacks.py` — utility script for attack simulation (moved to archive).
- `run_as_admin.bat` and `run_as_admin.ps1` — Windows helper scripts (moved to archive). Keep them if Windows users need them.

Why archive instead of delete:
- Safer: keeps history and allows quick restore if something was moved accidentally.
- Non-destructive: you can inspect, test, or permanently delete after review.

How to finalize (run locally):

1. Inspect archive contents:
```
ls -la archive
ls -R archive/apt-detection-system
```

2. Commit the archived changes (if not already committed):
```
git add -A
git commit -m "Archive unreferenced/duplicate items: apt-detection-system and miscellaneous scripts"
```

3. If you're satisfied and want to permanently remove these files from the repo (optional):
```
git rm -r archive/apt-detection-system
git rm archive/generate_traffic.py archive/simulate_attacks.py archive/run_as_admin.bat archive/run_as_admin.ps1
git commit -m "Remove archived unreferenced files"
```

If you want me to perform any of these steps (commit, or permanent deletion), tell me and I'll proceed.
