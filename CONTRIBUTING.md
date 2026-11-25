# Contributing

Describe the change, affected hardware or protocol feature, and how you verified it. Use synthetic identities, clipboard contents and paths in tests and reports. For protocol changes, document byte order, length bounds and the Options+ version used for comparison.

Run the following from the repository root. Linux is required for the full suite. The GTK tests use system Python, PyGObject, Libadwaita and gtk4-broadwayd.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
PYTHONPATH=src .venv/bin/python -B -m unittest discover -s tests -p 'test_*.py'
python3 -B -S -m unittest tests/test_flow_bar.py tests/test_flow_i18n.py
python3 -B -m unittest scripts/test_release.py
```

Include the test counts and any skips in your pull request. For hardware reports, distinguish successful discovery from an actual edge crossing or completed paste. Contributions are licensed under the repository's MIT license.
