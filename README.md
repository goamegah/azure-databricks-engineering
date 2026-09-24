# Azure & Databricks Engineering
## Databricks Unity Catalog environment setup

```bash
python -m venv .venv/dbw-uc
source .venv/dbw-uc/bin/activate
pip install -e . && pip install -r dev-requirements.txt
```

## Unit tests environment setup

```bash
python -m venv .venv/dbw-ut
source .venv/dbw-ut/bin/activate
pip install -e . && pip uninstall -y -r test-excluded-requirements.txt && pip install -r test-requirements.txt
```