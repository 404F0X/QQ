# QQ research

Source research and reproducible models for QQ protocol and signature behavior. Signature work is incomplete; supported model behavior and remaining source gaps will be documented with the implementation.

The signature source model is accessed through `signature_core.py` from this checkout. It uses only registered, manifest-pinned source files and loads a fresh isolated namespace. Python 3.10 or newer is required. The focused model checks use the standard library; optional Windows/native integrations have their own requirements and are not exercised here.

```python
from signature_core import load_core

core = load_core()
try:
    with core.activate():
        from qq_nt_replica.primary_signer import PrimarySigner
        # Supply explicit model inputs for the supported source domain.
finally:
    core.close()
```

Run `python -B -m unittest discover -s tests -p test_isolation.py` from the checkout. The focused `check_static_unit.py` and `check_environment_values.py` scripts also require this checkout on `PYTHONPATH`; run them from a disposable output directory because they write check reports there.

See [signature state](docs/signature-state.md) for scope, missing assets and source identity conventions. Login integration is maintained separately.

