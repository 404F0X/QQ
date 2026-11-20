# Signature source state

This checkout flattens the effective selected source closure into 336 Python modules, four native bridge C/header sources, five explicitly loaded support modules and 102 approved source-derived/public-key assets. Algorithms and source state are retained. The only algorithm-module edit replaces the old absolute device-cold image path with the package-relative data path.

Two data manifests also normalize historical absolute provenance references to `research-source:<artifact basename>` labels. Their original source hashes remain in the source manifest alongside the new packaged hashes; these labels are metadata, not paths loaded by the model.

`source-manifest.json` records original source hashes separately from packaged hashes. `source-manifest.sha256` pins the manifest; the isolated loader validates the manifest and every included file before use and rechecks source bytes at execution. These pins detect accidental changes; an attacker able to replace both the manifest and its digest is outside this integrity mechanism. Source support modules retain dependency order and their explicit `core.source(key)` API. Foreign namespaces and foreign module replacements are rejected; cleanup removes only owned module objects.

Existing dynamic `co_filename` checks continue to resolve current source paths and verify them against the caller's collector manifest. A caller must build that manifest from the current checkout rather than reuse historical paths or digests. Native bridge builds likewise verify current C/header identities; no compiled bridge, original DLL or captured runtime data is included. Native build scripts retain their explicit Windows toolchain requirements.

Five assets remain excluded because publication provenance is unresolved:

- `producer.bin`
- `primary-signature-codec-vectors.json`
- `singleton-destroy.bin`
- `source2581-setter.bin`
- `source2581.bin`

Their logical locations are listed in the manifest. Paths that require them fail with the existing missing-file or identity checks. They are not replaced with defaults. This checkout is therefore not a claim of a fully self-contained signing application.

| Excluded asset | Affected functionality |
| --- | --- |
| `primary_sec_init_qq52230/producer.bin` | Security initialization producer program loading |
| `primary_sign_qq52230/primary-signature-codec-vectors.json` | Historical codec-vector evidence; not evidence of a supported live signing route |
| `primary_sign_qq52230/singleton-destroy.bin` | Singleton destruction program loading |
| `primary_sign_qq52230/source2581-setter.bin` | Source2581 setter program loading |
| `primary_sign_qq52230/source2581.bin` | Source2581 program loading |

This is a checkout-based source distribution, with no installation into site-packages required: place the checkout root on `PYTHONPATH` or run the caller from that root and import `signature_core`. Do not put `src` directly on `PYTHONPATH`, which would bypass the isolated loader. To supply an excluded asset locally, first resolve its provenance and authorization, then place it at `src/qq_nt_replica/data/<relative path in the table>`. Existing program/table loaders enforce their fixed hashes (and applicable lengths/layouts); a mismatched file is rejected, and no historical report tree is searched. The codec-vector JSON is evidence rather than a model loader input: merely placing it there does not validate it or enable functionality. No installer or automatic download is provided for these unresolved assets. Keep them outside commits until their provenance is approved.

The delivered pure Python source models and focused checks need only Python's standard library. Complete native/Windows execution has not been established: bridge builds require the specific MSVC/Windows SDK paths declared in their build scripts, and live collector interfaces require caller-provided qualified session/script objects, source manifests and real source observations. These are explicit integration prerequisites, not dependencies supplied by installing a Python package. Original wrapper/Qimei DLLs and runtime observations are not bundled. No claim is made that installing third-party modules closes the remaining source gaps.

Historical main96 evidence does not establish the current full material-B goal. Full Windows material consumption, normal close, NT post-processing/bootstrap and callback source closure still have gaps. Pending allocator-family work is not represented as completed. Tests here cover explicit model observations, not native positive execution, live registry values, SDK submission or end-to-end signing.

The static-unit checks retain the original eight model groups. The environment checks retain ten behavioral groups; their historical eleventh assertion compared an old intermediate dispatch file to an even earlier file. The portable version checks the two environment routes and the current manifest-pinned selected dispatch source instead, because subsequent selected-source changes legitimately extend that dispatch.

The eleventh group additionally pins the dispatch to its exact current export-inventory SHA, so its existing capability guards must remain byte-for-byte unchanged. Historical reports are retained separately and have not been rewritten. The earlier label “CPP8” referred to these same eight static-unit groups; there is no additional CPP suite.

The fixed C-locale multibyte table is now bundled after its narrow fixed-source provenance audit; its existing consumer hash and layout checks are unchanged. The remaining five exclusions above still apply.


The pending-report container now uses the source upper allocator pair B75000/B75029 for its 56-byte nodes and bucket arrays. Its private rehash retains source capacity rounding, collision/equal-key runs and pointer-publication/old-free/count/zero order. Erase frees a nonnull node regardless of payload ownership; telemetry exit changes only its D8 nodes and C8 bucket array. Shared SDK allocation paths and allocator ownership guards are unchanged.

Validation covers the same-thread explicit CUSTOM model issuer with the actual independent guest-address supplier. The telemetry helper check supplies an explicitly initialized model container in existing mapped regions; it does not prove canonical owner construction, callback registration or actual exit dispatch. Cross-thread transfer/free, real notification-owner shutdown, original OOM/length-exception handling and full material-B remain unsupported or unproved. A stale selector epoch intentionally poisons its separate fixture and is never resumed. Model storage disposal is checked separately from source frees.
