# Voxel Vault

Voxel Vault is a provenance-oriented Python tool for registering files, generating deterministic fingerprints, and checking whether another file is identical or meaningfully similar to a previously registered work.

It is built for local workflows where we want structured evidence around authorship, prior registration, and likely derivation without relying on a hosted service.

## What it does

- Computes four fingerprint layers for a file:
  - exact content hash
  - structural hash
  - statistical fingerprint vector
  - structural skeleton hash
- Binds each registration to seed-derived voxel coordinates
- Saves registrations into a local vault file
- Checks a suspect file against registered works
- Exports a proof artifact containing similarity scores and vault commitment data
- Generates a commitment hash that can be published elsewhere as a time anchor

## What it is not

Voxel Vault is a useful prototype, not a hardened security product.

It does **not** currently provide:

- authenticated modern encryption for the vault file
- calibrated false-positive / false-negative analysis
- legal guarantees or automatic proof of infringement
- broad validation across many real-world corpora

The current vault format uses prototype-grade confidentiality logic and should be upgraded before making stronger security claims.

## Why it is useful

Voxel Vault helps create structured provenance evidence.

That can be useful when we want to:

- register files before sharing or distributing them
- compare a suspect file to a known original
- preserve a stable commitment hash for later review
- support attribution or ownership-tracking workflows with deterministic outputs

## Quick start

### 1. Register a file

```bash
python voxel_vault.py register --seed "my secret seed" --file example.txt --vault my.vxv
```

### 2. List registrations

```bash
python voxel_vault.py list --seed "my secret seed" --vault my.vxv
```

### 3. Check a suspect file

```bash
python voxel_vault.py prove --seed "my secret seed" --vault my.vxv --suspect suspect.txt
```

### 4. Export a proof file

```bash
python voxel_vault.py prove --seed "my secret seed" --vault my.vxv --suspect suspect.txt --output proof.json
```

### 5. Generate a commitment hash

```bash
python voxel_vault.py commit --seed "my secret seed" --vault my.vxv
```

If you want an external time anchor, publish that hash somewhere that carries a timestamp.

## Example workflow

The `examples/` folder includes a tiny example pair:

- `examples/original.txt`
- `examples/modified.txt`

A simple local run looks like this:

```bash
python voxel_vault.py register --seed "demo seed" --file examples/original.txt --vault demo.vxv
python voxel_vault.py prove --seed "demo seed" --vault demo.vxv --suspect examples/modified.txt --output demo-proof.json
```

## Similarity model

Voxel Vault combines four layers:

1. **Level 0** — exact content hash
2. **Level 1** — normalized structural hash
3. **Level 2** — statistical similarity vector
4. **Level 3** — structural skeleton hash

The combined score is a weighted heuristic. It is useful for triage and review, but it should not be treated as a legal conclusion by itself.

## Security status

The vault save/load path currently uses a prototype-grade stream cipher derived from PBKDF2 output plus an integrity check.

That is acceptable for a local prototype but should be replaced with a modern authenticated construction such as **AES-GCM** or **ChaCha20-Poly1305** before stronger confidentiality claims are made.

## Development notes

Recommended next upgrades:

- replace the vault encryption with authenticated encryption
- add a broader regression corpus for similarity behavior
- add threshold guidance from measured test results
- add package metadata / installable CLI entry point

## Included tests

This repo now includes a small regression test suite in `tests/test_voxel_vault.py` covering:

- exact registration and proof flow
- modified-file similarity flow
- save/load roundtrip
- commitment hash stability

Run with:

```bash
python -m pytest -q
```

## License

This repository includes its current project license in `LICENSE`.

Read it carefully before redistribution or commercial use.
