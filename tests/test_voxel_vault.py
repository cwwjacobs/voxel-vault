from pathlib import Path

from voxel_vault import VoxelVault


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def test_register_and_prove_exact(tmp_path: Path):
    original = tmp_path / "original.txt"
    _write(original, "alpha\nbeta\ngamma\n")

    vault = VoxelVault(seed="test-seed")
    vault.register(str(original))

    proof = vault.prove(str(original), threshold=0.6)
    assert proof["match_found"] is True
    assert proof["strongest_match"] is not None
    assert proof["strongest_match"]["similarity"]["level_0"] == 1.0


def test_register_and_prove_modified(tmp_path: Path):
    original = tmp_path / "original.txt"
    modified = tmp_path / "modified.txt"
    _write(original, "one\ntwo\nthree\nfour\n")
    _write(modified, "one\nthree\ntwo\nfour\nwith extra text\n")

    vault = VoxelVault(seed="test-seed")
    vault.register(str(original))
    proof = vault.prove(str(modified), threshold=0.4)

    assert proof["match_found"] is True
    assert proof["strongest_match"] is not None
    assert proof["strongest_match"]["similarity"]["combined"] >= 0.4


def test_save_load_roundtrip(tmp_path: Path):
    original = tmp_path / "roundtrip.txt"
    vault_path = tmp_path / "vault.vxv"
    _write(original, "stable content\n")

    vault = VoxelVault(seed="test-seed")
    vault.register(str(original), metadata={"kind": "test"})
    vault.save(str(vault_path))

    loaded = VoxelVault.load(str(vault_path), seed="test-seed")
    regs = loaded.list_registrations()
    assert len(regs) == 1
    assert regs[0]["metadata"]["kind"] == "test"


def test_commitment_hash_stable_for_same_state(tmp_path: Path):
    original = tmp_path / "commit.txt"
    _write(original, "commit me\n")

    vault = VoxelVault(seed="test-seed")
    vault.register(str(original), data_id="commit.txt")
    h1 = vault.commitment_hash()
    h2 = vault.commitment_hash()
    assert h1 == h2
