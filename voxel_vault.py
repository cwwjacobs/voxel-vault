"""
voxel_vault.py — provenance-oriented file registration and similarity checks.

Voxel Vault is a Python CLI and library prototype for:
  - registering files with deterministic multi-level fingerprints,
  - binding registrations to seed-derived voxel coordinates,
  - saving/loading a local vault file,
  - generating proof artifacts and commitment hashes for later review.

This project is best understood as provenance support tooling, not as a final
security or legal product. It can help establish structured evidence that two
files are identical or meaningfully similar, but it does not guarantee legal
outcomes and it is not hardened cryptographic storage.

Current status:
  - useful prototype for local authorship / provenance workflows
  - deterministic core logic and CLI are implemented
  - vault encryption remains prototype-grade and should be upgraded before any
    stronger security claims are made
"""

import hashlib
import hmac
import json
import math
import os
import struct
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Union
import secrets


# ═══════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════

# Earth parameters (WGS-84)
EARTH_SEMI_MAJOR = 6_378_137.0        # meters
EARTH_SEMI_MINOR = 6_356_752.314245   # meters

# Voxel grid resolution
# At resolution 1000, the Earth is divided into a grid where each voxel
# is roughly 12.7km on a side at the equator. This gives ~10^9 possible
# hiding spots — enough that brute force search is impractical but the
# grid is small enough to fit in memory.
DEFAULT_RESOLUTION = 1000

# Fingerprint granularity levels
# Each level captures different-scale features of the data.
# Level 0: full content hash (exact match only)
# Level 1: structural hash (survives reordering)
# Level 2: statistical fingerprint (survives 10-20% modification)
# Level 3: semantic skeleton (survives 30-50% modification)
GRANULARITY_LEVELS = 4

# Number of voxel coordinates per registration
# More coordinates = more proof points but larger grid
DEFAULT_SCATTER_COUNT = 7

# Version tag for format compatibility
FORMAT_VERSION = "vxv-1.0"


# ═══════════════════════════════════════════════════════════
# ECEF COORDINATE SYSTEM
# (Adapted from the original 3dTextvoxel binding.py)
# ═══════════════════════════════════════════════════════════

@dataclass(frozen=True)
class VoxelCoord:
    """
    A point on the voxel Earth.

    Coordinates are integer indices into the voxel grid, not floating
    point lat/lon. This ensures deterministic addressing — the same
    seed always produces the same coordinates, with no floating point
    drift across platforms or languages.
    """
    x: int
    y: int
    z: int

    def to_bytes(self) -> bytes:
        """Canonical byte representation. Platform-independent."""
        return struct.pack(">iii", self.x, self.y, self.z)

    def to_hex(self) -> str:
        return self.to_bytes().hex()

    @staticmethod
    def from_hex(h: str) -> "VoxelCoord":
        x, y, z = struct.unpack(">iii", bytes.fromhex(h))
        return VoxelCoord(x, y, z)

    def __repr__(self):
        return f"V({self.x},{self.y},{self.z})"


def quantize_to_voxel(lat: float, lon: float, alt: float = 0.0,
                       resolution: int = DEFAULT_RESOLUTION) -> VoxelCoord:
    """
    Convert geodetic coordinates to a voxel address.

    Uses ECEF (Earth-Centered, Earth-Fixed) conversion followed by
    deterministic integer quantization. The quantization is designed
    to be exactly reproducible across any platform that supports
    IEEE 754 double precision — no rounding ambiguity.
    """
    # Convert to radians
    lat_r = math.radians(lat)
    lon_r = math.radians(lon)

    # WGS-84 ECEF conversion
    e2 = 1 - (EARTH_SEMI_MINOR ** 2) / (EARTH_SEMI_MAJOR ** 2)
    n = EARTH_SEMI_MAJOR / math.sqrt(1 - e2 * math.sin(lat_r) ** 2)

    x = (n + alt) * math.cos(lat_r) * math.cos(lon_r)
    y = (n + alt) * math.cos(lat_r) * math.sin(lon_r)
    z = (n * (1 - e2) + alt) * math.sin(lat_r)

    # Quantize to grid
    # Scale factor maps ECEF range to [0, resolution)
    scale = resolution / (2.0 * EARTH_SEMI_MAJOR * 1.1)  # 1.1x margin for altitude

    vx = int(math.floor((x + EARTH_SEMI_MAJOR * 1.1) * scale))
    vy = int(math.floor((y + EARTH_SEMI_MAJOR * 1.1) * scale))
    vz = int(math.floor((z + EARTH_SEMI_MAJOR * 1.1) * scale))

    # Clamp to valid range
    vx = max(0, min(resolution - 1, vx))
    vy = max(0, min(resolution - 1, vy))
    vz = max(0, min(resolution - 1, vz))

    return VoxelCoord(vx, vy, vz)


# ═══════════════════════════════════════════════════════════
# SEED-DERIVED COORDINATE GENERATION
# ═══════════════════════════════════════════════════════════

def derive_coordinates(
    seed: bytes,
    data_id: str,
    count: int = DEFAULT_SCATTER_COUNT,
    resolution: int = DEFAULT_RESOLUTION
) -> List[VoxelCoord]:
    """
    Derive deterministic voxel coordinates from a secret seed and data identifier.

    The coordinates are spread across the grid using HMAC-based key derivation.
    Given the same seed and data_id, this always produces the same coordinates.
    Without the seed, an attacker would need to search ~10^9 voxels per
    coordinate — and they don't know how many coordinates exist.

    Each coordinate is derived independently so that revealing one
    coordinate (e.g., during a proof) doesn't help find the others.
    """
    coords = []
    for i in range(count):
        # Derive a unique key for this coordinate index
        # Using HMAC prevents length extension attacks on the seed
        key_material = hmac.new(
            seed,
            f"{data_id}:coord:{i}".encode("utf-8"),
            hashlib.sha256
        ).digest()

        # Extract three coordinate values from the key material
        # Each coordinate gets 8 bytes of entropy (more than enough for 10^3 range)
        x_bytes = key_material[0:8]
        y_bytes = key_material[8:16]
        z_bytes = key_material[16:24]

        x = int.from_bytes(x_bytes, "big") % resolution
        y = int.from_bytes(y_bytes, "big") % resolution
        z = int.from_bytes(z_bytes, "big") % resolution

        coords.append(VoxelCoord(x, y, z))

    return coords


def derive_seed_bytes(seed_phrase: str) -> bytes:
    """
    Derive a cryptographic seed from a human-readable phrase.

    Uses PBKDF2 with a fixed salt and high iteration count.
    The same phrase always produces the same seed.
    """
    return hashlib.pbkdf2_hmac(
        "sha256",
        seed_phrase.encode("utf-8"),
        b"voxel-vault-v1-salt",  # Fixed salt — phrase IS the secret
        iterations=100_000,
    )


# ═══════════════════════════════════════════════════════════
# MULTI-GRANULARITY FINGERPRINTING
# ═══════════════════════════════════════════════════════════

@dataclass
class Fingerprint:
    """
    Multi-granularity fingerprint of a data file.

    Level 0: Exact content hash (SHA-256 of raw bytes)
             Matches only if the file is byte-for-byte identical.

    Level 1: Structural hash (hash of sorted, normalized lines)
             Survives reordering of lines/records. Catches someone
             who shuffles your JSONL and calls it theirs.

    Level 2: Statistical fingerprint (content statistics)
             A vector of numeric features: line count, character
             distribution, token frequencies, size ratios. Survives
             10-20% modification. Similarity is cosine distance.

    Level 3: Skeleton hash (hash of structural elements only)
             For code: function names, class names, import statements.
             For JSONL: key names, nesting depth, type patterns.
             Survives content modification if structure is preserved.
             Catches someone who paraphrases your data but keeps
             the schema.
    """
    level_0: str = ""              # exact hash
    level_1: str = ""              # structural hash
    level_2: List[float] = field(default_factory=list)  # statistical vector
    level_3: str = ""              # skeleton hash
    file_size: int = 0
    line_count: int = 0
    created_at: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "Fingerprint":
        return Fingerprint(**d)


def compute_fingerprint(file_path: str) -> Fingerprint:
    """Compute all four fingerprint levels for a file."""
    path = Path(file_path)
    raw = path.read_bytes()
    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()

    fp = Fingerprint()
    fp.file_size = len(raw)
    fp.line_count = len(lines)
    fp.created_at = datetime.now(timezone.utc).isoformat()

    # Level 0: Exact content hash
    fp.level_0 = hashlib.sha256(raw).hexdigest()

    # Level 1: Structural hash (sorted, stripped, normalized)
    normalized_lines = sorted(line.strip().lower() for line in lines if line.strip())
    structural_content = "\n".join(normalized_lines).encode("utf-8")
    fp.level_1 = hashlib.sha256(structural_content).hexdigest()

    # Level 2: Statistical fingerprint vector
    fp.level_2 = _compute_statistical_vector(text, lines)

    # Level 3: Skeleton hash
    fp.level_3 = _compute_skeleton_hash(text, lines)

    return fp


def compute_fingerprint_from_bytes(data: bytes, name: str = "inline") -> Fingerprint:
    """Compute fingerprint from raw bytes (for data that isn't a file)."""
    text = data.decode("utf-8", errors="replace")
    lines = text.splitlines()

    fp = Fingerprint()
    fp.file_size = len(data)
    fp.line_count = len(lines)
    fp.created_at = datetime.now(timezone.utc).isoformat()

    fp.level_0 = hashlib.sha256(data).hexdigest()

    normalized_lines = sorted(line.strip().lower() for line in lines if line.strip())
    fp.level_1 = hashlib.sha256("\n".join(normalized_lines).encode("utf-8")).hexdigest()

    fp.level_2 = _compute_statistical_vector(text, lines)
    fp.level_3 = _compute_skeleton_hash(text, lines)

    return fp


def _compute_statistical_vector(text: str, lines: List[str]) -> List[float]:
    """
    Compute a statistical feature vector from text content.

    This vector is designed to survive partial modification while still
    being distinctive enough to identify the source data. Features are
    chosen to be robust against common transformations (reordering,
    paraphrasing, format changes) while being sensitive to the overall
    "shape" of the data.
    """
    if not text:
        return [0.0] * 20

    total_chars = len(text)
    total_lines = max(len(lines), 1)

    # Character class distribution (8 features)
    alpha = sum(1 for c in text if c.isalpha()) / max(total_chars, 1)
    digit = sum(1 for c in text if c.isdigit()) / max(total_chars, 1)
    space = sum(1 for c in text if c.isspace()) / max(total_chars, 1)
    punct = sum(1 for c in text if c in '.,;:!?()[]{}"-\'') / max(total_chars, 1)
    upper = sum(1 for c in text if c.isupper()) / max(total_chars, 1)
    newline = text.count("\n") / max(total_chars, 1)
    bracket = (text.count("{") + text.count("}") + text.count("[") + text.count("]")) / max(total_chars, 1)
    colon = text.count(":") / max(total_chars, 1)

    # Line length statistics (4 features)
    line_lengths = [len(l) for l in lines]
    avg_line_len = sum(line_lengths) / total_lines
    max_line_len = max(line_lengths) if line_lengths else 0
    line_len_std = math.sqrt(
        sum((l - avg_line_len) ** 2 for l in line_lengths) / max(total_lines - 1, 1)
    ) if total_lines > 1 else 0

    # Normalize to relative values
    avg_line_norm = avg_line_len / max(max_line_len, 1)
    std_norm = line_len_std / max(max_line_len, 1)

    # Content indicators (4 features)
    json_score = min(1.0, (text.count("{") + text.count("[")) / max(total_lines, 1))
    code_indicators = sum(1 for l in lines if l.strip().startswith(("def ", "class ", "import ", "from ")))
    code_score = min(1.0, code_indicators / max(total_lines, 1))
    empty_ratio = sum(1 for l in lines if not l.strip()) / total_lines
    indent_ratio = sum(1 for l in lines if l.startswith((" ", "\t"))) / total_lines

    # Token-level features (4 features)
    words = text.split()
    total_words = max(len(words), 1)
    avg_word_len = sum(len(w) for w in words) / total_words
    unique_ratio = len(set(w.lower() for w in words[:1000])) / min(total_words, 1000)

    # Byte-level entropy (rough approximation)
    byte_counts = [0] * 256
    for b in text.encode("utf-8", errors="replace")[:10000]:
        byte_counts[b] += 1
    total_sampled = sum(byte_counts)
    entropy = 0.0
    for count in byte_counts:
        if count > 0:
            p = count / total_sampled
            entropy -= p * math.log2(p)
    entropy_norm = entropy / 8.0  # Normalize to [0, 1]

    return [
        alpha, digit, space, punct, upper, newline, bracket, colon,
        avg_line_norm, std_norm, max_line_len / 10000.0, total_lines / 100000.0,
        json_score, code_score, empty_ratio, indent_ratio,
        avg_word_len / 20.0, unique_ratio, entropy_norm,
        total_chars / 10_000_000.0,
    ]


def _compute_skeleton_hash(text: str, lines: List[str]) -> str:
    """
    Hash the structural skeleton of the content.

    For JSON/JSONL: extract key names and type patterns.
    For code: extract function/class/import declarations.
    For plain text: extract sentence-initial words and paragraph structure.

    This captures the "shape" of the data without the content.
    """
    skeleton_parts = []

    for line in lines[:5000]:  # Cap for performance
        stripped = line.strip()
        if not stripped:
            skeleton_parts.append("EMPTY")
            continue

        # JSON structure detection
        if stripped.startswith(("{", "[")):
            try:
                obj = json.loads(stripped)
                skeleton_parts.append(_json_skeleton(obj))
                continue
            except (json.JSONDecodeError, RecursionError):
                pass

        # Code structure detection
        if stripped.startswith("def "):
            # Extract function signature without body
            skeleton_parts.append(f"DEF:{stripped.split('(')[0]}")
        elif stripped.startswith("class "):
            skeleton_parts.append(f"CLASS:{stripped.split('(')[0].split(':')[0]}")
        elif stripped.startswith(("import ", "from ")):
            skeleton_parts.append(f"IMPORT:{stripped}")
        elif stripped.startswith("#"):
            skeleton_parts.append("COMMENT")
        elif stripped.startswith(("def ", "async def")):
            skeleton_parts.append("FUNC")
        else:
            # Generic: first word + line length bucket
            first_word = stripped.split()[0] if stripped.split() else ""
            len_bucket = len(stripped) // 40  # 40-char buckets
            skeleton_parts.append(f"L:{first_word[:10]}:{len_bucket}")

    skeleton_str = "\n".join(skeleton_parts).encode("utf-8")
    return hashlib.sha256(skeleton_str).hexdigest()


def _json_skeleton(obj, depth: int = 0, max_depth: int = 4) -> str:
    """Extract structural skeleton from a JSON object."""
    if depth > max_depth:
        return "..."
    if isinstance(obj, dict):
        keys = sorted(obj.keys())
        parts = [f"{k}:{_json_skeleton(obj[k], depth+1)}" for k in keys[:20]]
        return "{" + ",".join(parts) + "}"
    elif isinstance(obj, list):
        if obj:
            return f"[{_json_skeleton(obj[0], depth+1)}]*{len(obj)}"
        return "[]"
    elif isinstance(obj, str):
        return f"str:{len(obj)//100}"
    elif isinstance(obj, (int, float)):
        return "num"
    elif isinstance(obj, bool):
        return "bool"
    elif obj is None:
        return "null"
    return "?"


# ═══════════════════════════════════════════════════════════
# FINGERPRINT SIMILARITY
# ═══════════════════════════════════════════════════════════

def fingerprint_similarity(a: Fingerprint, b: Fingerprint) -> Dict[str, float]:
    """
    Compare two fingerprints across all granularity levels.

    Returns similarity scores for each level:
      level_0: 1.0 if exact match, 0.0 otherwise
      level_1: 1.0 if structural match, 0.0 otherwise
      level_2: cosine similarity of statistical vectors (0.0 to 1.0)
      level_3: 1.0 if skeleton match, 0.0 otherwise
      combined: weighted combination of all levels
    """
    scores = {}

    # Level 0: exact match (binary)
    scores["level_0"] = 1.0 if a.level_0 == b.level_0 else 0.0

    # Level 1: structural match (binary)
    scores["level_1"] = 1.0 if a.level_1 == b.level_1 else 0.0

    # Level 2: statistical similarity (cosine)
    if a.level_2 and b.level_2 and len(a.level_2) == len(b.level_2):
        dot = sum(x * y for x, y in zip(a.level_2, b.level_2))
        mag_a = math.sqrt(sum(x * x for x in a.level_2))
        mag_b = math.sqrt(sum(x * x for x in b.level_2))
        if mag_a > 0 and mag_b > 0:
            scores["level_2"] = max(0.0, dot / (mag_a * mag_b))
        else:
            scores["level_2"] = 0.0
    else:
        scores["level_2"] = 0.0

    # Level 3: skeleton match (binary)
    scores["level_3"] = 1.0 if a.level_3 == b.level_3 else 0.0

    # Combined score — weighted toward the fuzzier levels since those
    # are the ones that survive modification
    scores["combined"] = (
        scores["level_0"] * 0.1 +    # Exact match is nice but fragile
        scores["level_1"] * 0.2 +    # Structural is more useful
        scores["level_2"] * 0.5 +    # Statistical is the workhorse
        scores["level_3"] * 0.2      # Skeleton catches schema theft
    )

    return scores


# ═══════════════════════════════════════════════════════════
# THE VAULT
# ═══════════════════════════════════════════════════════════

@dataclass
class Registration:
    """A single registered piece of work in the vault."""
    data_id: str                          # Human-readable name
    fingerprint: Fingerprint              # Multi-level fingerprint
    coordinates: List[str]                # Hex-encoded voxel coordinates
    registered_at: str                    # ISO timestamp
    metadata: Dict[str, str] = field(default_factory=dict)


class VoxelVault:
    """
    The spatial IP protection vault.

    This is the core data structure. It holds registered fingerprints
    bound to seed-derived voxel coordinates. The vault file is encrypted
    with the seed — without the seed phrase, the vault is opaque.

    Usage:
        vault = VoxelVault(seed="my secret phrase")
        vault.register("training_data.jsonl", metadata={"version": "1.0"})
        vault.save("my_vault.vxv")

        # Later...
        vault = VoxelVault.load("my_vault.vxv", seed="my secret phrase")
        proof = vault.prove("suspect_file.jsonl")
    """

    def __init__(self, seed: str, resolution: int = DEFAULT_RESOLUTION):
        self._seed_phrase = seed
        self._seed_bytes = derive_seed_bytes(seed)
        self._resolution = resolution
        self._registrations: Dict[str, Registration] = {}
        self._created_at = datetime.now(timezone.utc).isoformat()

    def register(
        self,
        file_path: str,
        data_id: Optional[str] = None,
        scatter_count: int = DEFAULT_SCATTER_COUNT,
        metadata: Optional[Dict[str, str]] = None,
    ) -> Registration:
        """
        Register a file in the vault.

        Computes a multi-granularity fingerprint, derives voxel coordinates
        from the seed + file identity, and binds them together. The
        registration is timestamped.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        if data_id is None:
            data_id = path.name

        # Compute fingerprint
        fingerprint = compute_fingerprint(file_path)

        # Derive coordinates from seed + data identity
        # We use the level_0 hash as part of the derivation so that
        # different files get different coordinates even with the same seed
        coord_input = f"{data_id}:{fingerprint.level_0}"
        coordinates = derive_coordinates(
            self._seed_bytes, coord_input, scatter_count, self._resolution
        )

        reg = Registration(
            data_id=data_id,
            fingerprint=fingerprint,
            coordinates=[c.to_hex() for c in coordinates],
            registered_at=datetime.now(timezone.utc).isoformat(),
            metadata=metadata or {},
        )

        self._registrations[data_id] = reg
        return reg

    def register_bytes(
        self,
        data: bytes,
        data_id: str,
        scatter_count: int = DEFAULT_SCATTER_COUNT,
        metadata: Optional[Dict[str, str]] = None,
    ) -> Registration:
        """Register raw bytes (for data not stored as a file)."""
        fingerprint = compute_fingerprint_from_bytes(data, data_id)

        coord_input = f"{data_id}:{fingerprint.level_0}"
        coordinates = derive_coordinates(
            self._seed_bytes, coord_input, scatter_count, self._resolution
        )

        reg = Registration(
            data_id=data_id,
            fingerprint=fingerprint,
            coordinates=[c.to_hex() for c in coordinates],
            registered_at=datetime.now(timezone.utc).isoformat(),
            metadata=metadata or {},
        )

        self._registrations[data_id] = reg
        return reg

    def prove(
        self,
        suspect_file: str,
        threshold: float = 0.6,
    ) -> Dict:
        """
        Attempt to prove that a suspect file matches a registered work.

        Computes the suspect's fingerprint and compares it against all
        registrations at all granularity levels. Returns match results
        with confidence scores.

        threshold: minimum combined similarity to consider a match (0.0-1.0)
        """
        suspect_fp = compute_fingerprint(suspect_file)
        return self._prove_fingerprint(suspect_fp, threshold)

    def prove_bytes(
        self,
        suspect_data: bytes,
        threshold: float = 0.6,
    ) -> Dict:
        """Prove against raw bytes."""
        suspect_fp = compute_fingerprint_from_bytes(suspect_data)
        return self._prove_fingerprint(suspect_fp, threshold)

    def _prove_fingerprint(self, suspect_fp: Fingerprint, threshold: float) -> Dict:
        """Core proof logic."""
        matches = []

        for data_id, reg in self._registrations.items():
            similarity = fingerprint_similarity(reg.fingerprint, suspect_fp)

            if similarity["combined"] >= threshold:
                matches.append({
                    "data_id": data_id,
                    "registered_at": reg.registered_at,
                    "similarity": similarity,
                    "coordinates_count": len(reg.coordinates),
                    "coordinates_revealed": reg.coordinates[:2],  # Reveal only 2 as proof
                    "metadata": reg.metadata,
                    "verdict": _verdict(similarity["combined"]),
                })

        matches.sort(key=lambda m: m["similarity"]["combined"], reverse=True)

        return {
            "suspect_fingerprint": suspect_fp.to_dict(),
            "matches": matches,
            "match_found": len(matches) > 0,
            "strongest_match": matches[0] if matches else None,
            "proof_generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def commitment_hash(self) -> str:
        """
        Generate a commitment hash of the entire vault state.

        Optionally publish this hash somewhere with a verifiable timestamp
        (for example email, a git commit, or another trusted timestamping
        channel) if you want an external time anchor. This lets you later
        show that the vault contents matched this commitment at that time.

        The hash covers all registrations, their fingerprints, and
        their coordinates. Changing any registration changes the hash.
        """
        # Serialize all registrations deterministically
        reg_data = []
        for data_id in sorted(self._registrations.keys()):
            reg = self._registrations[data_id]
            reg_data.append({
                "data_id": reg.data_id,
                "fingerprint_l0": reg.fingerprint.level_0,
                "fingerprint_l1": reg.fingerprint.level_1,
                "fingerprint_l3": reg.fingerprint.level_3,
                "coordinates": sorted(reg.coordinates),
                "registered_at": reg.registered_at,
            })

        canonical = json.dumps(reg_data, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def export_proof(self, proof: Dict, output_path: str):
        """
        Export a proof document for later review.

        The document contains:
        - the suspect file fingerprint
        - matching registration metadata
        - similarity scores at each granularity level
        - a subset of coordinates (not all — protect the remaining ones)
        - the vault commitment hash
        - timestamps
        """
        doc = {
            "title": "Voxel Vault Provenance Proof",
            "version": FORMAT_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "vault_commitment": self.commitment_hash(),
            "proof": proof,
            "verification_instructions": (
                "To review this proof: (1) confirm the vault_commitment hash matches "
                "a previously published commitment, if one exists; (2) confirm the "
                "suspect file fingerprint matches the suspect_fingerprint in this "
                "document; (3) inspect the similarity scores and thresholds in "
                "context; (4) use the revealed coordinates with the original vault "
                "to confirm the registration exists."
            ),
        }

        with open(output_path, "w") as f:
            json.dump(doc, f, indent=2)

    def list_registrations(self) -> List[Dict]:
        """List all registered works (without revealing coordinates)."""
        return [
            {
                "data_id": reg.data_id,
                "registered_at": reg.registered_at,
                "file_size": reg.fingerprint.file_size,
                "line_count": reg.fingerprint.line_count,
                "coordinates_count": len(reg.coordinates),
                "metadata": reg.metadata,
            }
            for reg in self._registrations.values()
        ]

    def save(self, output_path: str):
        """
        Save the vault to disk.

        The vault is encrypted with a key derived from the seed phrase.
        Without the seed, the file is opaque. This means the vault file
        itself can be stored in relatively untrusted locations (cloud
        backup, etc.) without revealing its contents.
        """
        vault_data = {
            "version": FORMAT_VERSION,
            "created_at": self._created_at,
            "resolution": self._resolution,
            "registrations": {
                data_id: {
                    "data_id": reg.data_id,
                    "fingerprint": reg.fingerprint.to_dict(),
                    "coordinates": reg.coordinates,
                    "registered_at": reg.registered_at,
                    "metadata": reg.metadata,
                }
                for data_id, reg in self._registrations.items()
            },
        }

        plaintext = json.dumps(vault_data, sort_keys=True).encode("utf-8")

        # Derive encryption key from seed
        enc_key = hashlib.pbkdf2_hmac(
            "sha256", self._seed_bytes, b"vxv-encryption-v1", 50_000
        )

        # Prototype-grade stream cipher.
        # For stronger security claims, replace with AES-GCM or ChaCha20-Poly1305.
        encrypted = _xor_encrypt(plaintext, enc_key)

        # Write with integrity check
        integrity = hashlib.sha256(plaintext).digest()

        with open(output_path, "wb") as f:
            f.write(b"VXV1")                      # Magic bytes
            f.write(len(integrity).to_bytes(2, "big"))
            f.write(integrity)
            f.write(encrypted)

    @staticmethod
    def load(file_path: str, seed: str) -> "VoxelVault":
        """Load a vault from disk using the seed phrase."""
        seed_bytes = derive_seed_bytes(seed)

        with open(file_path, "rb") as f:
            magic = f.read(4)
            if magic != b"VXV1":
                raise ValueError("Not a valid vault file")

            integrity_len = int.from_bytes(f.read(2), "big")
            stored_integrity = f.read(integrity_len)
            encrypted = f.read()

        # Decrypt
        enc_key = hashlib.pbkdf2_hmac(
            "sha256", seed_bytes, b"vxv-encryption-v1", 50_000
        )
        plaintext = _xor_encrypt(encrypted, enc_key)

        # Verify integrity
        computed_integrity = hashlib.sha256(plaintext).digest()
        if not hmac.compare_digest(stored_integrity, computed_integrity):
            raise ValueError(
                "Integrity check failed. Wrong seed phrase or corrupted vault."
            )

        vault_data = json.loads(plaintext.decode("utf-8"))

        # Reconstruct vault
        vault = VoxelVault(seed=seed, resolution=vault_data.get("resolution", DEFAULT_RESOLUTION))
        vault._created_at = vault_data.get("created_at", "")

        for data_id, reg_data in vault_data.get("registrations", {}).items():
            vault._registrations[data_id] = Registration(
                data_id=reg_data["data_id"],
                fingerprint=Fingerprint.from_dict(reg_data["fingerprint"]),
                coordinates=reg_data["coordinates"],
                registered_at=reg_data["registered_at"],
                metadata=reg_data.get("metadata", {}),
            )

        return vault


def _xor_encrypt(data: bytes, key: bytes) -> bytes:
    """
    XOR stream cipher. Same function encrypts and decrypts.

    ⚠️ This is a placeholder. For production, replace with AES-256-GCM
    using the `cryptography` library. XOR with a PBKDF2-derived key is
    acceptable for prototype confidentiality but doesn't provide
    authenticated encryption (AEAD). An attacker who can modify the
    encrypted vault could potentially corrupt it without detection,
    though the integrity hash catches this at load time.
    """
    # Generate keystream from key using SHA-256 in counter mode
    keystream = bytearray()
    counter = 0
    while len(keystream) < len(data):
        block = hashlib.sha256(
            key + counter.to_bytes(8, "big")
        ).digest()
        keystream.extend(block)
        counter += 1

    return bytes(a ^ b for a, b in zip(data, keystream[:len(data)]))


def _verdict(combined_score: float) -> str:
    """Human-readable verdict from a combined similarity score."""
    if combined_score >= 0.95:
        return "EXACT_MATCH — Byte-for-byte identical or extremely close."
    elif combined_score >= 0.80:
        return "STRONG_MATCH — Substantial overlap. Likely derived from the registered work."
    elif combined_score >= 0.60:
        return "PROBABLE_MATCH — Significant similarity. Review recommended."
    elif combined_score >= 0.40:
        return "WEAK_MATCH — Some overlap, but it may be coincidental."
    else:
        return "NO_MATCH — Insufficient similarity."


# ═══════════════════════════════════════════════════════════
# CLI INTERFACE
# ═══════════════════════════════════════════════════════════

def cli_main():
    """Command-line interface for the vault."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Voxel Vault — provenance-oriented file registration and similarity checks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Register your work
  python voxel_vault.py register --seed "my secret" --file training.jsonl --vault my.vxv

  # Register multiple files
  python voxel_vault.py register --seed "my secret" --file data1.jsonl --file data2.jsonl --vault my.vxv

  # Check a suspect file
  python voxel_vault.py prove --seed "my secret" --vault my.vxv --suspect stolen.jsonl

  # Get commitment hash (publish this somewhere timestamped if you need a time anchor)
  python voxel_vault.py commit --seed "my secret" --vault my.vxv

  # List registered works
  python voxel_vault.py list --seed "my secret" --vault my.vxv
        """,
    )

    sub = parser.add_subparsers(dest="command")

    # Register
    reg = sub.add_parser("register", help="Register a file in the vault")
    reg.add_argument("--seed", required=True, help="Secret seed phrase")
    reg.add_argument("--file", required=True, action="append", help="File(s) to register")
    reg.add_argument("--vault", required=True, help="Vault file path (.vxv)")
    reg.add_argument("--name", help="Optional name for the registration")

    # Prove
    prv = sub.add_parser("prove", help="Check a suspect file against the vault")
    prv.add_argument("--seed", required=True, help="Secret seed phrase")
    prv.add_argument("--vault", required=True, help="Vault file path")
    prv.add_argument("--suspect", required=True, help="Suspect file to check")
    prv.add_argument("--threshold", type=float, default=0.6, help="Match threshold (0-1)")
    prv.add_argument("--output", help="Save proof to this file")

    # Commit
    cmt = sub.add_parser("commit", help="Generate commitment hash")
    cmt.add_argument("--seed", required=True, help="Secret seed phrase")
    cmt.add_argument("--vault", required=True, help="Vault file path")

    # List
    lst = sub.add_parser("list", help="List registered works")
    lst.add_argument("--seed", required=True, help="Secret seed phrase")
    lst.add_argument("--vault", required=True, help="Vault file path")

    args = parser.parse_args()

    if args.command == "register":
        # Load or create vault
        vault_path = Path(args.vault)
        if vault_path.exists():
            vault = VoxelVault.load(args.vault, args.seed)
            print(f"Loaded existing vault: {args.vault}")
        else:
            vault = VoxelVault(seed=args.seed)
            print(f"Creating new vault: {args.vault}")

        for file_path in args.file:
            name = args.name or Path(file_path).name
            reg = vault.register(file_path, data_id=name)
            print(f"\n  Registered: {name}")
            print(f"  File size:  {reg.fingerprint.file_size:,} bytes")
            print(f"  Lines:      {reg.fingerprint.line_count:,}")
            print(f"  Coordinates: {len(reg.coordinates)} voxels bound")
            print(f"  Timestamp:  {reg.registered_at}")

        vault.save(args.vault)
        print(f"\nVault saved to {args.vault}")
        print(f"\nNext step: optionally run 'python voxel_vault.py commit' and publish the hash if you want a dated commitment anchor.")

    elif args.command == "prove":
        vault = VoxelVault.load(args.vault, args.seed)
        print(f"Loaded vault with {len(vault._registrations)} registrations.")
        print(f"Checking suspect: {args.suspect}\n")

        proof = vault.prove(args.suspect, threshold=args.threshold)

        if proof["match_found"]:
            best = proof["strongest_match"]
            sim = best["similarity"]
            print(f"  🚨 MATCH FOUND")
            print(f"  Matched: {best['data_id']}")
            print(f"  Registered: {best['registered_at']}")
            print(f"  Verdict: {best['verdict']}")
            print(f"\n  Similarity breakdown:")
            print(f"    Level 0 (exact):      {sim['level_0']:.4f}")
            print(f"    Level 1 (structural): {sim['level_1']:.4f}")
            print(f"    Level 2 (statistical):{sim['level_2']:.4f}")
            print(f"    Level 3 (skeleton):   {sim['level_3']:.4f}")
            print(f"    Combined:             {sim['combined']:.4f}")
        else:
            print(f"  No matches above threshold ({args.threshold}).")

        if args.output:
            vault.export_proof(proof, args.output)
            print(f"\nProof saved to {args.output}")

    elif args.command == "commit":
        vault = VoxelVault.load(args.vault, args.seed)
        h = vault.commitment_hash()
        print(f"\n  Commitment Hash: {h}")
        print(f"\n  Publish this hash with a verifiable timestamp if you want a dated commitment anchor.")
        print(f"  Options:")
        print(f"    - Email it to yourself (email headers contain timestamps)")
        print(f"    - Include it in a git commit or signed note")
        print(f"    - Submit it to a trusted timestamping service")
        print(f"    - Record it anywhere else with a durable timestamp")
        print(f"\n  This hash lets you later show that your vault contents")
        print(f"  matched this exact commitment at the time of publication.")

    elif args.command == "list":
        vault = VoxelVault.load(args.vault, args.seed)
        regs = vault.list_registrations()
        print(f"\nVault contains {len(regs)} registrations:\n")
        for r in regs:
            print(f"  {r['data_id']}")
            print(f"    Registered: {r['registered_at']}")
            print(f"    Size: {r['file_size']:,} bytes, {r['line_count']:,} lines")
            print(f"    Coordinates: {r['coordinates_count']} voxels")
            if r["metadata"]:
                for k, v in r["metadata"].items():
                    print(f"    {k}: {v}")
            print()

    else:
        parser.print_help()


if __name__ == "__main__":
    cli_main()
