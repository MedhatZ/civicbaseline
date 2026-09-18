from __future__ import annotations

import os
from pathlib import Path

import yaml

from civicbaseline.models import PackSpec, RuleSpec


def default_packs_root() -> Path:
    env = os.environ.get("CIVICBASELINE_PACKS")
    if env:
        return Path(env)
    repo = Path(__file__).resolve().parent.parent / "packs"
    if repo.exists():
        return repo
    cwd = Path.cwd() / "packs"
    if cwd.exists():
        return cwd
    return repo


def load_pack_index(pack_id: str, packs_root: Path | None = None) -> PackSpec:
    root = packs_root or default_packs_root()
    pack_dir = root / pack_id
    manifest = pack_dir / "pack.yaml"
    if not manifest.exists():
        raise FileNotFoundError(f"Unknown pack '{pack_id}'. Expected {manifest}")
    data = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
    return PackSpec.model_validate(data)


def _rule_files(pack_dir: Path) -> list[Path]:
    files = sorted(pack_dir.glob("*.yaml"))
    return [path for path in files if path.name != "pack.yaml"]


def load_rules_for_pack(pack_id: str, packs_root: Path | None = None) -> tuple[PackSpec, list[RuleSpec]]:
    root = packs_root or default_packs_root()
    spec = load_pack_index(pack_id, root)
    rules: list[RuleSpec] = []
    seen: set[str] = set()
    chain = spec.includes if spec.includes else [pack_id]
    for included in chain:
        pack_dir = root / included
        if not pack_dir.is_dir():
            raise FileNotFoundError(f"Included pack '{included}' is missing at {pack_dir}")
        for rule_file in _rule_files(pack_dir):
            payload = yaml.safe_load(rule_file.read_text(encoding="utf-8")) or {}
            items = payload.get("rules", payload if isinstance(payload, list) else [payload])
            for item in items:
                if not item:
                    continue
                rule = RuleSpec.model_validate(item)
                if rule.id in seen:
                    continue
                seen.add(rule.id)
                rules.append(rule)
    return spec, rules


def list_packs(packs_root: Path | None = None) -> list[PackSpec]:
    root = packs_root or default_packs_root()
    packs: list[PackSpec] = []
    if not root.exists():
        return packs
    for child in sorted(root.iterdir()):
        if (child / "pack.yaml").exists():
            packs.append(load_pack_index(child.name, root))
    return packs
