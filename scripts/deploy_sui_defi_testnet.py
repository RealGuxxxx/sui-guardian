#!/usr/bin/env python3
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List


def run_cmd(args: List[str], cwd: Path) -> Any:
    completed = subprocess.run(
        args,
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stdout)
    text = completed.stdout or ""
    starts = [i for i, c in enumerate(text) if c in "{["]
    if not starts:
        raise RuntimeError(text)
    for start in starts:
        try:
            return json.loads(text[start:])
        except json.JSONDecodeError:
            continue
    raise RuntimeError(text)


def extract_publish(payload: Dict[str, Any]) -> Dict[str, Any]:
    package_id = None
    upgrade_cap = None
    created: Dict[str, str] = {}
    for change in payload.get("objectChanges", []):
        if change.get("type") == "published":
            package_id = change.get("packageId")
        if change.get("type") == "created":
            obj_type = change.get("objectType", "")
            obj_id = change.get("objectId")
            if obj_type == "0x2::package::UpgradeCap":
                upgrade_cap = obj_id
            if isinstance(obj_type, str) and isinstance(obj_id, str) and obj_type:
                created[obj_type] = obj_id
    if not package_id:
        raise RuntimeError("missing packageId")
    return {
        "packageId": package_id,
        "upgradeCapId": upgrade_cap,
        "createdObjects": created,
    }


def main() -> None:
    if len(sys.argv) < 3:
        print("usage: deploy_sui_defi_testnet.py <sourceRoot> <projectId>")
        sys.exit(1)
    source_root = Path(sys.argv[1]).resolve()
    project_id = sys.argv[2]

    packages = ["library", "i256", "airdrop", "launchpad", "clamm"]
    out_dir = Path(".data/deployments")
    out_dir.mkdir(parents=True, exist_ok=True)

    manifest: Dict[str, Any] = {
        "projectId": project_id,
        "network": "testnet",
        "packages": [],
    }

    for label in packages:
        pkg_dir = source_root / label
        payload = run_cmd(["sui", "client", "publish", "--gas-budget", "100000000", "--json", "."], cwd=pkg_dir)
        extracted = extract_publish(payload)
        manifest["packages"].append(
            {
                "label": label,
                **extracted,
            }
        )

    target = out_dir / f"{project_id}.json"
    target.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()

