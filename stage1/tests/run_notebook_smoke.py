"""실제 PE 소수 표본으로 노트북 셀을 순서대로 실행하는 통합 검사.

nbclient 없이 설치된 IPython으로 %%writefile까지 실제 실행한다.
노트북 자체의 full 설정/빈 출력은 변경하지 않는다. 성능 측정용 실행이 아니다.
"""
from __future__ import annotations

import ast
import json
import os
import traceback
from pathlib import Path

os.environ["MPLBACKEND"] = "Agg"
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

ROOT = Path(__file__).resolve().parents[1]
os.chdir(ROOT)
notebook = json.loads((ROOT / "stage1_xgboost_training.ipynb").read_text(encoding="utf-8"))
assert notebook["nbformat"] == 4
assert len({cell["id"] for cell in notebook["cells"]}) == len(notebook["cells"])
for cell in notebook["cells"]:
    if cell["cell_type"] == "code":
        source = cell["source"]
        assert cell["outputs"] == [] and cell["execution_count"] is None
        ast.parse(source.split("\n", 1)[1] if source.startswith("%%writefile") else source)

from IPython.core.interactiveshell import InteractiveShell

shell = InteractiveShell.instance()
executed = []
try:
    for index, cell in enumerate(notebook["cells"]):
        if cell["cell_type"] != "code":
            continue
        tags = cell.get("metadata", {}).get("tags", [])
        if any(tag in tags for tag in ("install", "widgets")):
            continue
        source = cell["source"]
        if "configuration" in tags:
            source = source.replace('RUN_MODE = "full"', 'RUN_MODE = "smoke"')
        print(f"\nExecuting notebook cell {index}: {source.splitlines()[0][:100]}", flush=True)
        result = shell.run_cell(source, store_history=False)
        if not result.success:
            raise RuntimeError(f"Notebook cell {index} failed") from (
                result.error_before_exec or result.error_in_exec)
        executed.append(index)

    ns = shell.user_ns
    assert len(ns["metadata"]) == 72
    assert len(ns["FEATURE_NAMES"]) == 341
    assert ns["X"].shape == (72, 341)
    assert not ns["stage2_pending"].stage1_result.isin(["Normal", "Error"]).any()
    ns["assert_frozen_policy"]()
    original_low = ns["LOW"]
    ns["LOW"] = 0.11
    try:
        ns["assert_frozen_policy"]()
    except RuntimeError:
        pass
    else:
        raise AssertionError("Changed threshold was not rejected")
    finally:
        ns["LOW"] = original_low
    # 트리/속성이 변경됐을 때도 이전 모델의 Test 정책을 그대로 쓸 수 없다.
    booster = ns["model_combined"].get_booster()
    booster.set_attr(smoke_mutation_check="changed")
    try:
        ns["assert_frozen_policy"]()
    except RuntimeError:
        pass
    else:
        raise AssertionError("Changed model was not rejected")
    finally:
        booster.set_attr(smoke_mutation_check=None)
    ns["assert_frozen_policy"]()
    # 잘못된 새 입력은 예외나 정상 판정 대신 별도 Error로 끝나야 한다.
    missing = ns["detector"].analyze_file(ns["RUN_DIR"] / "missing_pe_input")
    assert missing["stage1_result"] == "Error"
    assert missing["stage2_pending"] is None and not missing["needs_stage2"]
    report = {
        "status": "passed", "mode": "smoke_not_performance",
        "executed_cells": executed, "rows": len(ns["metadata"]),
        "features": len(ns["FEATURE_NAMES"]),
        "extraction_status": ns["metadata"].parse_status.value_counts().to_dict(),
        "full_manifest_rows_audited": ns["dataset_audit"]["rows"],
        "checks": ["ordered notebook execution", "actual IPython writefile expansion",
                   "two real XGBoost fits", "score save/load equality", "PE re-extraction equality",
                   "threshold/model freeze mutations rejected", "missing file Error not forwarded",
                   "no Normal/Error in stage2 list"],
    }
    ns["json_write"](ns["RUN_DIR"] / "smoke_verification.json", report)
    print("\nSMOKE_PASSED", ns["RUN_DIR"], flush=True)
except Exception:
    traceback.print_exc()
    raise
