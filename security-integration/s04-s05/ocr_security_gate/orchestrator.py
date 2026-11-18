# SPDX-License-Identifier: Apache-2.0
"""Plans compose exact prior disabled plans, never processes or callbacks."""
from ocr_security.common import Refusal, canonical, digest, sha
from ocr_security_adapters.boundary import Plan
from .contracts import ADAPTERS, bind_policy


def offline_plan(target, policy, adapter_plans):
    bind_policy(policy, target)
    if type(adapter_plans) is not tuple or len(adapter_plans) != 5:
        raise Refusal("complete_baseline_plans_required")
    documents = []
    roles = set()
    ocr_projections = set()
    ocr_assets = set()
    for plan in adapter_plans:
        if not isinstance(plan, Plan): raise Refusal("prior_plan_required")
        value = plan.document()
        name = value["adapter"]
        role = (name, value["operation"])
        if name not in ADAPTERS or role in roles or value["snapshot_id"] != target["snapshot_id"]:
            raise Refusal("unbound_adapter_plan")
        if value["policy_sha256"] != target["adapter_policy_sha256"] or value["execution_enabled"] is not False:
            raise Refusal("unbound_adapter_policy")
        if name == "ocr":
            if value["operation"] not in ("preview", "rule"):
                raise Refusal("incomplete_ocr_operations")
            ocr_projections.add(sha(value["asset_pins"].get("model_projection")))
            if value["view"] != "model":raise Refusal("invalid_ocr_view")
            ocr_assets.add(digest(canonical([value["tool_sha256"], value["asset_pins"]])))
        elif any(existing[0] == name for existing in roles):
            raise Refusal("duplicate_adapter_plan")
        roles.add(role)
        documents.append({"adapter":name,"operation":value["operation"],"plan_sha256":sha(plan.identity),"requirements":value})
    if ({name for name, _ in roles} != set(ADAPTERS) or
        not {("ocr", "preview"), ("ocr", "rule")} <= roles or len(ocr_projections) != 1 or len(ocr_assets) != 1):
        raise Refusal("complete_baseline_plans_required")
    result = {"schema_version":"1.0","kind":"disabled-offline-orchestration","subject":dict(target),
              "gate_policy_sha256":policy.sha256,"plans":documents,"execution_enabled":False,
              "acquisition_allowed":False,"network":"denied","root_filesystem":"readonly_allowlisted",
              "environment":"empty_explicit_allowlist","credentials_and_sockets":"absent",
              "resource_and_output_limits":"inherited_exact_s01_profile_required",
              "qualification":"HELD","status":"not-run"}
    return dict(result, plan_sha256=digest(canonical(result)))


def execute(*args, **kwargs):
    raise Refusal("native_orchestration_unqualified")


def rollback():
    return {"execution_enabled":False,"security_review":"NOT_RUN","coverage":"incomplete",
            "previous_verified_manifests":"retained","raw_evidence":"retained_private",
            "standard_ocr":"unchanged","target_acceptance":"not-run"}
