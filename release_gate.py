from fastapi import FastAPI
from typing import Any

app = FastAPI()


@app.post("/release-gate")
def release_gate(payload: dict[str, Any]):
    violations = []

    target = payload.get("target")
    event = payload.get("event")
    ref = payload.get("ref")
    workflow = payload.get("workflow", {})
    image = payload.get("image", {})

    # 1. Permissions must be exactly:
    # contents: read
    # packages: write
    # id-token: none
    expected_permissions = {
        "contents": "read",
        "packages": "write",
        "id-token": "none",
    }

    if workflow.get("permissions") != expected_permissions:
        violations.append("EXCESS_PERMISSION")

    # 2. Pull requests must use pull_request, not pull_request_target
    if event == "pull_request" and workflow.get("trigger") != "pull_request":
        violations.append("UNSAFE_PR_TRIGGER")

    # 3. Tests + complete matrix + failFast false
    if (
        workflow.get("testsPassed") is not True
        or workflow.get("matrixComplete") is not True
        or workflow.get("failFast") is not False
    ):
        violations.append("TESTS_INCOMPLETE")

    # 4. Action pinning
    # actions/* may use a version tag.
    # Every third-party action must use a 40-char lowercase SHA.
    for action in workflow.get("actions", []):
        owner = action.get("owner", "")
        action_ref = action.get("ref", "")

        if owner == "actions":
            continue

        if not (
            isinstance(action_ref, str)
            and len(action_ref) == 40
            and all(c in "0123456789abcdef" for c in action_ref)
        ):
            violations.append("MUTABLE_ACTION")
            break

    # 5. Image requirements
    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    if image.get("secretMode") not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")

    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # 6. Production requirements
    if target == "production":
        if event != "push" or ref != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")

        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    return {
        "decision": "promote" if not violations else "block",
        "violations": violations,
    }
