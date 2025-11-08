import json
from lambdas.lib.parser import parse_iac_plan
from lambdas.lib.correlation_engine import correlate_threats
from lambdas.lib.risk_scoring import calculate_risk
from lambdas.lib.explanation_builder import build_explanation


def test_worker_full_pipeline():
    """
    Full local simulation of the Worker Lambda pipeline using real logic:
    - Parses IaC plan
    - Simulates fake threat findings
    - Correlates contextually
    - Calculates risk score
    - Builds final explanation records
    """

    # === Step 1: Fake Terraform plan ===
    fake_plan = {
        "resource_changes": [
            {
                "address": "aws_s3_bucket.publicbucket",
                "type": "aws_s3_bucket",
                "name": "publicbucket",
                "change": {"after": {"acl": "public-read"}}
            },
            {
                "address": "aws_instance.web",
                "type": "aws_instance",
                "name": "web",
                "change": {"after": {"associate_public_ip_address": True}}
            }
        ]
    }

    # === Step 2: Parse IaC ===
    resources = parse_iac_plan(fake_plan)
    assert isinstance(resources, list) and len(resources) > 0, "Parser failed to extract resources"

    results = []

    # === Step 3: Run simulated threat checks ===
    for res in resources:
        # Simulate feeds
        fake_findings = [
            {"feed": "otx", "risk": "LOW"},
            {"feed": "shodan", "risk": "HIGH"}
        ]

        # Match correlation_engine format
        res_struct = {
            "attributes": res.get("change", {}).get("after", {}),
            "type": res.get("type")
        }

        correlated = correlate_threats(res_struct, fake_findings)
        score = calculate_risk([{"risk_level": f["risk"]} for f in correlated])

        # ✅ FIXED: pass the entire resource dict, the correlated findings list, and the score
        explanation = build_explanation(
            resource=res,
            correlated_findings=correlated,
            score=score
        )
        results.append(explanation)

    # === Step 4: Build final output ===
    output = {
        "scan_id": "local-simulated-scan",
        "status": "COMPLETED",
        "results_json": results,
        "skipped_feeds": []
    }

    print(json.dumps(output, indent=2))

    # === Step 5: Assert expected severity ===
    assert any(r["risk_score"] in ["HIGH", "CRITICAL"] for r in results), \
        "Expected at least one HIGH/CRITICAL risk result"
