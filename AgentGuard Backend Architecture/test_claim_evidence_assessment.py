"""Offline tests for quote-validated, conservative abstract-level assessment."""

import json

from agent_logic import ResearchAgent
from rag_engine import ResearchSource


def source(source_id: str, abstract: str) -> ResearchSource:
    return ResearchSource(
        source_id=source_id,
        title=f"Test paper {source_id}",
        url=f"https://arxiv.org/abs/{source_id}",
        abstract=abstract,
        published="2024-01-01T00:00:00Z",
        authors=["Test Author"],
        provenance="arxiv_public_api",
        is_tainted=False,
        injection_reasons=[],
    )


def assessments_for(statuses_and_quotes):
    sources = [source(source_id, abstract) for source_id, abstract, _, _ in statuses_and_quotes]
    payload = {
        "assessments": [
            {
                "source_id": source_id,
                "assessment": assessment,
                "evidence_quote": quote,
                "rationale": "Test assessment.",
            }
            for source_id, _abstract, assessment, quote in statuses_and_quotes
        ]
    }
    return ResearchAgent._parse_source_evidence_assessments(json.dumps(payload), sources)


def test_two_quote_validated_supports_are_required_for_supported_verdict():
    items = assessments_for([
        ("2401.00001v1", "Predictive accuracy can decline when incoming data distributions shift.", "SUPPORTS", "Predictive accuracy can decline when incoming data distributions shift."),
        ("2401.00002v1", "Changing data distributions may reduce model performance over time.", "SUPPORTS", "Changing data distributions may reduce model performance over time."),
    ])
    verdict, rationale = ResearchAgent._aggregate_source_assessments(items, "llm_abstract_assessment")
    assert all(item.quote_validated for item in items)
    assert verdict == "SUPPORTED"
    assert "provisional" in rationale.lower()


def test_one_supporting_source_is_not_enough_for_supported_verdict():
    items = assessments_for([
        ("2401.00001v1", "Predictive accuracy can decline when incoming data distributions shift.", "SUPPORTS", "Predictive accuracy can decline when incoming data distributions shift."),
        ("2401.00002v1", "The paper discusses unrelated interpretability methods for neural models.", "NOT_ENOUGH_EVIDENCE", ""),
    ])
    verdict, _ = ResearchAgent._aggregate_source_assessments(items, "llm_abstract_assessment")
    assert verdict == "NOT_ENOUGH_EVIDENCE"


def test_quote_not_found_in_source_is_downgraded():
    items = assessments_for([
        ("2401.00001v1", "The abstract studies model calibration under dataset shift.", "SUPPORTS", "This invented quote does not occur in the abstract at all."),
    ])
    assert len(items) == 1
    assert items[0].assessment == "NOT_ENOUGH_EVIDENCE"
    assert items[0].quote_validated is False
    assert items[0].evidence_quote == ""
    verdict, _ = ResearchAgent._aggregate_source_assessments(items, "llm_abstract_assessment")
    assert verdict == "NOT_ENOUGH_EVIDENCE"


def test_conflicting_quote_validated_sources_produce_mixed_evidence():
    items = assessments_for([
        ("2401.00001v1", "Predictive accuracy can decline when incoming data distributions shift.", "SUPPORTS", "Predictive accuracy can decline when incoming data distributions shift."),
        ("2401.00002v1", "In our setting, distribution shift did not reduce predictive accuracy in the evaluated models.", "CONTRADICTS", "distribution shift did not reduce predictive accuracy in the evaluated models"),
    ])
    verdict, rationale = ResearchAgent._aggregate_source_assessments(items, "llm_abstract_assessment")
    assert all(item.quote_validated for item in items)
    assert verdict == "MIXED_EVIDENCE"
    assert "conflict" in rationale.lower()


def test_directional_verdict_requires_quote_validated_evidence_and_two_sources():
    items = assessments_for([
        ("2401.00001v1", "The model accuracy decreases under shift in incoming data distributions.", "CONTRADICTS", "The model accuracy decreases under shift in incoming data distributions."),
        ("2401.00002v1", "Incoming distributions change, but no result about accuracy is reported.", "NOT_ENOUGH_EVIDENCE", ""),
    ])
    verdict, _ = ResearchAgent._aggregate_source_assessments(items, "llm_abstract_assessment")
    assert verdict == "NOT_ENOUGH_EVIDENCE"


def test_unknown_source_id_is_not_accepted():
    src = source("2401.00001v1", "This abstract discusses concept drift and monitoring model performance.")
    payload = {
        "assessments": [
            {
                "source_id": "not-a-returned-source",
                "assessment": "SUPPORTS",
                "evidence_quote": "This abstract discusses concept drift and monitoring model performance.",
                "rationale": "Unknown source test.",
            }
        ]
    }
    items = ResearchAgent._parse_source_evidence_assessments(json.dumps(payload), [src])
    assert items == []


def test_llm_assessor_uses_only_supplied_ids_and_returns_source_validated_quotes(monkeypatch):
    import sys
    from types import SimpleNamespace

    monkeypatch.setenv("GROQ_API_KEY", "test-key-not-a-real-secret")
    monkeypatch.setenv("GROQ_MODEL", "test-model")

    src1 = source(
        "2401.00001v1",
        "Predictive accuracy can decline when incoming data distributions shift.",
    )
    src2 = source(
        "2401.00002v1",
        "Changing data distributions may reduce model performance over time.",
    )
    response_content = json.dumps({
        "assessments": [
            {
                "source_id": src1.source_id,
                "assessment": "SUPPORTS",
                "evidence_quote": "Predictive accuracy can decline when incoming data distributions shift.",
                "rationale": "The abstract directly links distribution shift and accuracy decline.",
            },
            {
                "source_id": src2.source_id,
                "assessment": "SUPPORTS",
                "evidence_quote": "Changing data distributions may reduce model performance over time.",
                "rationale": "The abstract directly relates changing distributions to reduced performance.",
            },
        ]
    })
    call_details = {}

    class FakeOpenAI:
        def __init__(self, **kwargs):
            call_details["client"] = kwargs
            self.chat = SimpleNamespace(
                completions=SimpleNamespace(create=self.create)
            )

        def create(self, **kwargs):
            call_details["request"] = kwargs
            return SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content=response_content))]
            )

    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=FakeOpenAI))
    agent = ResearchAgent()
    source_assessments, method = agent._assess_claim_against_sources(
        "Machine learning models can lose accuracy when incoming data distributions shift.",
        [src1, src2],
    )
    verdict, rationale = ResearchAgent._aggregate_source_assessments(source_assessments, method)

    assert method == "llm_abstract_assessment"
    assert [item.source_id for item in source_assessments] == [src1.source_id, src2.source_id]
    assert all(item.quote_validated for item in source_assessments)
    assert verdict == "SUPPORTED"
    assert "provisional" in rationale.lower()
    assert call_details["client"]["base_url"] == "https://api.groq.com/openai/v1"
    assert call_details["request"]["temperature"] == 0
    assert call_details["request"]["extra_body"]["include_reasoning"] is False
    assert "reasoning_format" not in call_details["request"]
    assert "include_reasoning" not in call_details["request"]
    assert call_details["request"]["response_format"] == {"type": "json_object"}
    assert not call_details["request"].get("tools")



def test_invalid_quote_gets_one_source_retry_and_only_accepts_verbatim_quote(monkeypatch):
    import sys
    from types import SimpleNamespace

    monkeypatch.setenv("GROQ_API_KEY", "test-key-not-a-real-secret")
    monkeypatch.setenv("GROQ_MODEL", "test-model")

    abstract = (
        "We predict learning curves (test risk vs. sample size) from raw data statistics. "
        "The method estimates model performance as the number of examples grows."
    )
    src = source("2401.90001v1", abstract)
    calls = []

    first_payload = json.dumps({
        "assessments": [{
            "source_id": src.source_id,
            "assessment": "SUPPORTS",
            "evidence_quote": "A paraphrased claim about sample size and test risk, not an exact quote.",
            "rationale": "The abstract discusses learning curves and sample size.",
        }]
    })
    second_payload = json.dumps({
        "assessments": [{
            "source_id": src.source_id,
            "assessment": "SUPPORTS",
            "evidence_quote": "We predict learning curves (test risk vs. sample size) from raw data statistics.",
            "rationale": "The exact sentence defines the learning curve in relation to sample size.",
        }]
    })

    class FakeOpenAI:
        def __init__(self, **kwargs):
            self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

        def create(self, **kwargs):
            calls.append(kwargs)
            content = first_payload if len(calls) == 1 else second_payload
            return SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content=content))]
            )

    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=FakeOpenAI))
    agent = ResearchAgent()
    assessments, method = agent._assess_claim_against_sources(
        "Learning curves can assess performance as the number of examples increases.",
        [src],
    )

    assert len(calls) == 2, "An invalid first quote should trigger one strict single-source retry."
    assert len(json.loads(calls[1]["messages"][1]["content"])["sources"]) == 1
    assert method == "llm_abstract_assessment"
    assert len(assessments) == 1
    assert assessments[0].assessment == "SUPPORTS"
    assert assessments[0].quote_validated is True
    assert assessments[0].evidence_quote in abstract


def test_assessment_fails_closed_when_api_key_is_missing(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "")
    agent = ResearchAgent()
    sources = [source(
        "2401.00001v1",
        "Predictive accuracy can decline when incoming data distributions shift.",
    )]
    result, method = agent._assess_claim_against_sources("Distribution shift can reduce accuracy.", sources)
    verdict, _ = ResearchAgent._aggregate_source_assessments(result, method)
    assert result == []
    assert method == "not_run_no_api_key"
    assert verdict == "NOT_ENOUGH_EVIDENCE"


def test_guarded_retrieval_includes_final_abstract_assessment(monkeypatch):
    import sys
    from types import SimpleNamespace
    import agent_logic as agent_module
    from rag_engine import ExtractedClaim

    monkeypatch.setenv("GROQ_API_KEY", "test-key-not-a-real-secret")

    sources = [
        source("2401.10001v1", "Predictive accuracy can decline when incoming data distributions shift. Monitoring recent data can help detect this issue."),
        source("2401.10002v1", "Changing data distributions may reduce model performance over time. This paper studies model drift monitoring."),
        source("2401.10003v1", "A distribution shift can degrade predictive model accuracy in deployed systems. We evaluate monitoring methods."),
    ]

    class FakeOpenAI:
        def __init__(self, **kwargs):
            self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

        def create(self, **kwargs):
            user_payload = json.loads(kwargs["messages"][1]["content"])
            model_assessments = []
            for item in user_payload["sources"]:
                abstract = item["abstract"]
                model_assessments.append({
                    "source_id": item["source_id"],
                    "assessment": "SUPPORTS",
                    "evidence_quote": abstract[:min(110, len(abstract))],
                    "rationale": "The abstract explicitly discusses accuracy decline under distribution shift.",
                })
            return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=json.dumps({"assessments": model_assessments})))])

    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=FakeOpenAI))
    agent = ResearchAgent()
    monkeypatch.setattr(agent.rag, "rank_academic_sources_for_claim", lambda claim, retrieved, max_results=3, min_score=0.18: [(item, 0.9) for item in retrieved[:max_results]])
    monkeypatch.setattr(agent.rag, "extract_claims_from_sources", lambda retrieved: [])
    monkeypatch.setattr(
        agent_module.GUARDED_TOOL_REGISTRY["search_academic_db"],
        "_raw_func",
        lambda query, max_results=3: agent_module.AcademicSearchResult("mock source records", sources[:max_results]),
    )

    def allow_gateway(tool_name, tool_args, session_context, detected_injection_text=None, human_approved=False):
        return agent_module.AgentGuardDecision(
            decision=agent_module.SecurityDecisionType.ALLOW,
            verdict="ALLOW",
            tool_name=tool_name,
            tool_args=tool_args,
            provenance_source="test_gateway",
            is_tainted=False,
            risk_level=agent_module.ToolRiskLevel.LOW,
            reason="Allowed by offline test gateway.",
            reasons=["TEST_ALLOW"],
            checks_fired=["TEST_GATEWAY"],
            action_lineage=[],
        )

    monkeypatch.setattr(agent_module.AgentGuardInterceptor, "inspect_and_evaluate", staticmethod(allow_gateway))
    claim = ExtractedClaim(
        claim_id="claim-1",
        statement="Machine learning models can lose accuracy when the distribution of incoming data changes over time.",
        evidence_text="Machine learning models can lose accuracy when the distribution of incoming data changes over time.",
        verdict="NOT_ENOUGH_EVIDENCE",
        verdict_method="document_only_extraction",
        confidence=0.3,
        rationale="Document-only extraction.",
    )

    retrieved_sources, _, reviews, lineage, result_text = agent._retrieve_pdf_claim_evidence(
        [claim], agent_module.SessionContext()
    )

    assert len(retrieved_sources) >= 2
    assert len(reviews) == 1
    assert reviews[0].verification_method == "llm_abstract_assessment"
    assert reviews[0].verdict == "SUPPORTED"
    assert len(reviews[0].source_assessments) >= 2
    assert all(item.quote_validated for item in reviews[0].source_assessments)
    assert any(node.type == "EVIDENCE_ASSESSMENT" for node in lineage)
    assert "preliminary LLM-assisted comparison" in result_text
