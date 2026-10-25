"""Regression tests for summary/retrieval consistency. Run from backend folder."""

from agent_logic import ResearchAgent


CLAIMS = [
    "[NOT_ENOUGH_EVIDENCE] (verdict_method: document_only_extraction) Machine learning models can lose accuracy when the distribution of incoming data changes over time.",
    "[NOT_ENOUGH_EVIDENCE] (verdict_method: document_only_extraction) Monitoring data quality and evaluating models on recent examples can help identify concept drift.",
    "[NOT_ENOUGH_EVIDENCE] (verdict_method: document_only_extraction) Learning curves can be used to assess how model performance changes as the number of training examples increases.",
]


def test_retrieval_summary_does_not_claim_no_literature_was_consulted():
    summary = (
        "The document presents assertions but no empirical evidence. "
        "No additional verification or external literature has been consulted; "
        "the summary reflects only the content of the supplied excerpt."
    )
    fixed = ResearchAgent._finalize_summary_for_retrieval(
        summary, CLAIMS, sources_found=True
    )
    assert "No additional verification or external literature has been consulted" not in fixed
    assert "Related academic source candidates are listed separately" in fixed
    assert "independently verify the claims" in fixed


def test_broken_numbered_outline_is_replaced_with_all_three_claims():
    summary = (
        "**Summary**\n\n"
        "1. **Potential loss of accuracy** — first point.\n"
        "3. **Use of learning curves** — third point."
    )
    fixed = ResearchAgent._finalize_summary_for_retrieval(
        summary, CLAIMS, sources_found=True
    )
    assert "1. **Distribution shift**" in fixed
    assert "2. **Concept-drift monitoring**" in fixed
    assert "3. **Learning curves**" in fixed


def test_no_sources_found_summary_does_not_suggest_retrieved_candidates_exist():
    summary = "Summary of the excerpt. No external literature has been consulted."
    fixed = ResearchAgent._finalize_summary_for_retrieval(
        summary, CLAIMS, sources_found=False
    )
    assert "No external literature has been consulted" not in fixed
    assert "Retrieval did not produce usable academic source candidates" in fixed
