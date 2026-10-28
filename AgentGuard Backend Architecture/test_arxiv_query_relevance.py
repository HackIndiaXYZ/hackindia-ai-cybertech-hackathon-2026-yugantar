"""Offline regression tests for precise arXiv query construction.

Run from the backend directory:
    python -m pytest -q test_agent_guard.py test_pdf_research_integration.py test_arxiv_query_relevance.py
"""

from agent_logic import ResearchAgent
from rag_engine import RAGPipeline


def test_machine_learning_query_uses_phrase_and_boolean_qualifiers():
    expression = RAGPipeline._build_arxiv_search_expression(
        "machine learning accuracy distribution data"
    )

    assert 'all:"machine learning"' in expression
    assert " AND (" in expression
    assert " OR " in expression
    assert "all:machine OR all:learning" not in expression


def test_concept_drift_query_preserves_the_important_phrase():
    expression = RAGPipeline._build_arxiv_search_expression(
        "concept drift data quality monitoring"
    )

    assert 'all:"concept drift"' in expression
    assert 'all:"data quality"' in expression
    assert "all:monitoring" in expression
    assert expression.startswith('all:"concept drift" AND (')


def test_claim_query_builder_keeps_concept_drift_instead_of_truncating_it():
    statement = (
        "Monitoring data quality and evaluating models on recent examples "
        "can help identify concept drift."
    )

    query = ResearchAgent._build_claim_search_query(statement)

    assert "concept drift" in query.lower()
    assert "data quality" in query.lower()
    assert "monitoring" in query.lower()


def test_short_multiword_query_is_preserved_as_a_phrase():
    expression = RAGPipeline._build_arxiv_search_expression("renewable energy")
    assert expression == 'all:"renewable energy"'


def test_relevance_ranker_prefers_distribution_shift_paper_over_interpretability_paper():
    from rag_engine import ResearchSource

    claim = "Machine learning models can lose accuracy when the distribution of incoming data changes over time."
    sources = [
        ResearchSource(
            source_id="relevant",
            title="Machine Learning Accuracy Under Distribution Shift",
            url="https://arxiv.org/abs/2401.00001v1",
            abstract=(
                "We study distribution shift in deployed machine learning systems. "
                "Predictive accuracy can deteriorate when incoming data changes, and "
                "monitoring model performance helps identify concept drift."
            ),
        ),
        ResearchSource(
            source_id="irrelevant",
            title="Physics-Inspired Interpretability of Machine Learning Models",
            url="https://arxiv.org/abs/2401.00002v1",
            abstract=(
                "This paper explains decisions made by machine learning models by "
                "identifying relevant input features and loss landscapes."
            ),
        ),
        ResearchSource(
            source_id="learning-curves",
            title="Learning Curves for Decision Making in Supervised Machine Learning",
            url="https://arxiv.org/abs/2401.00003v1",
            abstract=(
                "Learning curves assess model performance with respect to resources "
                "such as the number of training examples."
            ),
        ),
    ]

    ranked = RAGPipeline.rank_academic_sources_for_claim(claim, sources, max_results=3)
    ranked_ids = [source.source_id for source, score in ranked]

    assert ranked_ids
    assert ranked_ids[0] == "relevant"
    assert "irrelevant" not in ranked_ids
    assert all(0.18 <= score <= 1.0 for source, score in ranked)


def test_learning_curve_claim_prioritizes_learning_curve_literature():
    from rag_engine import ResearchSource

    claim = "Learning curves can be used to assess how model performance changes as the number of training examples increases."
    sources = [
        ResearchSource(
            source_id="concept-drift",
            title="Class Distribution Monitoring for Concept Drift Detection",
            url="https://arxiv.org/abs/2401.00004v1",
            abstract="This work monitors class distributions to detect concept drift in data streams.",
        ),
        ResearchSource(
            source_id="learning-curves",
            title="Learning Curves for Decision Making in Supervised Machine Learning: A Survey",
            url="https://arxiv.org/abs/2201.12150v2",
            abstract=(
                "Learning curves assess a learning algorithm with respect to a resource, "
                "such as the number of training examples or iterations."
            ),
        ),
    ]

    ranked = RAGPipeline.rank_academic_sources_for_claim(claim, sources, max_results=3)
    assert ranked
    assert ranked[0][0].source_id == "learning-curves"


def test_summary_reference_section_is_removed_if_llm_ignores_instruction():
    from agent_logic import ResearchAgent

    generated = (
        "The excerpt discusses concept drift and evaluation on recent examples.\n\n"
        "## Academic literature that discusses these topics\n"
        "• Gama, J. et al. (2014). A survey on concept drift adaptation.\n"
        "These references have not been verified by the application."
    )
    cleaned = ResearchAgent._strip_unverified_reference_sections(generated)
    assert "concept drift" in cleaned
    assert "Academic literature" not in cleaned
    assert "Gama" not in cleaned
