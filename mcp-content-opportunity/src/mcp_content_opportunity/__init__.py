"""MCP server that finds content opportunities by querying HN and Reddit.

Given a topic, surfaces discussions that signal underserved demand — questions,
pain points, fresh and discussion-heavy threads — ranked into a content plan.

Public API:
    from mcp_content_opportunity import Opportunity, rank, to_markdown
    from mcp_content_opportunity.sources import search_hackernews, search_reddit
"""
from mcp_content_opportunity.formatter import to_markdown
from mcp_content_opportunity.models import Opportunity
from mcp_content_opportunity.ranker import rank
from mcp_content_opportunity.sources import search_hackernews, search_reddit

__all__ = [
    "Opportunity",
    "rank",
    "search_hackernews",
    "search_reddit",
    "to_markdown",
]

__version__ = "0.1.0"
