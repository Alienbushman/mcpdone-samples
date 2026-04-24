"""Sources that surface content opportunities."""
from mcp_content_opportunity.sources.hackernews import search_hackernews
from mcp_content_opportunity.sources.reddit import search_reddit

__all__ = ["search_hackernews", "search_reddit"]
