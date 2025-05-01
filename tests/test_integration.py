# tests/test_integration.py - Integration tests for the application
import pytest
from unittest.mock import patch, MagicMock
import json
from datetime import datetime
from microservice.data_collector import COMMUNITY_MODELS

@patch('microservice.data_collector.requests.get')
def test_data_flow(mock_requests_get, data_collector, db_session):
    """Test the full data flow from API to database to web app"""
    # Mock the API response with a sample post
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "_embedded": {
            "items": [
                {
                    "content_plain": "12 345,6 + 5,4 = 12 351,0\nGreat run today!",
                    "author": {
                        "username": "test_user"
                    },
                    "created_at": "2024-03-01T12:00:00Z",
                    "slug": "test-post"
                }
            ]
        }
    }
    mock_requests_get.return_value = mock_response
    
    # Trigger the fetch and process
    data_collector.fetch_posts("Sztafeta")
    
    # Get the Post model for Sztafeta
    SztafetaPost = COMMUNITY_MODELS['Sztafeta']['Post']
    
    # Check that the post was added to the database
    post = db_session.query(SztafetaPost).first()
    assert post is not None
    assert post.author == "test_user"
    assert post.community_distance == 12345.6
    assert post.runner_distance == 5.4
    assert post.run_count == 1
    
    # Check that the summary tables were updated
    WeeklySummaryModel = COMMUNITY_MODELS['Sztafeta']['WeeklySummary']
    weekly_summary = db_session.query(WeeklySummaryModel).first()
    assert weekly_summary is not None
    assert weekly_summary.total_distance == 5.4
    
    RunnerYearlyStatsModel = COMMUNITY_MODELS['Sztafeta']['RunnerYearlyStats']
    yearly_stats = db_session.query(RunnerYearlyStatsModel).first()
    assert yearly_stats is not None
    assert yearly_stats.author == "test_user"
    assert yearly_stats.total_runs == 1