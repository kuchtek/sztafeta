# tests/test_data_collector.py - Test the HejtoDataCollector class
import pytest
from unittest.mock import patch, MagicMock
import datetime
from microservice.data_collector import HejtoDataCollector

def test_extract_distances():
    """Test the _extract_distances method for different community formats"""
    collector = HejtoDataCollector()
    
    # Test Sztafeta format (additive)
    sztafeta_content = "12 345,6 + 5,4 = 12 351,0\nSome additional text"
    community_distance, runner_distance, run_count = collector._extract_distances(sztafeta_content, "Sztafeta")
    assert community_distance == 12345.6
    assert runner_distance == 5.4
    assert run_count == 1
    
    # Test rowerowy-rownik format (additive)
    rownik_content = "24 680 + 120 = 24 800\nSome additional text"
    community_distance, runner_distance, run_count = collector._extract_distances(rownik_content, "rowerowy-rownik")
    assert community_distance == 24680
    assert runner_distance == 120
    assert run_count == 1
    
    # Test ksiezycowy-spacer format (subtractive)
    spacer_content = "384 400 - 10,5 = 384 389,5\nSome additional text"
    community_distance, runner_distance, run_count = collector._extract_distances(spacer_content, "ksiezycowy-spacer")
    assert community_distance == 384400
    assert runner_distance == 10.5
    assert run_count == 1
    
    # Test invalid content
    invalid_content = "Not a valid distance format"
    community_distance, runner_distance, run_count = collector._extract_distances(invalid_content, "Sztafeta")
    assert community_distance == 0.0
    assert runner_distance == 0.0
    assert run_count == 0

@patch('microservice.data_collector.requests.get')
def test_fetch_posts(mock_requests_get, data_collector):
    """Test the fetch_posts method"""
    # Mock the API response
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
    
    # Test fetching posts
    with patch.object(data_collector, 'process_posts') as mock_process_posts:
        data_collector.fetch_posts("Sztafeta")
        # Check that process_posts was called with the correct data
        mock_process_posts.assert_called_once()
        args = mock_process_posts.call_args[0]
        assert len(args[0]) == 1  # One post in the response
        assert args[1] == "Sztafeta"  # Community is Sztafeta

def test_generate_post_id(data_collector):
    """Test that post IDs are generated consistently"""
    content = "Test content"
    author = "test_user"
    created_at = "2024-03-01T12:00:00Z"
    
    # Generate the ID
    post_id_1 = data_collector._generate_post_id(content, author, created_at)
    post_id_2 = data_collector._generate_post_id(content, author, created_at)
    
    # ID should be a string
    assert isinstance(post_id_1, str)
    
    # Same inputs should give same ID
    assert post_id_1 == post_id_2
    
    # Different inputs should give different IDs
    post_id_3 = data_collector._generate_post_id("Different content", author, created_at)
    assert post_id_1 != post_id_3