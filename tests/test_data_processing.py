# tests/test_data_processing.py - New file
import pytest
from unittest.mock import patch, MagicMock
from microservice.data_collector import HejtoDataCollector, COMMUNITY_MODELS
from datetime import datetime

def test_extract_distances_edge_cases(data_collector):
    """Test edge cases for the distance extraction function."""
    # Test empty content
    community_distance, runner_distance, run_count = data_collector._extract_distances("", "Sztafeta")
    assert community_distance == 0.0
    assert runner_distance == 0.0
    assert run_count == 0
    
    # Test content with no equals sign
    content = "12 345,6 km run today!"
    community_distance, runner_distance, run_count = data_collector._extract_distances(content, "Sztafeta")
    assert community_distance == 0.0
    assert runner_distance == 0.0
    assert run_count == 0
    
    # Test content with equals but no operation
    content = "12 345,6 = 12 345,6"
    community_distance, runner_distance, run_count = data_collector._extract_distances(content, "Sztafeta")
    assert community_distance == 0.0
    assert runner_distance == 0.0
    assert run_count == 0
    
    # Test with multiple lines
    content = "12 345,6 + 5,4 = 12 351,0\nSecond line\nThird line"
    community_distance, runner_distance, run_count = data_collector._extract_distances(content, "Sztafeta")
    assert community_distance == 12345.6
    assert runner_distance == 5.4
    assert run_count == 1
    
    # Test with multiple operations
    content = "12 345,6 + 5,4 + 10,2 = 12 361,2"
    community_distance, runner_distance, run_count = data_collector._extract_distances(content, "Sztafeta")
    assert community_distance == 12345.6
    assert runner_distance == 15.6  # 5.4 + 10.2
    assert run_count == 2

def test_update_summary_tables_logic(data_collector, db_session):
    """Test that summary tables correctly aggregate data."""
    # Get the Post model for Sztafeta
    SztafetaPost = COMMUNITY_MODELS['Sztafeta']['Post']
    WeeklySummaryModel = COMMUNITY_MODELS['Sztafeta']['WeeklySummary']
    RunnerMonthlyStatsModel = COMMUNITY_MODELS['Sztafeta']['RunnerMonthlyStats']
    RunnerYearlyStatsModel = COMMUNITY_MODELS['Sztafeta']['RunnerYearlyStats']
    
    # Create some test posts for different weeks, months, and authors
    posts = [
        # Week 1, Jan 2024, Author A
        SztafetaPost(
            id="test_post_1",
            author="Author A",
            content="Test content 1",
            community_distance=100.0,
            runner_distance=5.0,
            run_count=1,
            created_at=datetime(2024, 1, 5),
            week_number=1,
            year=2024
        ),
        # Week 1, Jan 2024, Author A (second run)
        SztafetaPost(
            id="test_post_2",
            author="Author A",
            content="Test content 2",
            community_distance=105.0,
            runner_distance=3.0,
            run_count=1,
            created_at=datetime(2024, 1, 6),
            week_number=1,
            year=2024
        ),
        # Week 2, Jan 2024, Author B
        SztafetaPost(
            id="test_post_3",
            author="Author B",
            content="Test content 3",
            community_distance=108.0,
            runner_distance=10.0,
            run_count=1,
            created_at=datetime(2024, 1, 10),
            week_number=2,
            year=2024
        ),
        # Week 5, Feb 2024, Author A
        SztafetaPost(
            id="test_post_4",
            author="Author A",
            content="Test content 4",
            community_distance=118.0,
            runner_distance=8.0,
            run_count=1,
            created_at=datetime(2024, 2, 2),
            week_number=5,
            year=2024
        ),
    ]
    
    db_session.add_all(posts)
    db_session.commit()
    
    # Update summary tables
    data_collector.update_summary_tables("Sztafeta")
    
    # Test weekly summaries
    week1_summary = db_session.query(WeeklySummaryModel).filter_by(year=2024, week_number=1).first()
    assert week1_summary is not None
    assert week1_summary.total_distance == 8.0  # 5.0 + 3.0
    
    week2_summary = db_session.query(WeeklySummaryModel).filter_by(year=2024, week_number=2).first()
    assert week2_summary is not None
    assert week2_summary.total_distance == 10.0
    
    # Test monthly stats
    author_a_jan = db_session.query(RunnerMonthlyStatsModel).filter_by(
        year=2024, month=1, author="Author A"
    ).first()
    assert author_a_jan is not None
    assert author_a_jan.total_distance == 8.0  # 5.0 + 3.0
    assert author_a_jan.total_runs == 2
    assert author_a_jan.average_distance_per_run == 4.0  # (5.0 + 3.0) / 2
    
    # Test yearly stats
    author_a_2024 = db_session.query(RunnerYearlyStatsModel).filter_by(
        year=2024, author="Author A"
    ).first()
    assert author_a_2024 is not None
    assert author_a_2024.total_distance == 16.0  # 5.0 + 3.0 + 8.0
    assert author_a_2024.total_runs == 3