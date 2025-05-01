# tests/test_models.py - Test the SQLAlchemy models
import pytest
from datetime import datetime
from microservice.data_collector import COMMUNITY_MODELS

def test_post_model(db_session):
    """Test creating and querying a Post model"""
    # Get the Post model for Sztafeta
    SztafetaPost = COMMUNITY_MODELS['Sztafeta']['Post']
    
    # Create a new post
    post = SztafetaPost(
        id="test_post_id",
        author="test_user",
        content="Test content",
        community_distance=100.0,
        runner_distance=5.0,
        run_count=1,
        created_at=datetime.now(),
        week_number=10,
        year=2024
    )
    
    # Add to the session and commit
    db_session.add(post)
    db_session.commit()
    
    # Query the post back
    fetched_post = db_session.query(SztafetaPost).filter_by(id="test_post_id").first()
    
    # Check it's the same post
    assert fetched_post is not None
    assert fetched_post.id == "test_post_id"
    assert fetched_post.author == "test_user"
    assert fetched_post.community_distance == 100.0
    assert fetched_post.runner_distance == 5.0
    assert fetched_post.run_count == 1
    assert fetched_post.year == 2024

def test_summary_models(db_session):
    """Test creating and querying the summary models"""
    # Get the models for Sztafeta
    WeeklySummaryModel = COMMUNITY_MODELS['Sztafeta']['WeeklySummary']
    RunnerMonthlyStatsModel = COMMUNITY_MODELS['Sztafeta']['RunnerMonthlyStats']
    RunnerYearlyStatsModel = COMMUNITY_MODELS['Sztafeta']['RunnerYearlyStats']
    
    # Create summary records
    weekly_summary = WeeklySummaryModel(
        year=2024,
        week_number=10,
        total_distance=100.0
    )
    
    monthly_stats = RunnerMonthlyStatsModel(
        year=2024,
        month=3,
        author="test_user",
        total_distance=150.0,
        total_runs=5,
        average_distance_per_run=30.0
    )
    
    yearly_stats = RunnerYearlyStatsModel(
        year=2024,
        author="test_user",
        total_distance=500.0,
        total_runs=20,
        average_distance_per_run=25.0
    )
    
    # Add to the session and commit
    db_session.add_all([weekly_summary, monthly_stats, yearly_stats])
    db_session.commit()
    
    # Query and check the records
    fetched_weekly = db_session.query(WeeklySummaryModel).filter_by(year=2024, week_number=10).first()
    assert fetched_weekly is not None
    assert fetched_weekly.total_distance == 100.0
    
    fetched_monthly = db_session.query(RunnerMonthlyStatsModel).filter_by(year=2024, month=3, author="test_user").first()
    assert fetched_monthly is not None
    assert fetched_monthly.total_runs == 5
    
    fetched_yearly = db_session.query(RunnerYearlyStatsModel).filter_by(year=2024, author="test_user").first()
    assert fetched_yearly is not None
    assert fetched_yearly.total_distance == 500.0

def test_post_model_relationships(db_session):
    """Test the relationships between models and cascading operations."""
    SztafetaPost = COMMUNITY_MODELS['Sztafeta']['Post']
    
    # Create a test post
    post = SztafetaPost(
        id="cascade_test_id",
        author="test_user",
        content="Test content for cascade",
        community_distance=100.0,
        runner_distance=5.0,
        run_count=1,
        created_at=datetime.now(),
        week_number=10,
        year=2024
    )
    db_session.add(post)
    db_session.commit()
    
    # Verify it exists
    fetched = db_session.query(SztafetaPost).filter_by(id="cascade_test_id").first()
    assert fetched is not None
    
    # Test deletion
    db_session.delete(post)
    db_session.commit()
    
    # Verify it's gone
    fetched = db_session.query(SztafetaPost).filter_by(id="cascade_test_id").first()
    assert fetched is None

def test_model_constraints(db_session):
    """Test model constraints and validations."""
    SztafetaPost = COMMUNITY_MODELS['Sztafeta']['Post']
    
    # Test primary key constraint
    post1 = SztafetaPost(
        id="duplicate_id",
        author="test_user1",
        content="Test content 1",
        community_distance=100.0,
        runner_distance=5.0,
        run_count=1,
        created_at=datetime.now(),
        week_number=10,
        year=2024
    )
    db_session.add(post1)
    db_session.commit()
    
    # Try to add another post with the same ID (should fail)
    post2 = SztafetaPost(
        id="duplicate_id",
        author="test_user2",
        content="Test content 2",
        community_distance=200.0,
        runner_distance=10.0,
        run_count=2,
        created_at=datetime.now(),
        week_number=11,
        year=2024
    )
    db_session.add(post2)
    
    with pytest.raises(Exception) as excinfo:
        db_session.commit()
    
    # Rollback to clean state
    db_session.rollback()