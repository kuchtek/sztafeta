# tests/conftest.py
import os
import sys
import pytest
import tempfile
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Add the parent directory to PYTHONPATH 
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app as flask_app
from microservice.data_collector import Base, HejtoDataCollector, COMMUNITY_MODELS

@pytest.fixture(scope="function")
def app():
    """Flask application fixture with test configuration"""
    # Set testing configuration
    flask_app.config.update({
        "TESTING": True,
        "SECRET_KEY": "test_secret_key",
    })
    
    # Configure app for testing
    yield flask_app

@pytest.fixture(scope="function")
def client(app):
    """Test client for the Flask application"""
    return app.test_client()

@pytest.fixture(scope="function")
def test_db():
    """Create an isolated test database for each test function"""
    # Use in-memory SQLite database for faster tests without file locking issues
    db_url = 'sqlite:///:memory:'
    
    # Create the engine and tables
    engine = create_engine(db_url)
    Base.metadata.create_all(engine)
    
    # Create a session factory
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    
    # Return the session factory and engine
    yield TestingSessionLocal, engine
    
    # Clean up - dispose the engine to close all connections
    engine.dispose()

@pytest.fixture(scope="function")
def db_session(test_db):
    """Create a new isolated database session for testing"""
    TestingSessionLocal, _ = test_db
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

@pytest.fixture(scope="function")
def data_collector(test_db):
    """Create a HejtoDataCollector instance with a test database"""
    TestingSessionLocal, engine = test_db
    
    # Create a clean collector instance with test database
    collector = HejtoDataCollector()
    collector.engine = engine
    collector.Session = TestingSessionLocal
    
    return collector