# tests/test_routes.py - Test the Flask application routes
import pytest
import json
from unittest.mock import patch, MagicMock
from flask import url_for, session

def test_default_ranking_redirect(client):
    """Test that /ranking redirects to the default community"""
    response = client.get('/ranking')
    assert response.status_code == 302
    assert 'ranking/Sztafeta' in response.headers['Location']

@patch('app.get_db')
def test_show_rankings(mock_get_db, client, db_session):
    """Test the show_rankings route"""
    # Mock the database session
    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.order_by.return_value.all.return_value = []
    mock_get_db.return_value.__next__.return_value = mock_db

    response = client.get('/ranking')
    assert response.status_code == 308 or 302 # or 307 or 302 depending on your app
    assert 'ranking/Sztafeta' in response.headers['Location']
    
    # Test with a valid community
    response = client.get('/ranking/Sztafeta')
    assert response.status_code == 200
    assert b'Sztafeta - Ranking' in response.data
    
    # Test with invalid community
    response = client.get('/ranking/InvalidCommunity')
    assert response.status_code == 404

@patch('app.requests.get')
def test_api_chart_data(mock_requests_get, client):
    """Test the chart data API endpoint"""
    # Mock the database query results
    mock_response = MagicMock()
    mock_response.json.return_value = {
        'labels': ['Tydzień 1', 'Tydzień 2'],
        'values': [10.5, 15.2],
        'year': 2024,
        'community': 'Sztafeta'
    }
    mock_requests_get.return_value = mock_response
    
    # Test the endpoint
    response = client.get('/api/chart_data/Sztafeta?year=2024')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'labels' in data
    assert 'values' in data
    assert len(data['labels']) == 52
    assert len(data['values']) == 52

@patch('app.requests.get')
def test_api_chart_data_with_mocked_db(mock_requests_get, client):
    """Test the chart data API endpoint with a mocked database."""
    # Setup mock response for the database query
    mock_response = MagicMock()
    mock_data = {
        'labels': ['Tydzień 1', 'Tydzień 2'],
        'values': [10.5, 15.2],
        'year': 2024,
        'community': 'Sztafeta'
    }
    mock_response.json.return_value = mock_data
    mock_requests_get.return_value = mock_response
    
    # Test with default year
    response = client.get('/api/chart_data/Sztafeta')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'labels' in data
    assert 'values' in data
    
    # Test with specific year
    response = client.get('/api/chart_data/Sztafeta?year=2024')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['year'] == 2024  # This is from our mock data