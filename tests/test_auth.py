# tests/test_auth.py - New file
import pytest
from unittest.mock import patch, MagicMock
from flask import session

@patch('app.requests.post')
def test_hejto_auth_flow(mock_post, client):
    """Test the Hejto authentication flow."""
    # Mock the token response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        'access_token': 'test_access_token',
        'refresh_token': 'test_refresh_token'
    }
    mock_post.return_value = mock_response
    
    # Test initial redirect to Hejto auth
    response = client.get('/')
    assert response.status_code == 302
    assert 'auth.hejto.pl/authorize' in response.headers['Location']
    
    # Test callback with code
    with client.session_transaction() as sess:
        sess.clear()
    
    response = client.get('/callback?code=test_auth_code')
    assert response.status_code == 200
    
    with client.session_transaction() as sess:
        assert 'access_token' in sess
        assert sess['access_token'] == 'test_access_token'
        assert 'refresh_token' in sess
        assert sess['refresh_token'] == 'test_refresh_token'

@patch('app.requests.post')
def test_strava_auth_flow(mock_post, client):
    """Test the Strava authentication flow."""
    # Mock the token response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        'access_token': 'test_strava_token'
    }
    mock_post.return_value = mock_response
    
    # Test redirect to Strava auth
    response = client.get('/strava_login')
    assert response.status_code == 302
    assert 'strava.com/oauth/authorize' in response.headers['Location']
    
    # Test callback with code
    with client.session_transaction() as sess:
        sess.clear()
    
    response = client.get('/strava_callback?code=test_strava_code')
    assert response.status_code == 302  # Redirects to /athlete
    
    with client.session_transaction() as sess:
        assert 'strava_access_token' in sess
        assert sess['strava_access_token'] == 'test_strava_token'