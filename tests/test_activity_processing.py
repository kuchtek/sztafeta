# tests/test_activity_processing.py - New file
import pytest
from unittest.mock import patch, MagicMock
from io import BytesIO

@patch('app.get_last_distance')
@patch('app.upload_image')
@patch('app.create_post')
def test_process_activities(mock_create_post, mock_upload, mock_last_distance, client):
    """Test the process_activities route which creates posts."""
    # Setup mocks
    mock_last_distance.return_value = "12345.6"
    mock_upload.return_value = "test_image_uuid"
    
    mock_response = MagicMock()
    mock_response.status_code = 201
    mock_create_post.return_value = mock_response
    
    # Create test data
    data = {
        'activity_type': 'sztafeta',
        'selected_activities': ['5.4', '3.2'],
        'notes': 'Test run notes'
    }
    
    # Add a test image
    test_image = (BytesIO(b'test image content'), 'test.jpg')
    data['files'] = (test_image,)
    
    # Test the route
    with client.session_transaction() as sess:
        sess['access_token'] = 'test_token'
    
    response = client.post('/process_activities', data=data, content_type='multipart/form-data')
    
    # Check the response
    assert response.status_code == 302
    assert 'hejto.pl/spolecznosc/Sztafeta' in response.headers['Location']
    
    # Verify the mock calls
    mock_last_distance.assert_called_once_with(community='Sztafeta')
    mock_create_post.assert_called_once()
    
    # Check that the content has the correct format
    call_args = mock_create_post.call_args[1]
    content = call_args['content']
    assert '12 345,6 + 5,4 + 3,2 = 12 354,2' in content
    assert 'Test run notes' in content
    assert '#sztafeta' in content