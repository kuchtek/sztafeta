import schedule
import time
import requests
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def fetch_and_aggregate():
    """Fetch posts and aggregate data."""
    base_url = "http://localhost:8000"  # Adjust as needed
    
    try:
        # Fetch posts
        response = requests.post(f"{base_url}/fetch-posts")
        response.raise_for_status()
        logger.info("Posts fetched successfully")

        # Aggregate weekly data
        response = requests.post(f"{base_url}/aggregate-weekly")
        response.raise_for_status()
        logger.info("Weekly aggregation completed")
    except Exception as e:
        logger.error(f"Error in scheduled task: {str(e)}")

def main():
    # Schedule the task to run daily at midnight
    schedule.every().day.at("00:00").do(fetch_and_aggregate)
    
    # Run immediately on startup
    fetch_and_aggregate()
    
    while True:
        schedule.run_pending()
        time.sleep(60)

if __name__ == "__main__":
    main() 