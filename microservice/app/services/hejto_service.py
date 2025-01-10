import hashlib
import requests
from datetime import datetime
from typing import List, Optional
import logging
from sqlalchemy.orm import Session
from app.models import RunningPost, WeeklyAggregate
import re
import unicodedata

logger = logging.getLogger(__name__)

class HejtoService:
    def __init__(self, db: Session):
        self.db = db
        self.base_url = "https://api.hejto.pl"
        self.min_date = datetime(2022, 1, 1)

    def _calculate_content_hash(self, content: str) -> str:
        """Generate a unique hash for the post content."""
        return hashlib.md5(content.encode()).hexdigest()

    def _extract_distance(self, content: str) -> float:
        """Extract distance from post content."""
        content = unicodedata.normalize("NFKD", content)
        # Find numbers in format: XX,XX or XX.XX
        # Find numbers in format: XX,XX or XX.XX
        pattern = r'\b\d+(?:[.,]\d+)?\b'
        matches = re.findall(pattern, content)
        
        # Skip if no matches found
        if not matches:
            return 0.0
            
        # Look for operation patterns like "5 + 3 + 2 = 10"
        if '=' in content:
            # Split on equals and take left side
            operation = content.split('=')[0]
            # Find all numbers in the operation
            operation_matches = re.findall(pattern, operation)
            if len(operation_matches) > 1:
                # Skip first number and sum the rest
                total = sum(float(m.replace(',','.')) for m in operation_matches[1:])
                return total
                
        # If no operation found, use first number as before
        distance_str = matches[0].replace(',', '.')
        return float(distance_str)

    async def fetch_posts(self, page: int = 1, limit: int = 50) -> List[dict]:
        """Fetch posts from Hejto API."""
        try:
            params = {
                "community": "sztafeta",
                "page": page,
                "limit": limit
            }
            response = requests.get(f"{self.base_url}/posts", params=params)
            response.raise_for_status()
            return response.json()["_embedded"]["items"]
        except Exception as e:
            logger.error(f"Error fetching posts: {str(e)}")
            return []

    async def process_posts(self):
        """Process and store posts."""
        page = 1
        while True:
            posts = await self.fetch_posts(page=page)
            if not posts:
                break

            for post in posts:
                created_at = datetime.fromisoformat(post["created_at"].replace('Z', '+00:00'))
                if created_at < self.min_date:
                    return

                content = post["content_plain"]
                content_hash = self._calculate_content_hash(content)

                # Skip if already processed
                if self.db.query(RunningPost).filter_by(content_hash=content_hash).first():
                    continue

                distance = self._extract_distance(content)
                if distance <= 0:
                    continue

                running_post = RunningPost(
                    content_hash=content_hash,
                    post_id=post["id"],
                    author=post["author"]["username"],
                    content=content,
                    distance=distance,
                    created_at=created_at,
                    week_number=created_at.isocalendar()[1],
                    year=created_at.year
                )
                self.db.add(running_post)
                
            self.db.commit()
            page += 1

    def aggregate_weekly_data(self):
        """Aggregate running data by week."""
        # Clear existing aggregates
        self.db.query(WeeklyAggregate).delete()

        # Group by author, week, and year
        posts = self.db.query(RunningPost).all()
        aggregates = {}
        
        for post in posts:
            key = (post.author, post.week_number, post.year)
            if key not in aggregates:
                aggregates[key] = {"total_distance": 0, "post_count": 0}
            
            aggregates[key]["total_distance"] += post.distance
            aggregates[key]["post_count"] += 1

        # Store aggregates
        for (author, week, year), data in aggregates.items():
            aggregate = WeeklyAggregate(
                author=author,
                week_number=week,
                year=year,
                total_distance=data["total_distance"],
                post_count=data["post_count"]
            )
            self.db.add(aggregate)
        
        self.db.commit() 