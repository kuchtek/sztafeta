import requests
import hashlib
import re
import unicodedata
from datetime import datetime, timedelta
from sqlalchemy import create_engine, Column, String, Float, DateTime, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import func
import os
from dotenv import load_dotenv
import logging
from typing import List, Optional
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Database configuration
DB_TYPE = os.getenv('DB_TYPE', 'sqlite')  # 'sqlite' or 'postgresql'
if DB_TYPE == 'postgresql':
    DB_URL = os.getenv('DATABASE_URL')
else:
    DB_URL = 'sqlite:///hejto_posts.db'

# Create SQLAlchemy base
Base = declarative_base()

class Post(Base):
    __tablename__ = 'posts'
    
    id = Column(String, primary_key=True)  # Hash of content
    author = Column(String, nullable=False, index=True)
    content = Column(String, nullable=False)
    community_distance = Column(Float)  # Total community distance
    runner_distance = Column(Float)  # Sum of individual runs
    run_count = Column(Integer)  # Number of individual runs
    created_at = Column(DateTime, nullable=False)
    week_number = Column(Integer, nullable=False)
    year = Column(Integer, nullable=False)
    processed_at = Column(DateTime, server_default=func.now())

class HejtoDataCollector:
    def __init__(self):
        self.engine = create_engine(DB_URL)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)
        
    def _generate_post_id(self, content: str, author: str, created_at: str) -> str:
        """Generate unique hash for a post based on its content and metadata."""
        content_hash = f"{content}{author}{created_at}".encode('utf-8')
        return hashlib.md5(content_hash).hexdigest()

    def _extract_distances(self, content: str) -> tuple[float, float, int]:
        """
        Extract distances from post content.
        Returns (community_distance, runner_distance, run_count)
        """
        content = unicodedata.normalize("NFKD", content)
        
        # Get first line and log it for debugging
        first_line = content.splitlines()[0] if content else ""
        logger.debug(f"Processing line: {first_line}")
        
        # Skip if no equals sign or plus sign (not a valid format)
        if '=' not in first_line or '+' not in first_line:
            logger.debug("Skipping - no equals or plus sign")
            return 0.0, 0.0, 0
        
        try:
            # Split on equals to get the calculation part
            calculation_part = first_line.split('=')[0].strip()
            
            # Split on plus to get individual components
            components = [x.strip() for x in calculation_part.split('+')]
            
            if len(components) < 2:  # Need at least community total and one run
                logger.debug("Skipping - not enough components")
                return 0.0, 0.0, 0
            
            # First component is community total
            community_str = components[0].replace(' ', '').replace(',', '.')
            try:
                community_distance = float(community_str)
            except ValueError:
                logger.warning(f"Invalid community total: {community_str}")
                return 0.0, 0.0, 0
            
            # Rest are individual runs
            individual_runs = []
            for run_str in components[1:]:
                clean_run = run_str.strip().replace(' ', '').replace(',', '.')
                try:
                    distance = float(clean_run)
                    # Sanity check for individual run
                    if 0 < distance <= 100:  # Individual runs typically under 100km
                        individual_runs.append(distance)
                    else:
                        logger.warning(f"Suspicious individual run distance: {distance}km")
                except ValueError:
                    continue
            
            runner_distance = sum(individual_runs)
            run_count = len(individual_runs)
            
            # Log the results for debugging
            logger.debug(f"Extracted - Community: {community_distance}, Runner: {runner_distance}, Runs: {run_count}")
            
            # Final sanity checks
            if runner_distance > 200:  # Unlikely to have more than 200km in one post
                logger.warning(f"Suspiciously high total distance: {runner_distance}km in post")
                return 0.0, 0.0, 0
            
            if community_distance > 100000:  # Sanity check for community total
                logger.warning(f"Suspiciously high community distance: {community_distance}km")
                return 0.0, 0.0, 0
            
            return community_distance, runner_distance, run_count
            
        except Exception as e:
            logger.warning(f"Error processing distances: {e}, Content: {first_line}")
            return 0.0, 0.0, 0

    def fetch_posts(self, start_date: datetime, community: str = "Sztafeta") -> List[dict]:
        """Fetch posts from Hejto API with pagination."""
        url = 'https://api.hejto.pl/posts'
        all_posts = []
        page = 1
        
        while True:
            params = {
                'community': community,
                'limit': 50,
                'page': page,
                'period': 'all'
            }
            
            try:
                response = requests.get(url, params=params)
                response.raise_for_status()

                logger.info(f"Fetched page {page}")
                
                data = response.json()
                posts = data["_embedded"]["items"]
                
                if not posts:
                    break
                
                # Filter posts by date
                filtered_posts = [
                    post for post in posts
                    if datetime.fromisoformat(post["created_at"].replace('Z', '+00:00')) >= start_date
                ]
                logger.info(f"Max date: {max(datetime.fromisoformat(post['created_at'].replace('Z', '+00:00')) for post in filtered_posts)}")
                all_posts.extend(filtered_posts)
                
                # Check if we've reached posts older than start_date
                if len(filtered_posts) < len(posts):
                    break
                
                page += 1
                time.sleep(1)  # Rate limiting
                
            except requests.exceptions.RequestException as e:
                logger.error(f"Error fetching posts: {e}")
                break
        
        return all_posts

    def process_posts(self, posts: List[dict]) -> None:
        """Process and store posts in the database."""
        session = self.Session()
        processed_count = 0
        skipped_count = 0
        
        try:
            # First, clear existing data
            session.query(Post).delete()
            session.commit()
            
            for post in posts:
                created_at = datetime.fromisoformat(post["created_at"].replace('Z', '+00:00'))
                content = post["content_plain"]
                author = post["author"]["username"]
                
                post_id = self._generate_post_id(content, author, post["created_at"])
                community_distance, runner_distance, run_count = self._extract_distances(content)
                
                if runner_distance <= 0 or run_count == 0:
                    skipped_count += 1
                    continue
                
                # Calculate week number and year
                week_number = created_at.isocalendar()[1]
                year = created_at.year
                
                new_post = Post(
                    id=post_id,
                    author=author,
                    content=content,
                    community_distance=community_distance,
                    runner_distance=runner_distance,
                    run_count=run_count,
                    created_at=created_at,
                    week_number=week_number,
                    year=year
                )
                session.add(new_post)
                processed_count += 1
                
                # Commit every 100 posts
                if processed_count % 100 == 0:
                    session.commit()
            
            session.commit()
            logger.info(f"Processed {processed_count} posts, skipped {skipped_count} posts")
            
        except Exception as e:
            logger.error(f"Error processing posts: {e}")
            session.rollback()
            raise
        finally:
            session.close()

    def get_weekly_stats(self) -> List[dict]:
        """Get accumulated weekly statistics for all users."""
        session = self.Session()
        try:
            results = session.query(
                Post.author,
                Post.year,
                Post.week_number,
                func.sum(Post.runner_distance).label('total_distance'),
                func.sum(Post.run_count).label('total_runs'),
                func.count(Post.id).label('post_count')
            ).group_by(
                Post.author,
                Post.year,
                Post.week_number
            ).all()
            
            return [
                {
                    'author': r.author,
                    'year': r.year,
                    'week': r.week_number,
                    'total_distance': round(r.total_distance, 2),
                    'total_runs': r.total_runs,
                    'posts': r.post_count
                }
                for r in results
            ]
        finally:
            session.close()

    def get_overall_stats(self) -> List[dict]:
        """Get total distance and runs for each runner."""
        session = self.Session()
        try:
            results = session.query(
                Post.author,
                func.sum(Post.runner_distance).label('total_distance'),
                func.sum(Post.run_count).label('total_runs'),
                func.count(Post.id).label('post_count')
            ).group_by(
                Post.author
            ).order_by(func.sum(Post.runner_distance).desc()).all()
            
            return [
                {
                    'author': r.author,
                    'total_distance': round(r.total_distance, 2),
                    'total_runs': r.total_runs,
                    'posts': r.post_count
                }
                for r in results
            ]
        except Exception as e:
            logger.error(f"Error getting overall stats: {e}")
            return []
        finally:
            session.close()

    def get_current_week_stats(self) -> List[dict]:
        """Get stats for current week."""
        current_date = datetime.now()
        current_week = current_date.isocalendar()[1]
        current_year = current_date.year
        
        session = self.Session()
        try:
            results = session.query(
                Post.author,
                func.sum(Post.runner_distance).label('total_distance'),
                func.sum(Post.run_count).label('total_runs')
            ).filter(
                Post.week_number == current_week,
                Post.year == current_year
            ).group_by(
                Post.author
            ).order_by(func.sum(Post.runner_distance).desc()).all()
            
            return [
                {
                    'author': r.author,
                    'total_distance': round(r.total_distance, 2),
                    'total_runs': r.total_runs
                }
                for r in results
            ]
        except Exception as e:
            logger.error(f"Error getting current week stats: {e}")
            return []
        finally:
            session.close()

    def get_current_month_stats(self) -> List[dict]:
        """Get stats for current month."""
        current_date = datetime.now()
        session = self.Session()
        try:
            results = session.query(
                Post.author,
                func.sum(Post.runner_distance).label('total_distance'),
                func.sum(Post.run_count).label('total_runs')
            ).filter(
                func.extract('month', Post.created_at) == current_date.month,
                func.extract('year', Post.created_at) == current_date.year
            ).group_by(
                Post.author
            ).order_by(func.sum(Post.runner_distance).desc()).all()
            
            return [
                {
                    'author': r.author,
                    'total_distance': round(r.total_distance, 2),
                    'total_runs': r.total_runs
                }
                for r in results
            ]
        except Exception as e:
            logger.error(f"Error getting current month stats: {e}")
            return []
        finally:
            session.close()

    def get_monthly_community_stats(self) -> List[dict]:
        """Get total community distance per month."""
        session = self.Session()
        try:
            # Use date_trunc to properly group by month
            results = session.query(
                func.strftime('%Y', Post.created_at).label('year'),
                func.strftime('%m', Post.created_at).label('month'),
                func.sum(Post.runner_distance).label('total_distance'),
                func.sum(Post.run_count).label('total_runs'),
                func.count(Post.id).label('post_count')
            ).group_by(
                func.strftime('%Y', Post.created_at),
                func.strftime('%m', Post.created_at)
            ).order_by(
                func.strftime('%Y', Post.created_at).asc(),
                func.strftime('%m', Post.created_at).asc()
            ).all()
            
            monthly_stats = []
            for r in results:
                # Skip months with suspiciously high values
                total_distance = round(r.total_distance, 2)
                if total_distance > 2000:  # Sanity check - unlikely to have more than 2000km in a month
                    continue
                    
                monthly_stats.append({
                    'year': int(r.year),
                    'month': int(r.month),
                    'total_distance': total_distance,
                    'total_runs': r.total_runs,
                    'post_count': r.post_count,
                    'label': f"{r.year}-{int(r.month):02d}"  # Ensure proper month formatting
                })
            
            return monthly_stats
        finally:
            session.close()

def main():
    collector = HejtoDataCollector()
    start_date = datetime(2023, 11, 6, tzinfo=datetime.now().astimezone().tzinfo)
    
    # Fetch and process posts
    posts = collector.fetch_posts(start_date)
    collector.process_posts(posts)
    
    # Get statistics
    stats = collector.get_weekly_stats()
    logger.info(f"Processed {len(stats)} weekly records")

if __name__ == "__main__":
    main() 