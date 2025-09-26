import requests
import hashlib
import re
import unicodedata
from datetime import datetime, timedelta, timezone
from sqlalchemy import create_engine, Column, String, Float, DateTime, Integer, func, extract, MetaData, desc
from sqlalchemy.orm import declarative_base
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
    DB_URL = 'sqlite:///data/hejto_posts.db'

# Create SQLAlchemy base
Base = declarative_base()

# --- Base Model Structure (for reuse) ---
# We define the columns once and reuse them via mixins or direct definition
class PostColumns:
    id = Column(String, primary_key=True)  # Hash of content
    author = Column(String, nullable=False, index=True)
    content = Column(String, nullable=False)
    community_distance = Column(Float)  # Total community distance
    runner_distance = Column(Float)  # Sum of individual runs
    run_count = Column(Integer)  # Number of individual runs
    created_at = Column(DateTime, nullable=False, index=True)
    week_number = Column(Integer, nullable=False, index=True)
    year = Column(Integer, nullable=False, index=True)
    processed_at = Column(DateTime, server_default=func.now())

class WeeklySummaryColumns:
    year = Column(Integer, primary_key=True)
    week_number = Column(Integer, primary_key=True)
    total_distance = Column(Float, default=0.0)

class RunnerMonthlyStatsColumns:
    year = Column(Integer, primary_key=True)
    month = Column(Integer, primary_key=True)
    author = Column(String, primary_key=True, index=True)
    total_distance = Column(Float, default=0.0)
    total_runs = Column(Integer, default=0)
    average_distance_per_run = Column(Float, default=0.0)

class RunnerYearlyStatsColumns:
    year = Column(Integer, primary_key=True)
    author = Column(String, primary_key=True, index=True)
    total_distance = Column(Float, default=0.0)
    total_runs = Column(Integer, default=0)
    average_distance_per_run = Column(Float, default=0.0)

# --- Define Models for EACH Community ---

# == Sztafeta Models ==
class SztafetaPost(Base, PostColumns): __tablename__ = 'posts'
class SztafetaWeeklySummary(Base, WeeklySummaryColumns): __tablename__ = 'weekly_summary'
class SztafetaRunnerMonthlyStats(Base, RunnerMonthlyStatsColumns): __tablename__ = 'runner_monthly_stats'
class SztafetaRunnerYearlyStats(Base, RunnerYearlyStatsColumns): __tablename__ = 'runner_yearly_stats'

# == RowerowyRownik Models ==
class RowerowyRownikPost(Base, PostColumns): __tablename__ = 'rowerowyrownik_posts'
class RowerowyRownikWeeklySummary(Base, WeeklySummaryColumns): __tablename__ = 'rowerowyrownik_weekly_summary'
class RowerowyRownikRunnerMonthlyStats(Base, RunnerMonthlyStatsColumns): __tablename__ = 'rowerowyrownik_runner_monthly_stats'
class RowerowyRownikRunnerYearlyStats(Base, RunnerYearlyStatsColumns): __tablename__ = 'rowerowyrownik_runner_yearly_stats'

# == KsiezycowySpacer Models ==
class KsiezycowySpacerPost(Base, PostColumns): __tablename__ = 'ksiezycowyspacer_posts'
class KsiezycowySpacerWeeklySummary(Base, WeeklySummaryColumns): __tablename__ = 'ksiezycowyspacer_weekly_summary'
class KsiezycowySpacerRunnerMonthlyStats(Base, RunnerMonthlyStatsColumns): __tablename__ = 'ksiezycowyspacer_runner_monthly_stats'
class KsiezycowySpacerRunnerYearlyStats(Base, RunnerYearlyStatsColumns): __tablename__ = 'ksiezycowyspacer_runner_yearly_stats'

# == RokMedytacji Models ==
class RokMedytacjiPost(Base, PostColumns): __tablename__ = 'rokmedytacji_posts'
class RokMedytacjiWeeklySummary(Base, WeeklySummaryColumns): __tablename__ = 'rokmedytacji_weekly_summary'
class RokMedytacjiRunnerMonthlyStats(Base, RunnerMonthlyStatsColumns): __tablename__ = 'rokmedytacji_runner_monthly_stats'
class RokMedytacjiRunnerYearlyStats(Base, RunnerYearlyStatsColumns): __tablename__ = 'rokmedytacji_runner_yearly_stats'

# == PompujWPoprzekZiemi Models ==
class PompujWPoprzekZiemiPost(Base, PostColumns): __tablename__ = 'pompujwpoprzekziemi_posts'
class PompujWPoprzekZiemiWeeklySummary(Base, WeeklySummaryColumns): __tablename__ = 'pompujwpoprzekziemi_weekly_summary'
class PompujWPoprzekZiemiRunnerMonthlyStats(Base, RunnerMonthlyStatsColumns): __tablename__ = 'pompujwpoprzekziemi_runner_monthly_stats'
class PompujWPoprzekZiemiRunnerYearlyStats(Base, RunnerYearlyStatsColumns): __tablename__ = 'pompujwpoprzekziemi_runner_yearly_stats'

# Add other communities here if needed following the pattern

# --- Model Mapping ---
COMMUNITY_MODELS = {
    'Sztafeta': {
        'Post': SztafetaPost,
        'WeeklySummary': SztafetaWeeklySummary,
        'RunnerMonthlyStats': SztafetaRunnerMonthlyStats,
        'RunnerYearlyStats': SztafetaRunnerYearlyStats
    },
    'rowerowy-rownik': {
        'Post': RowerowyRownikPost,
        'WeeklySummary': RowerowyRownikWeeklySummary,
        'RunnerMonthlyStats': RowerowyRownikRunnerMonthlyStats,
        'RunnerYearlyStats': RowerowyRownikRunnerYearlyStats
    },
    'ksiezycowy-spacer': {
        'Post': KsiezycowySpacerPost,
        'WeeklySummary': KsiezycowySpacerWeeklySummary,
        'RunnerMonthlyStats': KsiezycowySpacerRunnerMonthlyStats,
        'RunnerYearlyStats': KsiezycowySpacerRunnerYearlyStats
    },
    'rok-medytacji': {
        'Post': RokMedytacjiPost,
        'WeeklySummary': RokMedytacjiWeeklySummary,
        'RunnerMonthlyStats': RokMedytacjiRunnerMonthlyStats,
        'RunnerYearlyStats': RokMedytacjiRunnerYearlyStats
    },
    'pompuj': {
        'Post': PompujWPoprzekZiemiPost,
        'WeeklySummary': PompujWPoprzekZiemiWeeklySummary,
        'RunnerMonthlyStats': PompujWPoprzekZiemiRunnerMonthlyStats,
        'RunnerYearlyStats': PompujWPoprzekZiemiRunnerYearlyStats
    }
}

# List of communities the collector should process
COMMUNITIES_TO_PROCESS = list(COMMUNITY_MODELS.keys())

class HejtoDataCollector:
    def __init__(self):
        self.engine = create_engine(DB_URL)
        # Create all defined tables
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)
        
    def _get_models_for_community(self, community: str) -> dict:
        """Get the model classes for a given community name."""
        models = COMMUNITY_MODELS.get(community)
        if not models:
            raise ValueError(f"Models not defined for community: {community}")
        return models

    def _get_latest_post_timestamp(self, community: str) -> Optional[datetime]:
        """Query the database for the timestamp of the most recent post for a specific community's table."""
        models = self._get_models_for_community(community)
        PostModel = models['Post']
        session = self.Session()
        try:
            latest_post = session.query(PostModel).order_by(desc(PostModel.created_at)).first()
            if latest_post:
                logger.info(f"Latest post in DB for '{community}' ({PostModel.__tablename__}) created at: {latest_post.created_at}")
                return latest_post.created_at.replace(tzinfo=timezone.utc)
            else:
                logger.info(f"No posts found in DB for '{community}' ({PostModel.__tablename__}). Will fetch all available.")
                return None
        except Exception as e:
            logger.error(f"Error getting latest post timestamp for '{community}': {e}")
            return None
        finally:
            session.close()

    def _generate_post_id(self, content: str, author: str, created_at: str) -> str:
        """Generate unique hash for a post based on its content and metadata."""
        content_hash = f"{content}{author}{created_at}".encode('utf-8')
        return hashlib.md5(content_hash).hexdigest()

    def _extract_distances(self, content: str, community: str) -> tuple[float, float, int]:
        """
        Extract distances from post content, handling different community formats.
        Returns (community_distance, runner_distance, run_count)
        community_distance for subtractive communities is the starting value.
        runner_distance is the sum of positive distances added/subtracted.
        """
        content = unicodedata.normalize("NFKD", content)
        first_line = content.splitlines()[0] if content else ""
        logger.debug(f"[{community}] Processing line: {first_line}")
        
        # Determine operator based on community
        # Add other subtractive communities here if needed
        is_subtractive = community in ['ksiezycowy-spacer', 'rok-medytacji', 'pompuj'] 
        required_operator = '-' if is_subtractive else '+'
        
        # Check for equals sign and the required operator
        if '=' not in first_line or required_operator not in first_line:
            logger.debug(f"[{community}] Skipping - no equals or required operator ('{required_operator}') found")
            return 0.0, 0.0, 0
        
        try:
            calculation_part = first_line.split('=')[0].strip()
            
            # Split based on the determined operator
            components = [x.strip() for x in calculation_part.split(required_operator)]
            
            if len(components) < 2: # Need at least initial total and one operation
                logger.debug(f"[{community}] Skipping - not enough components after splitting by '{required_operator}'")
                return 0.0, 0.0, 0
            
            # First component is the initial total (community distance)
            community_str = components[0].replace(' ', '').replace(',', '.')
            try:
                community_distance = round(float(community_str), 4)
            except ValueError:
                logger.warning(f"[{community}] Invalid initial total: {community_str}")
                return 0.0, 0.0, 0
            
            # Rest are individual distances operated on
            individual_distances = []
            for dist_str in components[1:]:
                clean_dist = dist_str.strip().replace(' ', '').replace(',', '.')
                try:
                    # Treat distance as positive value, regardless of +/- operator
                    distance = round(float(clean_dist), 2) 
                    # Basic sanity check (adjust range if needed for different communities)
                    if distance > 0:
                        individual_distances.append(distance)
                    else:
                        logger.warning(f"[{community}] Skipping non-positive individual value: {distance}")

                except ValueError:
                    logger.warning(f"[{community}] Invalid distance value: {clean_dist}")
                    continue
            
            # runner_distance is the sum of the individual distances in the post
            runner_distance = sum(individual_distances)
            run_count = len(individual_distances)
            
            logger.debug(f"[{community}] Extracted - Initial: {community_distance}, Runner Sum: {runner_distance}, Count: {run_count}")
            
            return community_distance, round(runner_distance, 2), run_count
            
        except Exception as e:
            logger.warning(f"[{community}] Error processing distances: {e}, Content: {first_line}")
            return 0.0, 0.0, 0

    def fetch_posts(self, community: str) -> None:
        """Fetch posts for a specific community incrementally or fully, handling API repetitions."""
        latest_stored_timestamp = self._get_latest_post_timestamp(community)
        url = 'https://api.hejto.pl/posts'
        new_posts_to_process = []
        page = 1
        keep_fetching = True
        is_initial_fetch = latest_stored_timestamp is None
        previous_page_post_ids = set() # Store IDs from the previous page to detect repetition

        if is_initial_fetch:
            logger.info(f"No latest timestamp found for '{community}'. Performing initial fetch for all available posts.")
        else:
            logger.info(f"Starting incremental fetch for '{community}'. Looking for posts newer than: {latest_stored_timestamp}")

        while keep_fetching:
            # --- Set API Parameters ---
            params = {
                'limit': 50,
                'page': page,
                'period': 'all'
            }
            # Handle tag-based vs community-based searches
            if community == 'rok-medytacji':
                params['tags[]'] = 'rokmedytacji'
            elif community == 'pompuj':
                params['tags[]'] = 'pompujwpoprzekziemi'
            elif community == 'ksiezycowy-spacer':
                 params['tags[]'] = 'ksiezycowyspacer' # Assuming tag search now
            # elif community == 'sztafeta': # Example if sztafeta used a tag
            #     params['tags[]'] = 'sztafeta'
            else: # Default to community parameter if no specific tag logic
                params['community'] = community

            oldest_ts_on_this_page = None
            found_new_on_page = False # Only relevant for incremental fetch

            try:
                # --- Fetch Data ---
                logger.debug(f"Fetching page {page} with params: {params}")
                response = requests.get(url, params=params)
                response.raise_for_status()
                logger.info(f"Fetched page {page} successfully for '{community}'")

                data = response.json()
                posts_on_page = data.get("_embedded", {}).get("items", [])
                page_post_count = len(posts_on_page)
                logger.debug(f"Found {page_post_count} posts on page {page}.")

                if not posts_on_page:
                    logger.info("Stopping fetch: No more posts found on API (empty page received).")
                    keep_fetching = False
                    break # Exit while loop

                # --- Repetition Check (Initial Fetch Only, after page 1) ---
                current_page_post_ids = set()
                try:
                    # Generate IDs for comparison - must handle potential missing keys
                    current_page_post_ids = {
                        self._generate_post_id(p["content_plain"], p["author"]["username"], p["created_at"])
                        for p in posts_on_page
                        if "content_plain" in p and "author" in p and "username" in p["author"] and "created_at" in p
                    }
                    if len(current_page_post_ids) != page_post_count:
                         logger.warning(f"Page {page}: Mismatch between post count ({page_post_count}) and successfully generated IDs ({len(current_page_post_ids)}). Some posts might be missing required fields.")

                except KeyError as e:
                     logger.error(f"KeyError generating post IDs for repetition check on page {page}: {e}. Cannot reliably check for repetition.")
                     # Decide how to handle: continue cautiously or stop? Stopping might be safer.
                     # keep_fetching = False # Option: Stop if we can't check
                     # break

                if is_initial_fetch and page > 1:
                    if not current_page_post_ids: # If we couldn't generate any IDs for the current page
                         logger.warning(f"Initial fetch page {page}: Could not generate any post IDs to check for repetition. Stopping fetch as a precaution.")
                         keep_fetching = False
                         break
                    if current_page_post_ids == previous_page_post_ids:
                        logger.warning(f"Stopping initial fetch: Page {page} appears to be a repeat of page {page-1}. Assuming end of unique results.")
                        keep_fetching = False
                        break # Exit while loop

                # --- Process Posts on Page ---
                logger.debug(f"--- Processing Page {page} for {community} ---")
                for post in posts_on_page:
                    # (Error handling for timestamp/slug remains as before)
                    try:
                        post_created_at = datetime.fromisoformat(post["created_at"].replace('Z', '+00:00'))
                        post_slug = post.get('slug', '[no slug]')
                        logger.debug(f"Checking post '{post_slug}' ({post_created_at})")
                    except (ValueError, KeyError) as e:
                        logger.warning(f"Could not parse timestamp for post {post.get('slug')}: {e}. Skipping.")
                        continue

                    # Update oldest timestamp seen on this specific page
                    if oldest_ts_on_this_page is None or post_created_at < oldest_ts_on_this_page:
                        oldest_ts_on_this_page = post_created_at

                    # --- Add/Stop Logic ---
                    if is_initial_fetch:
                        # Initial Fetch: Add ALL posts from the page unconditionally
                        new_posts_to_process.append(post)
                        logger.debug(f"  -> Initial Fetch: Adding post '{post_slug}'.")
                    else:
                        # Incremental Fetch: Check timestamp
                        if post_created_at > latest_stored_timestamp:
                            new_posts_to_process.append(post)
                            found_new_on_page = True # Mark we found something new
                            logger.debug(f"  -> Incremental Fetch: Adding post '{post_slug}' (newer than {latest_stored_timestamp}).")
                        else:
                            # Post is NOT newer. Stop processing this page and stop fetching more pages.
                            logger.info(f"Incremental fetch stop condition met: Post '{post_slug}' ({post_created_at}) is not newer than latest stored ({latest_stored_timestamp}). Stopping fetch.")
                            keep_fetching = False
                            break # Exit the inner 'for post in posts_on_page' loop

                # --- End of loop for posts on page ---
                logger.debug(f"--- Finished Page {page}. Oldest on page: {oldest_ts_on_this_page}. Found new (incremental): {found_new_on_page} ---")

                # --- Decide if Next Page Needed ---
                if keep_fetching: # Only evaluate if the inner loop/repetition check didn't already set keep_fetching to False
                    limit = params['limit']
                    if is_initial_fetch:
                        # Initial Fetch: Stop ONLY if the page wasn't full (Checked BEFORE repetition check now)
                        if page_post_count < limit:
                            logger.info(f"Initial fetch stopping: Page {page} had {page_post_count} posts (limit {limit}), indicating the end of results.")
                            keep_fetching = False
                        # else: Page was full, repetition check already happened, so continue if keep_fetching is still True.
                    else:
                        # Incremental Fetch: Stop if page wasn't full OR if no new posts were found on a full page
                        if page_post_count < limit:
                            logger.info(f"Incremental fetch stopping: Page {page} had {page_post_count} posts (limit {limit}), indicating the end of results.")
                            keep_fetching = False
                        elif not found_new_on_page:
                            logger.warning(f"Incremental fetch stopping: Page {page} was full ({page_post_count}/{limit}), but NO posts newer than {latest_stored_timestamp} were found. Oldest on page: {oldest_ts_on_this_page}.")
                            keep_fetching = False
                        # else: Incremental fetch continuing: Page was full and contained new posts.

                # --- Prepare for next iteration or exit ---
                if keep_fetching:
                    previous_page_post_ids = current_page_post_ids # Store current IDs for next iteration's check
                    page += 1
                    logger.debug("Waiting 1 second before next fetch...")
                    # time.sleep(1)
                else:
                    logger.debug(f"keep_fetching is False after page {page} processing. Exiting fetch loop.")

            except requests.exceptions.RequestException as e:
                logger.error(f"HTTP Error fetching posts for '{community}' on page {page}: {e}")
                keep_fetching = False # Stop fetching on HTTP error
            except Exception as e:
                 logger.error(f"Unexpected error during fetch loop for '{community}' on page {page}: {e}", exc_info=True)
                 keep_fetching = False # Stop fetching on unexpected error

        logger.info(f"Finished fetch process for '{community}'. Found {len(new_posts_to_process)} new posts to potentially process.")
        # Pass the list (reversed, oldest first) directly to process_posts
        self.process_posts(new_posts_to_process[::-1], community)


    def process_posts(self, posts: List[dict], community: str) -> None:
        """Process and store ONLY NEW posts in the specific table for the community."""
        models = self._get_models_for_community(community)
        PostModel = models['Post']
        session = self.Session()
        processed_count = 0
        skipped_count = 0
        added_ids = set()

        # Get existing IDs from the specific community table
        existing_ids_query = session.query(PostModel.id)
        existing_ids = {id_[0] for id_ in existing_ids_query.all()}
        logger.info(f"Found {len(existing_ids)} existing post IDs in table '{PostModel.__tablename__}'.")
        try:
            for post in posts:
                try:
                    created_at_str = post["created_at"]
                    created_at = datetime.fromisoformat(created_at_str.replace('Z', '+00:00'))
                    content = post["content_plain"]
                    author = post["author"]["username"]
                    post_slug = post.get('slug', '[no slug]') # Get slug for logging
                except KeyError as e:
                    logger.warning(f"Skipping post due to missing key: {e} in post data: {post.get('slug')}")
                    skipped_count += 1
                    continue
                
                post_id = self._generate_post_id(content, author, created_at_str)
                
                # Check if post already exists (by ID/hash in this community's table)
                if post_id in existing_ids:
                    logger.debug(f"Skipping post {post_id} ('{post_slug}'): Already exists in DB table '{PostModel.__tablename__}'.")
                    skipped_count += 1
                    continue
                if post_id in added_ids:
                    logger.debug(f"Skipping post {post_id} ('{post_slug}'): Duplicate within current fetch batch.")
                    skipped_count += 1
                    continue

                # Pass community to _extract_distances
                community_distance, runner_distance, run_count = self._extract_distances(content, community)
                
                # Check for valid extraction results
                if runner_distance <= 0 or run_count == 0:
                    logger.debug(f"Skipping post {post_id} ('{post_slug}'): Invalid distance/count after extraction ({runner_distance=}, {run_count=}).")
                    skipped_count += 1
                    continue
                
                week_number = created_at.isocalendar()[1]
                year = created_at.year
                
                # Create instance of the specific PostModel for this community
                new_post_obj = PostModel( 
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
                session.add(new_post_obj)
                added_ids.add(post_id)
                processed_count += 1
                
                # Commit periodically
                if processed_count > 0 and processed_count % 100 == 0:
                    logger.info(f"[{community} - {PostModel.__tablename__}] Committing batch of {processed_count} posts...")
                    session.commit()
                    logger.info(f"[{community} - {PostModel.__tablename__}] Commit successful.")
            
            if processed_count % 100 != 0: # Commit any remaining posts
                 logger.info(f"[{community} - {PostModel.__tablename__}] Committing final batch of {processed_count % 100} posts...")
                 session.commit()
                 logger.info(f"[{community} - {PostModel.__tablename__}] Final commit successful.")

            logger.info(f"[{community} - {PostModel.__tablename__}] Added {processed_count} new posts, skipped {skipped_count} posts.")
            
            # Update summary tables for THIS community if new posts were added
            if processed_count > 0:
                logger.info(f"[{community}] Updating summary tables...")
                # Pass community name to update only its tables
                self.update_summary_tables(community) 
                logger.info(f"[{community}] Summary tables updated.")
            else:
                 logger.info(f"[{community}] No new posts added, skipping summary table update.")

        except Exception as e:
            logger.error(f"Error processing posts: {e}")
            session.rollback()
            raise
        finally:
            session.close()

    def update_summary_tables(self, community: str) -> None:
        """Calculate and store aggregated stats in the summary tables for ONE specific community."""
        models = self._get_models_for_community(community)
        PostModel = models['Post']
        WeeklySummaryModel = models['WeeklySummary']
        RunnerMonthlyStatsModel = models['RunnerMonthlyStats']
        RunnerYearlyStatsModel = models['RunnerYearlyStats']
        
        session = self.Session()
        logger.info(f"(Re)calculating summaries for community '{community}' into tables: "
                    f"{WeeklySummaryModel.__tablename__}, {RunnerMonthlyStatsModel.__tablename__}, {RunnerYearlyStatsModel.__tablename__}")
        try:
            # Clear existing summary data for THIS community ONLY
            session.query(WeeklySummaryModel).delete()
            session.query(RunnerMonthlyStatsModel).delete()
            session.query(RunnerYearlyStatsModel).delete()
            # Commit the delete before proceeding with inserts
            session.commit() 
            logger.info(f"Cleared existing summary data for '{community}'.")

            # --- Calculate Weekly Summary (using specific community PostModel) --- 
            weekly_data = session.query(
                PostModel.year,
                PostModel.week_number,
                func.sum(PostModel.runner_distance).label('total_distance')
            ).group_by(
                PostModel.year,
                PostModel.week_number
            ).all()

            weekly_summary_objects = [
                WeeklySummaryModel( # Use specific model
                    year=row.year,
                    week_number=row.week_number,
                    total_distance=round(row.total_distance or 0.0, 2)
                ) for row in weekly_data
            ]
            if weekly_summary_objects:
                session.bulk_save_objects(weekly_summary_objects)
                logger.info(f"[{community}] Inserted {len(weekly_summary_objects)} rows into {WeeklySummaryModel.__tablename__}.")

            # --- Calculate Runner Monthly Stats (using specific community PostModel) --- 
            monthly_data = session.query(
                PostModel.year,
                extract('month', PostModel.created_at).label('month'),
                PostModel.author,
                func.sum(PostModel.runner_distance).label('total_distance'),
                func.sum(PostModel.run_count).label('total_runs')
            ).group_by(
                PostModel.year,
                extract('month', PostModel.created_at),
                PostModel.author
            ).all()

            monthly_stats_objects = []
            for row in monthly_data:
                total_distance = round(row.total_distance or 0.0, 2)
                total_runs = row.total_runs or 0
                avg_distance = round((total_distance / total_runs) if total_runs > 0 else 0.0, 2)
                monthly_stats_objects.append(
                    RunnerMonthlyStatsModel( # Use specific model
                        year=row.year,
                        month=row.month,
                        author=row.author,
                        total_distance=total_distance,
                        total_runs=total_runs,
                        average_distance_per_run=avg_distance
                    )
                )
            if monthly_stats_objects:
                session.bulk_save_objects(monthly_stats_objects)
                logger.info(f"[{community}] Inserted {len(monthly_stats_objects)} rows into {RunnerMonthlyStatsModel.__tablename__}.")

            # --- Calculate Runner Yearly Stats (using specific community PostModel) --- 
            yearly_data = session.query(
                PostModel.year,
                PostModel.author,
                func.sum(PostModel.runner_distance).label('total_distance'),
                func.sum(PostModel.run_count).label('total_runs')
            ).group_by(
                PostModel.year,
                PostModel.author
            ).all()

            yearly_stats_objects = []
            for row in yearly_data:
                total_distance = round(row.total_distance or 0.0, 2)
                total_runs = row.total_runs or 0
                avg_distance = round((total_distance / total_runs) if total_runs > 0 else 0.0, 2)
                yearly_stats_objects.append(
                    RunnerYearlyStatsModel( # Use specific model
                        year=row.year,
                        author=row.author,
                        total_distance=total_distance,
                        total_runs=total_runs,
                        average_distance_per_run=avg_distance
                    )
                )
            if yearly_stats_objects:
                session.bulk_save_objects(yearly_stats_objects)
                logger.info(f"[{community}] Inserted {len(yearly_stats_objects)} rows into {RunnerYearlyStatsModel.__tablename__}.")

            session.commit()
            logger.info(f"Successfully updated summary tables for community '{community}'.")

        except Exception as e:
            logger.error(f"Error updating summary tables: {e}")
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
    """Main function to run data collection for multiple communities."""
    logger.info("Starting Hejto Data Collector script for multiple communities...")
    collector = HejtoDataCollector()
    
    for community in COMMUNITIES_TO_PROCESS:
        logger.info(f"--- Processing community: {community} ---")
        # Fetch returns the list of posts
        new_posts_data = collector.fetch_posts(community=community)
        
        # # Process the returned list if it's not empty
        # if new_posts_data:
        #     collector.process_posts(new_posts_data, community=community) 
        # else:
        #     logger.info(f"No new posts found for '{community}' to process.")

    logger.info("Hejto Data Collector script finished for all communities.")

if __name__ == "__main__":
    main() 