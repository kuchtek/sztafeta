from fastapi import FastAPI, Depends, BackgroundTasks
from sqlalchemy.orm import Session
from app.database import get_db, engine
from app.models import Base
from app.services.hejto_service import HejtoService
import logging

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.post("/fetch-posts")
async def fetch_posts(background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """Endpoint to trigger post fetching."""
    service = HejtoService(db)
    background_tasks.add_task(service.process_posts)
    return {"message": "Post fetching started"}

@app.post("/aggregate-weekly")
async def aggregate_weekly(db: Session = Depends(get_db)):
    """Endpoint to trigger weekly data aggregation."""
    service = HejtoService(db)
    service.aggregate_weekly_data()
    return {"message": "Weekly aggregation completed"}

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"} 