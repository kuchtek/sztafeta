from sqlalchemy import Column, Integer, String, Float, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func

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