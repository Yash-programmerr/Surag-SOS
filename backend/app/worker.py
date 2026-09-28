import os
from celery import Celery

celery_app = Celery("satellite", broker=os.getenv("REDIS_URL", "redis://localhost:6379/0"))
