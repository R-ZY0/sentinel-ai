import os
from celery.signals import setup_logging
from .logging_setup import configure_logging
from celery import Celery


@setup_logging.connect
def configure_worker_logging(**kwargs):
    configure_logging()


celery_app = Celery(
    "sentinel",
    broker=os.environ["CELERY_BROKER_URL"],
    backend=os.environ["CELERY_RESULT_BACKEND"],
    include=["app.scan_tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    broker_connection_retry_on_startup=True,
)


@celery_app.task(name="sentinel.ping")
def ping():
    return "pong"