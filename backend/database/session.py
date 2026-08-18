"""
MongoDB client and database access.

MONGODB_URI and MONGODB_DATABASE are read from the environment, e.g.:
  MONGODB_URI=mongodb://localhost:27017
  MONGODB_DATABASE=ibqc
"""
from __future__ import annotations

import os
from collections.abc import Generator

from pymongo import MongoClient
from pymongo.collection import ReturnDocument
from pymongo.database import Database

MONGODB_URI = os.environ.get("MONGODB_URI", "mongodb://localhost:27017")
MONGODB_DATABASE = os.environ.get("MONGODB_DATABASE", "ibqc")

# pymongo connects lazily — constructing MongoClient does not itself
# open a socket or block, so this is safe to do at import time (mirrors
# how `engine = create_engine(...)` worked for the previous
# SQLAlchemy-backed session module).
client: MongoClient = MongoClient(MONGODB_URI)
db: Database = client[MONGODB_DATABASE]


def get_db() -> Generator[Database, None, None]:
    """FastAPI dependency: yields the MongoDB database handle."""
    yield db


def get_next_id(collection_name: str) -> int:
    """
    Atomically allocate the next integer id for `collection_name`.

    MongoDB documents default to an ObjectId `_id`, but the existing
    API response schemas (`api/schemas.py`) declare id fields as
    plain `int` (e.g. `record_id: int`, `intent_id: int`,
    `PolicyResponse.id: int`) and those schemas are not being changed
    as part of this migration. To keep ids working as ints end to end,
    every collection stores an application-assigned integer `_id`,
    handed out here via a dedicated `counters` collection — the
    standard MongoDB pattern for auto-increment-style ids.
    """
    counter = db.counters.find_one_and_update(
        {"_id": collection_name},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=ReturnDocument.AFTER,
    )
    return counter["seq"]
