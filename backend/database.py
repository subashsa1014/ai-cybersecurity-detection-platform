"""
MongoDB database connection and management.
"""

from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
import motor.motor_asyncio
from config import settings
AsyncMongoDBClient = motor.motor_asyncio.AsyncIOMotorClient

# Motor async client for async operations
mongodb_client: motor.motor_asyncio.AsyncIOMotorClient = None
database = None

# Sync client for ML operations
sync_client: MongoClient = None


async def connect_to_mongodb():
    global mongodb_client, database

    try:
        mongodb_client = motor.motor_asyncio.AsyncIOMotorClient(
            settings.MONGODB_URI,
            serverSelectionTimeoutMS=5000,
        )
        # Test connection
        await mongodb_client.admin.command("ping")
        database = mongodb_client[settings.DB_NAME]
        print(f"Connected to MongoDB database: {settings.DB_NAME}")
    except ConnectionFailure as e:
        print(f"MongoDB connection failed: {e}")
        raise
    except ServerSelectionTimeoutError as e:
        print(f"MongoDB server selection timeout: {e}")
        raise


async def close_mongodb_connection():
    global mongodb_client, database, sync_client

    if mongodb_client:
        mongodb_client.close()
        print("MongoDB async connection closed")

    if sync_client:
        sync_client.close()
        print("MongoDB sync connection closed")

    database = None


def get_database():
    """Get the database instance."""
    return database


def get_collection(collection_name: str):
    """Get a collection from the database."""
    if database is None:
        raise ConnectionFailure("Database not connected")
    return database[collection_name]


def get_sync_client() -> MongoClient:
    """Get a synchronous MongoDB client for ML operations."""
    global sync_client
    if sync_client is None:
        sync_client = MongoClient(
            settings.MONGODB_URI,
            serverSelectionTimeoutMS=5000,
        )
    return sync_client


def create_indexes():
    """Create database indexes for better query performance."""
    try:
        db = get_sync_client()[settings.DB_NAME]

        # Users collection indexes
        db["users"].create_index("email", unique=True)
        db["users"].create_index("username", unique=True)

        # Scan history indexes
        db["scan_history"].create_index("user_id")
        db["scan_history"].create_index("scan_type")
        db["scan_history"].create_index("timestamp")
        db["scan_history"].create_index("threat_level")

        # Threats collection indexes
        db["threats"].create_index("type")
        db["threats"].create_index("severity")
        db["threats"].create_index("timestamp")

        print("Database indexes created successfully")
    except Exception as e:
        print(f"Error creating indexes: {e}")
        

def get_db():
    """Return the current MongoDB database instance."""
    return database
