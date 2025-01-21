from prisma import Prisma
db = Prisma()

async def db_connect():
    """
    Connected to the database.
    """
    if not db.is_connected():
        print("Connecting to database...")
        await db.connect()

async def db_disconnect():
    """
    Disconnect from the database.
    """
    if db.is_connected():
        print("Disconnected from database")
        await db.disconnect()