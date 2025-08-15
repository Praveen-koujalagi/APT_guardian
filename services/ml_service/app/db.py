import os
from pymongo import MongoClient
from py2neo import Graph

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB = os.getenv("MONGO_DB", "apt_guardian")

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "neo4jpassword")

mongo = MongoClient(MONGO_URI)[MONGO_DB]
graph = Graph(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

def ensure_graph_constraints():
    graph.run("CREATE CONSTRAINT IF NOT EXISTS FOR (h:Host) REQUIRE h.ip IS UNIQUE")
