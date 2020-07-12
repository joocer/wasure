import pymongo
import random

filename = "mongo.secret"
fd = open(filename , 'r')
connectionstring = fd.read()
conn = pymongo.MongoClient(connectionstring)
db = conn['wasure']
collection = db['assets']


def add(item):
    collection.update({ "type": item['type'], "asset": item['asset'] }, item, upsert=True )

def fetch(type='*'):
    records = collection.count()
    select = random.randint(0,records)
    results = collection.find().limit(1).skip(select)
    for result in results:
        return result