import pymongo
from queue_manager import q
import scanners

filename = "mongo.secret"
fd = open(filename , 'r')
connectionstring = fd.read()
conn = pymongo.MongoClient(connectionstring)
db = conn['wasure']

q.add({ 'type': 'http', 'asset': 'https://branleys.com/' })

while True:
    item = q.fetch()
    print(item)

    scanner = scanners.scanner_factory(item)

    result, relationships, assets = scanner.execute_scan()

    for asset in assets:
        q.add(asset)

    for relationship in relationships:
        db['relationships'].update(relationship, relationship, upsert=True )

    db['assets_' + item['type']].update({ "hash": result['hash'] }, result, upsert=True )