
def scanner_factory(record):
    #if record == 1:
    #    return dns_scanner(record)
    #if record == 2:
    #    return http_scanner(record)
    #if record == 3:
    #    return ip_scanner(record)
    #if record == 4:
    #    return port_scanner(record)
    #if record == 5:
    #    return version_scanner(record)
    return null_scanner(record)

class wasure_scanner():
    def __init__(self, record):
        pass

    def execute_scan(self):
        """ 
        Execute the scan. Returns three values:
        1) result
        2) relationships
        3) additional assets 

        The RESULT is the direct response to this scan, the record that is
        persisted for this record.

        The RELATIONSHIPS are the new or updated interrelationships between
        assets.

        ADDITIONAL ASSETS are 'new' assets to add to the scanning backlog.
        """ 
        pass

class null_scanner(wasure_scanner):
    _record = None

    def __init__(self, record):
        _record = record

    def execute_scan(self):
        return None, None, None