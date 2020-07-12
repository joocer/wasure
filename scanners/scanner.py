from .http_scanner import http_scanner
from .null_scanner import null_scanner

def scanner_factory(record):
    if record['type'] == 'http':
        return http_scanner(record['asset'])
    #if record == 2:
    #    return http_scanner(record)
    #if record == 3:
    #    return ip_scanner(record)
    #if record == 4:
    #    return port_scanner(record)
    #if record == 5:
    #    return version_scanner(record)
    return null_scanner(record)

