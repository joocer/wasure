import dns.resolver
from .scanner import wasure_scanner

class dns_resolver_scanner(wasure_scanner):

    @staticmethod
    def execute_scan(record):
        IP_TYPES = ['AAAA', 'A']
        NAME_SERVER_TYPES = ['NS']
        ALIAS_TYPES = ['CNAME']
        RECORD_TYPES = IP_TYPES + NAME_SERVER_TYPES
        NAME_TYPES = NAME_SERVER_TYPES + ALIAS_TYPES

        relationships = []
        assets = []

        has_cname = False
        for record_type in NAME_TYPES:
            try:
                answers = dns.resolver.resolve(record, record_type)
                for answer in answers:
                    if record_type in ALIAS_TYPES:
                        assets.append({ 'type' : 'DNS', 'response' : answer.to_text() })
                        has_cname = True
                    relationships.append({ 
                        'source': record, 
                        'target': answer.to_text(), 
                        'relationship': record_type
                        })
            except:
                pass

        if has_cname:
            return None, relationships, assets
            
        for record_type in RECORD_TYPES:
            try:
                answers = dns.resolver.resolve(record, record_type)
                for answer in answers:
                    if record_type in NAME_TYPES:
                        assets.append({ 'type' : 'DNS', 'response' : answer.to_text() })
                    if record_type in IP_TYPES:
                        assets.append({ 'type' : 'IP', 'response' : answer.to_text() })
                    relationships.append({ 
                        'source': record, 
                        'target': answer.to_text(), 
                        'relationship': record_type
                        })
            except:
                pass
        return None, relationships, assets