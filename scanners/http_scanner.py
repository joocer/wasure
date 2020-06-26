import requests
from bs4 import BeautifulSoup
import hashlib
import datetime
from .scanner import wasure_scanner

HTTPResponse = requests.packages.urllib3.response.HTTPResponse
orig_HTTPResponse__init__ = HTTPResponse.__init__
def new_HTTPResponse__init__(self, *args, **kwargs):
    orig_HTTPResponse__init__(self, *args, **kwargs)
    try:
        self.peer_certificate = self._connection.peer_certificate
    except AttributeError:
        pass
HTTPResponse.__init__ = new_HTTPResponse__init__

HTTPAdapter = requests.adapters.HTTPAdapter
orig_HTTPAdapter_build_response = HTTPAdapter.build_response
def new_HTTPAdapter_build_response(self, request, resp):
    response = orig_HTTPAdapter_build_response(self, request, resp)
    try:
        response.peer_certificate = resp.peer_certificate
    except AttributeError:
        pass
    return response
HTTPAdapter.build_response = new_HTTPAdapter_build_response

HTTPSConnection = requests.packages.urllib3.connection.HTTPSConnection
orig_HTTPSConnection_connect = HTTPSConnection.connect
def new_HTTPSConnection_connect(self):
    orig_HTTPSConnection_connect(self)
    try:
        self.peer_certificate = self.sock.connection.get_peer_certificate()
    except AttributeError:
        pass
HTTPSConnection.connect = new_HTTPSConnection_connect

def certificate_summary(cert):
    valid_from = cert.get_notBefore().decode()
    valid_until = cert.get_notAfter().decode()
    valid_from = datetime.datetime.strptime(valid_from, "%Y%m%d%H%M%SZ")
    valid_until = datetime.datetime.strptime(valid_until, "%Y%m%d%H%M%SZ")

    summary = { 
        'subject_cn'        : cert.get_subject().commonName,
        'subject_org'       : cert.get_subject().organizationName,
        'subject_ou'        : cert.get_subject().organizationalUnitName,
        'subject_location'  : cert.get_subject().countryName,
        'issuer_cn'         : cert.get_issuer().commonName,
        'issuer_org'        : cert.get_issuer().organizationName,
        'issuer_ou'         : cert.get_issuer().organizationalUnitName,
        'issuer_location'   : cert.get_issuer().countryName,
        'serial_number'     : cert.get_serial_number(),
        'algorithm'         : cert.get_signature_algorithm().decode(),
        'version'           : cert.get_version(),
        'valid_from'        : "{}".format(valid_from),
        'valid_until'       : "{}".format(valid_until),
        'validity'          : (valid_until - valid_from).days
    }
    return summary

class http_scanner(wasure_scanner):
    _url = None

    def __init__(self, record):
        self._url = record

    def execute_scan(self):
        # 1) result
        # 2) relationships
        # 3) additional assets 

        r = requests.get(url = self._url, verify=True)
        page_hash = hashlib.sha224(r.text.encode('utf-8')).hexdigest()
        soup = BeautifulSoup(r.text, 'html.parser')

        relationships = []
        assets = []

        # hrefs
        for anchor in soup.find_all('a'):
            target = requests.compat.urljoin(self._url, anchor.get('href'))
            relationships.append({ 
                'source': self._url, 
                'target': target, 
                'relationship': 'link' 
                })
            assets.append({ 'type': 'http', 'asset': target })

        # javascript includes
        for script in soup.find_all('script'):
            target = requests.compat.urljoin(self._url, script.get('src'))
            relationships.append({ 
                'source' : self._url, 
                'target': target, 
                'relationship': 'script', 
                'sri': script.get('integrity') 
                })
            assets.append({ 'type': 'http', 'asset': target })
            assets.append({ 'type': 'version', 'asset': target })
        
        # stylesheet includes
        for style in soup.find_all('link'):
            target = requests.compat.urljoin(self._url, style.get('href'))
            relationships.append({ 
                'source': self._url, 
                'target': target, 
                'relationship': 'style', 
                'sri': script.get('integrity') 
                })
            assets.append({ 'type': 'http', 'asset': target })

        result =  { 
            'url': self._url, 
            'hash': page_hash, 
            'status': r.status_code, 
            'duration': r.elapsed.total_seconds(), 
            'size': len(r.text), 
            'headers': r.headers, 
            'cert': certificate_summary(r.peer_certificate),
            'body': r.text 
            }

        return result, relationships, assets
