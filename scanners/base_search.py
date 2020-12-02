import abc
import enum

class ASSET_TYPES(enum.Enum):
    IP: "ip"
    HOST: "host"


class BaseSearch(abc.ABC):

    def supports_asset(self, asset_type:ASSET_TYPES) -> bool:
        raise NotImplementedError()

    def execute_scan(self, record):
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
        raise NotImplementedError()
