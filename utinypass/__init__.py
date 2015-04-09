''' An UNOFFICIAL TinyPass untility library.

Use like:

    import utinypass.crypto

    encrypted = utinypass.crypt.b64encode( 'mykey', 'mydata' ) 

'''
from utinypass.client import TinyPassApiClient as api

__all__ = [ 'crypto', api]
__version__ = '0.2.1'

