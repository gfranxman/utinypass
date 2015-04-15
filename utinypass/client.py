import utinypass.crypto

import requests
import json
import time
import datetime
import calendar

class TinyPassApiClient(  object ):

    def __init__( self, app_id=None, api_token=None, private_key=None, sandbox=False ):
        self.sandbox = sandbox
        self.app_id = app_id
        self.api_token = api_token
        self.private_key = private_key


    @property
    def base_url( self ):
        if self.sandbox:
            requests.packages.urllib3.disable_warnings()
            return 'https://sandbox.tinypass.com'
        return 'https://api.tinypass.com'


    def get_access_list( self, email, uid ):
        '''
            Takes and email and matching uid, builds a uref and fetches an access structure that looks like:

            {
              "count": 1, 
              "code": 0, 
              "ts": 1428522205, 
              "limit": 100, 
              "offset": 0, 
              "total": 1, 
              "data": [
                {
                  "granted": true, 
                  "resource": {
                    "aid": "J8MY0Bu8Xs", 
                    "rid": "RESOURCE_MONTHLY", 
                    "image_url": "/images2/default/file-document.png", 
                    "name": "Month", 
                    "description": ""
                  }, 
                  "user": {
                    "first_name": "WackoJacko", 
                    "last_name": "AndDot", 
                    "email": "dotswill@echo.net", 
                    "api_token": "CDEADBEEFcafebabe0x1337KxYzCiuIHaX0Ri3GH"
                  }, 
                  "access_id": "1VShIZzLeIod"
                }
              ]
            }

        '''
        path = '/api/v3/access/list'

        # package the user
        userRef = {
            'uid': uid,
            'email': email,
            'timestamp': int(time.time())
        }
        serialized = json.dumps(userRef)#, indent=2)
        user_ref = utinypass.crypto.aesencrypt(self.private_key, serialized)

        # prepare the request        
        data = {
            'aid': self.app_id,
            'user_ref': user_ref, 
        }

        # doit
        r = requests.get( self.base_url + path, data=data )

        if r.status_code != 200:
            raise ValueError( path + ":" + r.reason )

        access_struct = json.loads( r.content )

        return access_struct


    def grant_user_access( self, uid, rid, expire_datetime = None, send_email=False ):
        '''
            Takes a user id and resource id and records a grant of access to that reseource for the user.
            If no expire_date is set, we'll default to 24 hours.
            If send_email is set to True, Tinypass will send an email related to the grant.
            No return value, raises ValueError.
        '''
        path =  "/api/v3/publisher/user/access/grant"
        
        # convert expire_date to gmt seconds
        if expire_datetime:
            expires_seconds = calendar.timegm(expires_datetime.timetuple())
        else:
            expires_seconds = calendar.timegm(datetime.datetime.now().timetuple()) + (60*60*24)

        data = {
            'api_token': self.api_token, 
            'aid': self.app_id,
            'rid': rid,
            'uid': uid,
            'expire_date': expires_seconds,
            'send_email': send_email,
        }

        r = requests.get( self.base_url + path, data=data )

        if r.status_code != 200:
            raise ValueError( path + ":" + r.reason ) 
        #print r.content


    def revoke_user_access( self, access_id ):
        '''
            Takes an access_id, probably obtained from the get_access_list structure, and revokes that access.
            No return value, but may raise ValueError.
        ''' 
        path = "/api/v3/publisher/user/access/revoke"

        data = {
            'api_token': self.api_token, 
            'access_id': access_id,
        }

        r = requests.get( self.base_url + path, data=data )

        if r.status_code != 200:
            raise ValueError( path + ":" + r.reason ) 


    def create_user( self, uid, email, first_name='', last_name='' ):
        path = "/api/v3/publisher/user/create"

        data = {
            'api_token': self.api_token,
            'aid': self.app_id,
            'uid': uid,
            'email': email,
        }

        if first_name:
            data['first_name'] = first_name

        if last_name:
            data['last_name'] = last_name

        r = requests.get( self.base_url + path, data=data )

        if r.status_code != 200:
            raise ValueError( path + ":" + r.reason ) 

        res = json.loads( r.content )

        if res.has_key( 'code' ):
            if res['code'] in (403, 2001, 2000, 2002):
                raise ValueError( path + ":" + res['message'] )
            print res

        return res['user']



    def update_user( self, uid, email='', first_name='', last_name='' ):
        path = "/api/v3/publisher/user/update"

        data = {
            'api_token': self.api_token,
            'aid': self.app_id,
            'uid': uid,
        }

        if email:
            data['email'] = email

        if first_name:
            data['first_name'] = first_name

        if last_name:
            data['last_name'] = last_name

        r = requests.get( self.base_url + path, data=data )

        if r.status_code != 200:
            raise ValueError( path + ":" + r.reason ) 

        res = json.loads( r.content )

        if res.has_key( 'code' ):
            if res['code'] in (403, 2001, 2000, 2002):
                raise ValueError( path + ":" + res['message'] )
            print res

        return res['user']



    def get_user( self, uid, disabled=False ):
        ''' given a uid, returns
        {
        first_name (string): User's first name,
        image1 (string): User's profile image,
        email (string): User's email address,
        create_date (string): The creation date,
        last_name (string): User's last name,
        uid (string): User's UID
        }

        You can pass disabled=True if you'd like to get the user even if the user has been disabled.
        '''
        path = "/api/v3/publisher/user/get"

        data = {
            'api_token': self.api_token,
            'aid': self.app_id,
            'uid': uid,
            'disabled': disabled,
        }

        r = requests.get( self.base_url + path, data=data )

        if r.status_code == 2:
            raise ValueError( path + ":" + r.reason )  # An Auth issue

        if r.status_code == 2004:
            return None # no user found

        res = json.loads( r.content )

        # great the error could be in the json
        if res.has_key( 'code' ):
            if res['code'] != 0:
                # 403 == auth error, 2004 = not found, 2 = access denied
                if res['code'] == 2:
                    raise ValueError( path + ":" + res['message'] )  # An Auth issue
                print res
                return None

        return res['user']

