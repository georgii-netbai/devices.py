from backend.connections.config import config
import hashlib
import requests
import time


class Device:
    def __init__(self, extid, username, password, region=config.region):
        self.extid = extid
        self.username = username
        self.password = password
        self.region = region

    def get_sso(self):
        url = '/er/ssoauth/auth'
        connection = requests.post(config.discovery_server + url,
                                   data={'username': self.username,
                                         'password': self.password,
                                         'region': self.region})
        result = connection.json()
        return result['sso']

    def get_device_token(self):
        url = '/token/device'
        connection = requests.get(config.discovery_server + url,
                                  params={'device_id': self.extid,
                                          'client_id': self.get_client_id(),
                                          'timestamp': int(time.time())})
        token = connection.json()['token']
        return token

    def get_token(self):
        url = '/token/subscriber_device/by_sso'
        connection = requests.get(config.discovery_server + url,
                                  params={'client_id': self.get_client_id(),
                                          'timestamp': int(time.time()),
                                          'sso_system': 'er',
                                          'sso_key': self.get_sso()},
                                  headers={'X-Auth-Token': self.get_device_token()})

        token = connection.json()['token']
        return token

    def get_client_id(self):
        pass


class Stb(Device):
    device_type = 'stb'

    def __init__(self, extid, username=None, password=None, region=config.region):
        super().__init__(extid, username, password, region)
        self.token = self.get_token()

    def get_token(self):
        parameters = {'client_id': self.get_client_id(),
                      'timestamp': int(time.time()),
                      'device_id': self.extid}
        signature = self.generate_signature(parameters, config.secret_stb)
        parameters['signature'] = signature
        url = '/token/device'
        connection = requests.get(config.discovery_server + url, params=parameters)
        token = connection.json()['token']
        return token

    @staticmethod
    def generate_signature(arguments, secret):
        items = sorted(arguments.items())
        items_hash = hashlib.md5()
        items_hash.update((''.join(('%s%s' % (k, v) for k, v in items)) + secret).encode('utf-8'))
        return items_hash.hexdigest()

    def get_client_id(self):
        return config.client_id.stb


class Android(Device):
    device_type = 'android'

    def __init__(self, extid, username, password, region=config.region):
        super().__init__(extid, username, password, region)
        self.token = self.get_token()

    def get_client_id(self):
        return config.client_id.android


class Ios(Device):
    device_type = 'ios'

    def __init__(self, extid, username, password, region=config.region):
        super().__init__(extid, username, password, region)
        self.token = self.get_token()

    def get_client_id(self):
        return config.client_id.ios


class Web(Device):
    device_type = 'web'

    def __init__(self, extid, username, password, region=config.region):
        super().__init__(extid, username, password, region)
        self.token = self.get_token()

    def get_client_id(self):
        return config.client_id.web
