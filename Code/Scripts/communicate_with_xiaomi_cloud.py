import requests
import hashlib
import random
import string
import json
import secrets
import struct
import base64
import time
import hmac


TEST_USERNAME = "111111111"  # input your username
TEST_PASSWORD = "111111111"  # input your password


class xiaomi_cloud:
    def __init__(self):
        self.username = None
        self.password = None
        self.userid = None
        self.device_id = None
        self.ssecurity = None
        self.service_token = None
        return

    def generate_random_string(self, length):
        characters = string.ascii_letters
        random_string = ''.join(random.choice(characters) for _ in range(length))
        return random_string

    def generate_nonce(self):
        random_bytes = secrets.token_bytes(8)
        current_minute = int(round(time.time() / 60))
        time_bytes = struct.pack('>I', current_minute)
        buf = bytearray(12)
        buf[:8] = random_bytes
        buf[8:] = time_bytes
        return base64.b64encode(buf).decode()

    def get_sign_k(self, ssecret, nonce):
        ssecret_bytes = base64.b64decode(ssecret)
        nonce_bytes = base64.b64decode(nonce)
        sha256 = hashlib.sha256()
        sha256.update(ssecret_bytes)
        sha256.update(nonce_bytes)
        return base64.b64encode(sha256.digest()).decode()

    def get_signature(self, _signed_nonce, nonce, params, path):
        exps = [path, _signed_nonce, nonce]
        sorted_params = sorted(params.items())
        for key, value in sorted_params:
            exps.append(f"{key}={value}")
        signature = hmac.new(base64.b64decode(_signed_nonce), '&'.join(exps).encode(), hashlib.sha256)
        return base64.b64encode(signature.digest()).decode()

    def micloud_login(self, username, password):
        self.username = username
        self.password = password
        self.device_id = self.generate_random_string(6)
        md5 = hashlib.md5()
        md5.update(self.password.encode())
        upper_password_hash = md5.hexdigest().upper()
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Android-7.1.1-1.0.0-ONEPLUS A3010-136-CDDDCFBBDDAEB APP/xiaomi.smarthome APPV/62830',
            'Cookie': f'deviceId={self.device_id}; sdkVersion=accountsdk-18.8.15',
            'Host': 'account.xiaomi.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }
        response = requests.get('https://account.xiaomi.com/pass/serviceLogin?_json=true&sid=xiaomiio&_locale=zh_CN',
                                headers=headers)
        result = json.loads(response.text[11:])
        qs = result.get("qs")
        callback = result.get("callback")
        sid = result.get("sid")
        _sign = result.get("_sign")

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Android-7.1.1-1.0.0-ONEPLUS A3010-136-CDDDCFBBDDAEB APP/xiaomi.smarthome APPV/62830',
            'Cookie': f'deviceId={self.device_id}; sdkVersion=accountsdk-18.8.15',
            'Host': 'account.xiaomi.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }
        data = {
            "cc": "+86",
            "qs": f"{qs}",
            "callback": f"{callback}",
            "_json": "true",
            "_sign": f"{_sign}",
            "user": f"{self.username}",
            "hash": f"{upper_password_hash}",
            "sid": f"{sid}",
            "_locale": "zh_CN"
        }
        response = requests.post('https://account.xiaomi.com/pass/serviceLoginAuth2', headers=headers, data=data)
        result = json.loads(response.text[11:])
        cUserId = result.get("cUserId")
        location = result.get("location")
        self.ssecurity = result.get("ssecurity")
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Android-7.1.1-1.0.0-ONEPLUS A3010-136-CDDDCFBBDDAEB APP/xiaomi.smarthome APPV/62830',
            'Cookie': f'deviceId={self.device_id}; sdkVersion=accountsdk-18.8.15',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip',
            "Host": "sts.api.io.mi.com"
        }
        response = requests.get(location, headers=headers)
        cookie = response.headers['Set-Cookie']
        lines = cookie.split(";")
        for line in lines:
            if "serviceToken" in line:
                self.service_token = line.split("=")[2] + "="
        # print("serviceToken=" + self.service_token)
        return

    def micloud_request(self, path, data):
        param = {"data": json.dumps(data)}
        nonce = self.generate_nonce()
        # print("nonce=" + nonce)
        sign_k = self.get_sign_k(self.ssecurity, nonce)
        # print("sign_k=" + sign_k)
        signature = self.get_signature(sign_k, nonce, param, path)
        # print("signature=" + signature)
        # print("[4]request " + path)
        body = {
            "_nonce": f"{nonce}",
            "data": param['data'],
            "signature": signature
        }
        headers = {
            'User-Agent': 'Android-7.1.1-1.0.0-ONEPLUS A3010-136-CDDDCFBBDDAEB APP/xiaomi.smarthome APPV/62830',
            'x-xiaomi-protocal-flag-cli': 'PROTOCAL-HTTP2',
            'Content-Type': 'application/x-www-form-urlencoded',
            "Cookie": f"sdkVersion=accountsdk-18.8.15; deviceId={self.device_id}; userId={self.username}; yetAnotherServiceToken={self.service_token}; serviceToken={self.service_token}; locale=en; channel=MI_APP_STORE"
        }
        response = requests.post("https://api.io.mi.com/app" + path, headers=headers, data=body)
        return response.text


class base_plug():
    def __init__(self):
        self.ins = xiaomi_cloud()
        self.ins.micloud_login(TEST_USERNAME, TEST_PASSWORD)
        self.plug_is_on = False

    def on(self):
        if not self.plug_is_on:
            print("Base plug on")
            prop_path = "/miotspec/prop/set"
            prop_data = {"params": [{"did": "1111111111", "siid": 2, "piid": 1, "value": True}]}  # input your device id

            result = json.loads(self.ins.micloud_request(prop_path, prop_data))
            # print(result)
            self.plug_is_on = True

    def off(self):
        if self.plug_is_on:
            print("Base plug off")
            prop_path = "/miotspec/prop/set"
            prop_data = {"params": [{"did": "1111111111", "siid": 2, "piid": 1, "value": False}]}  # input your device id

            result = json.loads(self.ins.micloud_request(prop_path, prop_data))
            # print(result)
            self.plug_is_on = False


def communicate_main(mi_username, mi_password, switch_flag):
    """
    :param mi_username: username of mi_home
    :param mi_password: password of mi_home
    :param switch_flag: on: True, off: False
    """
    ins = xiaomi_cloud()
    ins.micloud_login(mi_username, mi_password)

    prop_path = "/miotspec/prop/set"
    prop_data = {"params": [{"did": "11111111111", "siid": 2, "piid": 1, "value": switch_flag}]}  # input your device id

    # True on, False off
    result = json.loads(ins.micloud_request(prop_path, prop_data))
    # print(result)


def plug_on():
    # return
    print("Base plug on")
    communicate_main(TEST_USERNAME, TEST_PASSWORD, True)


def plug_off():
    # return
    print("Base plug off")
    communicate_main(TEST_USERNAME, TEST_PASSWORD, False)

