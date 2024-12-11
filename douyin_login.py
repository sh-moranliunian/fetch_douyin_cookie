import base64
import copy
import json
import time
from datetime import datetime
from CookieUtil import CookieUtil

import requests
from fake_useragent import UserAgent
import random

session = requests.Session()
session.trust_env = False

ua = UserAgent(platforms=['pc'], os=["windows", "macos"])
pc_user_agent = ua.chrome

print('user-agent:\n', pc_user_agent)

common_headers = {
    "User-Agent": pc_user_agent,
    "Origin": "https://creator.douyin.com",
    "Referer": "https://creator.douyin.com/"
}


def getQrCoce(trace_id):
    request_url = "https://sso.douyin.com/get_qrcode/"

    request_headers = copy.deepcopy(common_headers)
    request_headers['X-Tt-Passport-Trace-Id'] = trace_id

    request_params = {
        'service': 'https://creator.douyin.com/',
        'aid': "2906",
        "account_sdk_source": "sso",
        "account_sdk_source_info": "7e276d64776172647760466a6b66707777606b667c273f3d292772606761776c736077273f63646976602927756970626c6b76273f5e2755414325536c60726077272927466d776a68602555414325536c60726077272927466d776a686c70682555414325536c60726077272927486c66776a766a637125406162602555414325536c607260772729275260674e6c712567706c6971286c6b2555414327582927756077686c76766c6a6b76273f5e7e276b646860273f2762606a696a6664716c6a6b2729277671647160273f276277646b7160612778297e276b646860273f276b6a716c636c6664716c6a6b762729277671647160273f2775776a6875712778297e276b646860273f27736c61606a5a666475717077602729277671647160273f2775776a6875712778297e276b646860273f276470616c6a5a666475717077602729277671647160273f2775776a68757127785829276c6b6b60774d606c626d71273f363c3029276c6b6b6077526c61716d273f3431313529276a707160774d606c626d71273f323c3d29276a70716077526c61716d273f34313135292767606d64736c6a77273f7e27716a70666d273f63646976602927686a707660273f7177706029276e607c476a647761273f717770607829277260676269273f7e27736077766c6a6b273f27526067424925342b35252d4a75606b424925405625372b3525466d776a686c70682c27292773606b616a77273f275260674e6c7127292777606b6160776077273f275260674e6c71255260674249277878",
        "language": "zh",
        "passport_jssdk_version": "3.0.1",
        "is_vcd": "1",
        "need_logo": "true",
        "biz_trace_id": trace_id
    }

    response = session.get(request_url, params=request_params, headers=request_headers)
    print("getQrCoce:\n", response.text)
    jsonObj = json.loads(response.text)

    base64_string = jsonObj['data']['qrcode'].replace("data:image/png;base64,", '')
    image_data = base64.b64decode(base64_string)
    with open("qrcode.png", "wb") as f:
        f.write(image_data)
    return jsonObj['data']['token']


def sms_handle(trace_id, type, ticket, token, lastest_cookie, headers, cookie_file_name):
    sendSmsCode(type, ticket, lastest_cookie)
    sms_text = input("请输入短信验证码：")
    validSmsCode(type, ticket, lastest_cookie, sms_text)

    doCheckQrCode(trace_id, token, lastest_cookie, headers, cookie_file_name)

def extractHeader(headers, key):
    for header, value in headers.items():
        header = header.lower()
        if header == key:
            return value
    return None


def redirectToUrl(redirect_url, headers, lastest_cookie, cookie_file_name):
    headers['Cookie'] = CookieUtil.cookies_to_string(lastest_cookie)
    response = session.get(redirect_url, headers=headers, allow_redirects=False)
    print("redirectToUrl:\n", redirect_url)
    print(f"redirectToUrl response: {response.text}")

    response_cookie = CookieUtil.cookies(session.cookies, lastest_cookie)
    print("response_cookie: \n", CookieUtil.cookies_to_string(response_cookie))
    print("latest_cookie: \n", CookieUtil.cookies_to_string(lastest_cookie))

    status = response.status_code
    if status == 302:
        location_url = extractHeader(response.headers, "location")
        redirectToUrl(location_url, headers, lastest_cookie, cookie_file_name)
    elif status == 200:
        print("final cookie:\n", CookieUtil.cookies_to_string(lastest_cookie))


def confirm_handle(jsonObj, headers, lastest_cookie, cookie_file_name):
    if 'redirect_url' in jsonObj['data']:
        redirect_url = jsonObj['data']['redirect_url']

        redirectToUrl(redirect_url, headers, lastest_cookie, cookie_file_name)


def doCheckQrCode(trace_id, token, lastest_cookie, headers, cookie_file_name):
    request_url = f"https://sso.douyin.com/check_qrconnect/"

    headers['X-Tt-Passport-Trace-Id'] = trace_id

    request_params = {
        'token': token,
        'service': 'https://creator.douyin.com/',
        'correct_service': "https://creator.douyin.com/",
        'aid': "2906",
        "account_sdk_source": "sso",
        "account_sdk_source_info": "7e276d64776172647760466a6b66707777606b667c273f3d292772606761776c736077273f63646976602927756970626c6b76273f5e2755414325536c60726077272927466d776a68602555414325536c60726077272927466d776a686c70682555414325536c60726077272927486c66776a766a637125406162602555414325536c607260772729275260674e6c712567706c6971286c6b2555414327582927756077686c76766c6a6b76273f5e7e276b646860273f2762606a696a6664716c6a6b2729277671647160273f276277646b7160612778297e276b646860273f276b6a716c636c6664716c6a6b762729277671647160273f2775776a6875712778297e276b646860273f27736c61606a5a666475717077602729277671647160273f2775776a6875712778297e276b646860273f276470616c6a5a666475717077602729277671647160273f2775776a68757127785829276c6b6b60774d606c626d71273f363c3029276c6b6b6077526c61716d273f3431313529276a707160774d606c626d71273f323c3d29276a70716077526c61716d273f34313135292767606d64736c6a77273f7e27716a70666d273f63646976602927686a707660273f7177706029276e607c476a647761273f717770607829277260676269273f7e27736077766c6a6b273f27526067424925342b35252d4a75606b424925405625372b3525466d776a686c70682c27292773606b616a77273f275260674e6c7127292777606b6160776077273f275260674e6c71255260674249277878",
        "passport_ztsdk": "3.0.20",
        "passport_verify": "1.0.17",
        "language": "zh",
        "passport_jssdk_version": "3.0.1",
        "is_vcd": "1",
        "biz_trace_id": trace_id
    }

    response = session.get(request_url, params=request_params, headers=headers)
    response_text = response.text
    print(f"doCheckQrCode response: {response_text}")
    jsonObj = json.loads(response.text)

    response_cookie = CookieUtil.cookies(session.cookies, lastest_cookie)
    print("response_cookie: \n", CookieUtil.cookies_to_string(response_cookie))
    print("latest_cookie: \n", CookieUtil.cookies_to_string(lastest_cookie))

    current_time = datetime.now()
    readable_time = current_time.strftime("%Y-%m-%d %H:%M:%S")

    if 'data' in jsonObj and 'status' in jsonObj['data']:
        status = jsonObj['data']['status']

        if status == '1':
            print(f"{readable_time} {response_text}: 客户端未扫码")
            return False
        elif status == '2':
            print(f"{readable_time} {response_text}: 客户端已扫码，等待确认")
            return False
        elif status == '3':
            print(f"{readable_time} {response_text}: 客户端确认登录")
            confirm_handle(jsonObj, headers, lastest_cookie, cookie_file_name)
            return True
        elif status == '4':
            print(f"{readable_time} {response_text}: 客户端取消登录")
            return True
        elif status == '5':
            print(f"{readable_time} {response_text}: 二维码过期，请重新获取")
            return True
    else:
        if 'error_code' in jsonObj and jsonObj['error_code'] == 2046:
            print(response_text)
            smsObj = json.loads(response.text)
            ticket = smsObj['verify_ticket']
            verify_ways = []
            for verify_way in smsObj['verify_ways']:
                verify_ways.append(verify_way['verify_way'])

            if 'mobile_sms_verify' in verify_ways or 'assist_mobile_sms_verify' in verify_ways:
                type = "3737"
                if 'assist_mobile_sms_verify' in verify_ways:
                    type = '363c'
                sms_handle(trace_id, type, ticket, token, lastest_cookie, headers, cookie_file_name)
            elif 'pwd_verify' in verify_ways:
                # 密码登录认证
                type = "363c"
            return True
        else:
            print(f"异常返回: {response_text}")
            return True


def checkQrCode(trace_id, token, lastest_cookie, cookie_file_name):
    headers = copy.deepcopy(common_headers)
    headers['Cookie'] = CookieUtil.cookies_to_string(lastest_cookie)
    while True:
        ret = doCheckQrCode(trace_id, token, lastest_cookie, headers, cookie_file_name)
        if ret:
            break
        time.sleep(2)


def sendSmsCode(type, ticket, lastest_cookie):
    headers = copy.deepcopy(common_headers)
    headers['Cookie'] = CookieUtil.cookies_to_string(lastest_cookie)
    request_url = f"https://creator.douyin.com/passport/web/send_code/"

    query_params = {
        'new_authn_sdk_version': '1.0.20-web'
    }

    data = {
        'mix_mode': "1",
        'type': type,
        'is6Digits': "1",
        'verify_ticket': ticket,
        'encrypt_uid': '',
        "aid": "2906",
        "new_authn_sdk_version": "1.0.20-web"
    }
    response = session.post(request_url, params=query_params, headers=headers, data=data)
    response_text = response.text
    print("sendSmsCode: \n", response_text)


def encodePassword(t):
    def encode_utf8_char(char):
        code = ord(char)
        if 0 <= code <= 127:
            return [code]
        elif 128 <= code <= 2047:
            return [(192 | (31 & code >> 6)), (128 | (63 & code))]
        elif 2048 <= code <= 55295 or 57344 <= code <= 65535:
            return [(224 | (15 & code >> 12)), (128 | (63 & code >> 6)), (128 | (63 & code))]
        return []

    encoded_bytes = []
    for char in str(t):
        encoded_bytes.extend(encode_utf8_char(char))

    result = []
    for byte in encoded_bytes:
        result.append(hex(5 ^ byte)[2:])

    return ''.join(result)


def validSmsCode(type, ticket, lastest_cookie, sms_text):
    sms_code = encodePassword(sms_text)
    headers = copy.deepcopy(common_headers)
    headers['Cookie'] = CookieUtil.cookies_to_string(lastest_cookie)
    request_url = f"https://creator.douyin.com/passport/web/validate_code/"
    query_params = {
        'new_authn_sdk_version': '1.0.20-web'
    }

    data = {
        'mix_mode': "1",
        'type': type,
        'code': sms_code,
        'verify_ticket': ticket,
        'encrypt_uid': '',
        "aid": "2906",
        "new_authn_sdk_version": "1.0.20-web"
    }
    response = session.post(request_url, params=query_params, headers=headers, data=data)
    response_text = response.text
    print("validSmsCode: \n", response_text)


def getTtwidCookie():
    local_header = {
        "User-Agent": common_headers['User-Agent'],
        "Content-Type": "application/json"
    }
    request_url = "https://ttwid.bytedance.com/ttwid/union/register/"

    data = {
        "aid": 2906,
        "service": "creator.douyin.com",
        "unionHost": "https://ttwid.bytedance.com",
        "needFid": "false",
        "union": "true",
        "fid": ""
    }

    data_str = json.dumps(data)
    response = session.post(request_url, data=data_str, headers=local_header)
    print("getTtwid: \n", response.text)

    jsonObj = json.loads(response.text)
    callback_url = jsonObj['redirect_url']
    response = session.get(callback_url, headers=local_header)
    status_code = response.status_code
    if status_code == 200 and 'Set-Cookie' in response.headers:
        cookie_dict = CookieUtil.cookies_from_headers(session.cookies)
        return cookie_dict
    return {}


def get_ms_token(randomlength=107):
    random_str = ''
    base_str = 'ABCDEFGHIGKLMNOPQRSTUVWXYZabcdefghigklmnopqrstuvwxyz0123456789='
    length = len(base_str) - 1
    for _ in range(randomlength):
        random_str += base_str[random.randint(0, length)]
    return random_str


def get_trace_id():
    t = int(time.time() * 1000)  # 获取当前时间的毫秒数
    e = int((time.perf_counter() if hasattr(time, 'perf_counter') else 0) * 1000)  # 获取性能时间的毫秒数

    uuid_template = "xxxxxxxx"
    uuid = []

    for char in uuid_template:
        if char == 'x':
            r = int(16 * random.random())
            if t > 0:
                r = (t + r) % 16
                t = t // 16
            else:
                r = (e + r) % 16
                e = e // 16
            uuid.append(format(r, 'x'))
        else:
            r = int(16 * random.random())
            uuid.append(format((3 & r) | 8, 'x'))

    return ''.join(uuid)


def login(latest_cookie):
    request_url = "https://creator.douyin.com/aweme/v1/creator/login/"
    headers = {
        'Host': "creator.douyin.com",
        "Cookie": CookieUtil.cookies_to_string(lastest_cookie)
    }

    request_data = {
        "login_type": 1,
        "login_app": 2906
    }

    response = session.post(request_url, headers=headers, data=request_data)
    print(response.text)
    resp_cookie = CookieUtil.cookies(session.cookies, lastest_cookie)
    print("final cookie:\n", CookieUtil.cookies_to_string(latest_cookie))


def save_cookie(lastest_cookie, cookie_file_name):
    file_path = cookie_file_name
    with open(file_path, 'w') as file:
        file.write(CookieUtil.cookies_to_string(lastest_cookie))


if __name__ == '__main__':
    session = requests.Session()
    session.trust_env = False
    lastest_cookie = getTtwidCookie()
    print("ttwid: \n", CookieUtil.cookies_to_string(lastest_cookie))
    trace_id = get_trace_id()
    lastest_cookie['biz_trace_id'] = trace_id
    token = getQrCoce(trace_id)
    lastest_cookie['msToken'] = get_ms_token()

    cookie_file_name = "douyin_cookie.txt"
    checkQrCode(trace_id, token, lastest_cookie, cookie_file_name)
    login(lastest_cookie)
    save_cookie(lastest_cookie, cookie_file_name)
