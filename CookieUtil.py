
class CookieUtil:

    @staticmethod
    def cookies(session_cookies, lastest_cookie):
        old_cookies = CookieUtil.cookies_from_headers(session_cookies)
        CookieUtil.merge_cookies(old_cookies, lastest_cookie)
        return old_cookies

    @staticmethod
    def cookies_from_headers(session_cookies):
        cookies = {}
        for i in session_cookies:
            cookies[i.name.strip()] = i.value.strip()

        return cookies

    @staticmethod
    def cookies_to_string(cookies):
        return "; ".join([f"{key}={value}" for key, value in cookies.items()])

    @staticmethod
    def merge_cookies(old_cookies, new_cookies):
        for key, value in old_cookies.items():
            new_cookies.setdefault(key, value)

