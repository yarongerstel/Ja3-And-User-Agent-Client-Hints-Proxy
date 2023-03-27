import types
from mitmproxy import http, tls
from ja3 import *
import csv

GREASE_TABLE = {0x0a0a: True, 0x1a1a: True, 0x2a2a: True, 0x3a3a: True,
                0x4a4a: True, 0x5a5a: True, 0x6a6a: True, 0x7a7a: True,
                0x8a8a: True, 0x9a9a: True, 0xaaaa: True, 0xbaba: True,
                0xcaca: True, 0xdada: True, 0xeaea: True, 0xfafa: True}


class JA3:
    def __init__(self, tls_version, cipher_suites, extensions, elliptic_curve, elliptic_curve_point_format):
        self.tls_version = tls_version
        self.cipher_suites = cipher_suites
        self.extensions = extensions
        self.elliptic_curve = elliptic_curve
        self.elliptic_curve_point_format = elliptic_curve_point_format

    def __str__(self):
        return f"JA3(\n tls_version={self.tls_version},\n cipher_suites={self.cipher_suites},\n \
extensions={self.extensions},\n elliptic_curve={self.elliptic_curve},\n \
elliptic_curve_point_format={self.elliptic_curve_point_format}\n)"


class UA:
    def __init__(self, user_agent, sec_ch_ua, sec_ch_ua_mobile, sec_ch_ua_platform):
        self.user_agent = user_agent
        self.sec_ch_ua = sec_ch_ua
        self.sec_ch_ua_mobile = sec_ch_ua_mobile
        self.sec_ch_ua_platform = sec_ch_ua_platform

    def __str__(self):
        return f"UA(\n user_agent={self.user_agent},\n sec_ch_ua={self.sec_ch_ua},\n \
sec_ch_ua_mobile={self.sec_ch_ua_mobile},\n sec_ch_ua_platform={self.sec_ch_ua_platform})"


class Session:
    def __init__(self, port_session, ja3, ua=None):
        self.port_session = port_session
        self.ja3 = ja3
        self.ua = ua


def delete_GREASE(cipher_suites):
    new_cipher_suites = []
    for cipher in cipher_suites:
        #
        if cipher not in GREASE_TABLE and cipher != 0:
            new_cipher_suites.append(cipher)

    return new_cipher_suites


def format_to_string(field):
    return '-'.join(str(num) for num in field)


def search_JA3(ja3):
    rows = []
    with open('JA3_Project.csv', 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            if row['TLSVersion'] == str(ja3.tls_version) \
                    and row['Ciphers'] == format_to_string(ja3.cipher_suites) \
                    and row['sorted_Extensions'] == format_to_string(ja3.extensions) \
                    and row['EllipticCurves'] == ja3.elliptic_curve \
                    and row['EllipticCurvePointFormats'] == ja3.elliptic_curve_point_format:
                rows.append(row['Platform'])
    return rows


def search_user_agent(ua):
    rows = []
    with open('JA3_Project.csv', 'r') as file:
        reader = csv.DictReader(file)
        # for row in reader:
        #  # print(row['User agent'], row['sec-ch-ua'], row['sec-ch-ua-mobile'], row['sec-ch-ua-platform'])
        #     if row['User agent'] == ua.user_agent \
        #             and row['sec-ch-ua'] == ua.sec_ch_ua \
        #             and row['sec-ch-ua-mobile'] == ua.sec_ch_ua_mobile \
        #             and row['sec-ch-ua-platform'] == ua.sec_ch_ua_platform:
        #         rows.append(row['Platform'])
    #return rows
        return compare_ua(ua)



def make_extensions_array(data):
    extensions = []
    for x in data:
        extensions.append(x[0])
    return sorted(extensions)


def get_http_headers(flow):
    user_agent = flow.request.headers.get('User-Agent')
    sec_ch_ua = flow.request.headers.get('sec-ch-ua')
    sec_ch_ua_mobile = flow.request.headers.get('sec-ch-ua-mobile')
    sec_ch_ua_platform = flow.request.headers.get('sec-ch-ua-platform')

    if sec_ch_ua == None:
        sec_ch_ua = '-'
    if sec_ch_ua_mobile == None:
        sec_ch_ua_mobile = '-'
    if sec_ch_ua_platform == None:
        sec_ch_ua_platform = '-'
    return user_agent, sec_ch_ua, sec_ch_ua_mobile, sec_ch_ua_platform

def compare_ua(ua):
    if ua.sec_ch_ua != "-":
        if "Google Chrome" in ua.sec_ch_ua:
            return "Google Chrome"
        if "Microsoft Edge" in ua.sec_ch_ua:
            return "Microsoft Edge"

    else:
        if "Firefox" in ua.user_agent:
            return "Firefox"
        if "curl" in ua.user_agent:
            return "curl"
        if "python" in ua.user_agent:
            return "python"
        if "Boost.Beast" in ua.user_agent:
            return "C++"
        if "HeadlessChrome" in ua.user_agent:
            return "selenium"

    if ua.sec_ch_ua != "-":
        return ua.sec_ch_ua
    else:
        return ua.user_agent



def is_browser(platform):
    if "mobile" in platform:
        print("Probably mobile")
        return False
    if "chrome" in platform or "edge" in platform or "firefox" in platform:
        print("Probably browser")
        return True
    print("Probably not browser")
    return False


def min_chipher(cipher_suites):
    if len(cipher_suites) <= 3:
        print("the number of ciphers is less then 3,Probably Bot -  Blocked!!!")
        return False
    return True

def only_humen(extentions):
    if 5 in extentions and 65281 in extentions:
        return True
    print("Probably Bot -  Blocked!!!")
    return False

def compare_user_agents(ua1, ua2):
    # Remove the version number from the user agents
    ua1 = ua1.split('/')[0]
    ua2 = ua2.split('/')[0]

    # Compare the user agents and calculate the compatibility percentage
    if ua1 == ua2:
        return 100
    else:
        common_chars = set(ua1) & set(ua2)
        total_chars = set(ua1) | set(ua2)
        compatibility_percentage = len(common_chars) / len(total_chars) * 100
        return compatibility_percentage


flag = input("only browsers (Not mobile) - b\n"
             "only mobile (Not browser) - m \n"
             "only humen (Not bot) - h\n"
             "(press enter to all..)")
sessions = []


def tls_clienthello(data: tls.ClientHelloData):
    raw_hex = data.client_hello.raw_bytes()
    tls_version = int.from_bytes(raw_hex[1:3], byteorder='big')

    cipher_suites = data.client_hello.cipher_suites
    #

    cipher_suites = delete_GREASE(cipher_suites)

    extensions = make_extensions_array(data.client_hello.extensions)
    extensions = delete_GREASE(extensions)

    elliptic_curve, elliptic_curve_point_format = elipric_curves_extract(data.client_hello.extensions)
    ja3 = JA3(tls_version, cipher_suites, extensions, elliptic_curve, elliptic_curve_point_format)

    print("source port of tls: " + str(data.context.client.address[1]))
    sessions.append(Session(str(data.context.client.address[1]), ja3))

    # print((format_to_string(extensions)))

    # if 4865 in data.client_hello.cipher_suites:
    #     data.ignore_connection = True
    #     print("ignored")


def request(flow: http.HTTPFlow) -> None:
    user_agent, sec_ch_ua, sec_ch_ua_mobile, sec_ch_ua_platform = get_http_headers(flow)

    ua = UA(user_agent, sec_ch_ua, sec_ch_ua_mobile, sec_ch_ua_platform)

    source_port = str(flow.client_conn.address[1])
    # print('source port of http ' + source_port)
    #
    # print('------------')

    for session in sessions:
        if session.port_session == source_port:
            session.ua = ua
            # print(session.port_session)
            # print(session.JA3)
            # print(session.ua)

            print("JA3 match the following platforms: ")
            print(search_JA3(session.ja3))
            print('------------')

            print("user agent match the following platforms: ")
            print(search_user_agent(session.ua))

            print('------------')


            if min_chipher(session.ja3.cipher_suites) == False:
                flow.request.port = 0
                return

            if  flag == "m" and is_browser(session.ua.sec_ch_ua_platform):
                flow.request.port = 0
                return

            if flag == "b" and not is_browser(session.ua.sec_ch_ua_platform):
                flow.request.port = 0
                return

            if flag == "h" and not only_humen(session.ja3.extensions):
                flow.request.port = 0
                return


            print('------------')
    # if "Edg" in flow.request.headers.get('User-Agent'):
    #     flow.request.port = 0

    flow.request.scheme = "https"
    flow.request.port = 4444
