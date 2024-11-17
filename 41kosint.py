
import time
import crayons
import sys
import jwt
import datetime
import fade
import json
import random
from bs4 import BeautifulSoup
import phonenumbers
from phonenumbers import carrier, geocoder, timezone
from colorama import Fore, Style
import cowsay
import os
import requests
import re
import subprocess
from rich.console import Console
from rich.table import Table



a = fade.purplepink("[")
b = fade.purplepink("]")
console = Console()

GREEN = "\033[38;5;10m"
WHITE = "\033[97m"
RESET = "\033[0m"
RED = "\033[91m"
BLUE = "\033[38;5;12m"
DARK_GRAY = "\033[90m"


LEAKCHECK_URL = (
    "https://leakcheck.net/api/public?key=49535f49545f5245414c4c595f4150495f4b4559&check={}"
)
HUDSON_ROCK_API_URL = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email"
HUDSON_ROCK_API_KEY = "ROCKHUDSONROCK"


SECRET_KEY = "sbyjthkoft4yaimbwcjqpmxs8huovd"
SAPI_URL = "https://api-experimental.snusbase.com/"
IP_API_URL = "http://ip-api.com/json/"


uagent = [
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0) Opera 12.14",
    "Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:26.0) Gecko/20100101 Firefox/26.0",
    "Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3",
    "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)",
    "Mozilla/5.0 (Windows NT 6.2) AppleWebKit/535.7 (KHTML, like Gecko) Comodo_Dragon/16.1.1.0 Chrome/16.0.912.63 Safari/535.7",
    "Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)",
    "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:63.0) Gecko/20100101 Firefox/63.0"
]


def search(req, stop=10):
    chosenUserAgent = random.choice(uagent)
    reqSession = requests.Session()
    headers = {
        'User-Agent': chosenUserAgent,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-us,en;q=0.5',
        'Accept-Encoding': 'gzip,deflate',
        'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.7',
        'Keep-Alive': '115',
        'Connection': 'keep-alive',
        'Cache-Control': 'no-cache'
    }

    REQ = urlencode({'q': req})
    URL = f'https://www.google.com/search?tbs=li:1&{REQ}&amp;gws_rd=ssl&amp;gl=us'
    r = reqSession.get(URL, headers=headers)
    
    soup = BeautifulSoup(r.text, 'html5lib')
    results = soup.find("div", id="search").find_all("div", class_="g")
    
    links = []
    counter = 0
    for result in results:
        counter += 1
        if int(counter) > int(stop):
            break
        url = result.find("a").get('href')
        url = re.sub(r'(?:\/url\?q\=)', '', url)
        url = re.sub(r'(?:\/url\?url\=)', '', url)
        url = re.sub(r'(?:\&sa\=)(?:.*)', '', url)
        url = re.sub(r'(?:\&rct\=)(?:.*)', '', url)

        if re.match(r"^(?:\/search\?q\=)", url) is not None:
            url = 'https://google.com' + url

        if url is not None:
            links.append(url)

    return links

def formatNumber(InputNumber):
    return re.sub("(?:\+)?(?:[^[0-9]*)", "", InputNumber)

def localScan(InputNumber):

    FormattedPhoneNumber = "+" + formatNumber(InputNumber)

    try:
        PhoneNumberObject = phonenumbers.parse(FormattedPhoneNumber, None)
    except Exception as e:
        return False
    else:
        if not phonenumbers.is_valid_number(PhoneNumberObject):
            print('[!] The number is not valid.')
            return False

        if not phonenumbers.is_possible_number(PhoneNumberObject):
            print('[!] The number is not possible.')
            return False

        number = phonenumbers.format_number(
            PhoneNumberObject, phonenumbers.PhoneNumberFormat.E164).replace('+', '')
        numberCountryCode = phonenumbers.format_number(
            PhoneNumberObject, phonenumbers.PhoneNumberFormat.INTERNATIONAL).split(' ')[0]
        localNumber = phonenumbers.format_number(
            PhoneNumberObject, phonenumbers.PhoneNumberFormat.NATIONAL)
        internationalNumber = phonenumbers.format_number(
            PhoneNumberObject, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        numberCountry = geocoder.description_for_number(PhoneNumberObject, 'en')
        numberCarrier = carrier.name_for_number(PhoneNumberObject, 'en')
        numberTimeZone = timezone.time_zones_for_number(PhoneNumberObject)

        number_type = phonenumbers.number_type(PhoneNumberObject)
        if number_type == 0:
            numberType = 'Fixed line'
        elif number_type == 1:
            numberType = 'Mobile'
        elif number_type == 2:
            numberType = 'Fixed line or Mobile'
        elif number_type == 3:
            numberType = 'Toll free'
        elif number_type == 4:
            numberType = 'Premium rate'
        elif number_type == 5:
            numberType = 'Shared cost'
        elif number_type == 6:
            numberType = 'VOIP'
        elif number_type == 7:
            numberType = 'Personal number'
        elif number_type == 8:
            numberType = 'Pager'
        elif number_type == 9:
            numberType = 'UAN'
        elif number_type == 10:
            numberType = 'Voice mail'
        else:
            numberType = 'Unknown'

        print(f"{GREEN}[!] Fetching informations for {FormattedPhoneNumber}{RESET}")
        print(f"{WHITE}[+] International format: {internationalNumber}{RESET}")
        print(f"{WHITE}[+] Local format: {localNumber}{RESET}")
        print(f"{WHITE}[+] Country found: {numberCountry} ({numberCountryCode}){RESET}")
        print(f"{WHITE}[+] City/Area: {numberCountry}{RESET}")
        print(f"{WHITE}[+] Carrier: {numberCarrier}{RESET}")
        print(f"{WHITE}[+] Timezone: {', '.join(numberTimeZone)}{RESET}")
        print(f"{WHITE}[-] The number is valid and possible.{RESET}")
        print(f"{WHITE}[-] Number type: {numberType}{RESET}")
        print(f"{WHITE}[-] Scan finished.{RESET}")

        return True


def run():
    phone_number = input(f"{BLUE}Enter the phone number to scan: {RESET}")

    if not localScan(phone_number):
        print(f'{RED}[!] Unable to parse this number.{RESET}')
        return

    print(f'{GREEN}[-] Finished.{RESET}')
    time.sleep(4)
    print()
    print()

def generate_token():
    expiration1 = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    token1 = jwt.encode({"exp": expiration1}, SECRET, algorithm="HS256")
    return token1

def verify_key(key):
    url1 = 'https://029c-104-28-242-72.ngrok-free.app//verify_key'
    token1 = generate_token()
    headers1 = {'Authorization': token1}
    response1 = requests.post(url1, json={"key": key}, headers=headers1)
    try:
        return response1.json().get("valid")
    except ValueError:
        return False

def decode(json_text):
    try:
        return json.loads(json_text)
    except json.JSONDecodeError as e:
        print(f"{RED}Error decoding JSON: {e}{RESET}")
        return {}


def fetch(query):
    try:
        response = requests.get(LEAKCHECK_URL.format(query))
        response.raise_for_status()
        data = decode(response.text)
        return data
    except requests.RequestException as e:
        print(f"{RED}Error fetching data: {e}{RESET}")
        return None


def post_request(endpoint, payload=None):
    headers = {
        "Auth": SECRET_KEY,
        "Content-Type": "application/json",
    }
    method = "POST" if payload else "GET"
    data = json.dumps(payload) if payload else None
    try:
        response = requests.request(method, SAPI_URL + endpoint, headers=headers, data=data)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"{RED}Error fetching data: {e}{RESET}")
        return {}


def print_table(headers, rows):
    table = Table(*headers, border_style="white")
    for row in rows:
        table.add_row(*row)
    console.print(table, style="white")
    console.print()


def check_email(email):
    if email:
        data = fetch(email)
        if data and "success" in data:
            found = data.get("found", "N/A")
            passwords = data.get("passwords", "N/A")
            print(
                f"{GREEN}[*] Found {found} data leaks for {email} with {passwords} passwords!{RESET}"
            )
            sources = data.get("sources", [])

            if sources:
                print_table(
                    ["Name", "Date"],
                    [[source.get("name", "N/A"), source.get("date", "N/A")] for source in sources],
                )
                time.sleep(3)
        else:
            print(f"{RED}[!] No leaks found for {email}!{RESET}")
            time.sleep(2)


def leak_lookup(email):
    if email:
        try:
            result = subprocess.run(
                [
                    "curl",
                    "-X",
                    "GET",
                    "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email",
                    "-H",
                    "api-key: ROCKHUDSONROCK",
                    "-G",
                    "--data-urlencode",
                    f"email={email}",
                ],
                capture_output=True,
                text=True,
            )

            if result.returncode != 0:
                print(f"{RED}Error executing curl command: {result.stderr}{RESET}")
                return
            data = json.loads(result.stdout)

            if "stealers" in data and data["stealers"]:
                print(f"{GREEN}[*] Email Data Lookup :{RESET}")
                for steal in data["stealers"]:
                    total_user_services = steal.get("total_user_services", "N/A")
                    date_compromised = steal.get("date_compromised", "N/A")
                    computer_name = steal.get("computer_name", "N/A")
                    operating_system = steal.get("operating_system", "N/A")
                    malware_path = steal.get("malware_path", "N/A")
                    antiviruses = steal.get("antiviruses", "N/A")
                    ip = steal.get("ip", "N/A")
                    top_passwords = steal.get("top_passwords", [])
                    top_logins = steal.get("top_logins", [])

                    date_compromised = date_compromised.replace("T", " ").replace("Z", "")

                    print(f"{WHITE}[+] Total user services: {total_user_services}{RESET}")
                    print(f"{WHITE}[+] Date compromised: {date_compromised}{RESET}")
                    print(f"{WHITE}[+] Computer name: {computer_name}{RESET}")
                    print(f"{WHITE}[+] Operating system: {operating_system}{RESET}")
                    print(f"{WHITE}[+] Malware path: {malware_path}{RESET}")
                    print(f"{WHITE}[+] Antiviruses: {', '.join(antiviruses) if antiviruses else 'None'}{RESET}")
                    print(f"{WHITE}[+] IP address: {ip}{RESET}")
                    print(
                        f"{WHITE}[+] Top passwords: {', '.join(top_passwords) if top_passwords else 'None'}{RESET}"
                    )
                    print(f"{WHITE}[+] Top logins: {', '.join(top_logins) if top_logins else 'None'}{RESET}")
                    print()
            else:
                print(f"{RED}[!] No data found for {email}.{RESET}")
            time.sleep(5)
            print()
            print()
        except (json.JSONDecodeError, subprocess.CalledProcessError) as e:
            print(f"[-] No results")
            time.sleep(2)
            print()
            print()
            print()


def search_email(email):
    response = post_request(
        "data/search",
        {
            "terms": [email],
            "types": ["email"],
            "wildcard": False,
        },
    )
    if response:
        print(f"{GREEN}[*] DB Search Results:{RESET}\n{json.dumps(response, indent=2)}")
        print()
        time.sleep(3)
    else:
        print(f"{RED}Error: No data returned for search email query.{RESET}")
        time.sleep(3)


def check_username(username):
    if username:
        data = fetch(username)
        if data and "success" in data:
            found = data.get("found", "N/A")
            passwords = data.get("passwords", "N/A")
            print(
                f"{GREEN}[*] Found {found} data leaks for {username} with {passwords} passwords!{RESET}"
            )
            sources = data.get("sources", [])

            if sources:
                print_table(
                    ["Name", "Date"],
                    [[source.get("name", "N/A"), source.get("date", "N/A")] for source in sources],
                )
                time.sleep(3)
        else:
            print(f"{RED}[!] No leaks found for {username}!{RESET}")
            time.sleep(2)


def search_username(username):
    response = post_request(
        "data/search",
        {
            "terms": [username],
            "types": ["username"],
            "wildcard": False,
        },
    )
    if response:
        print(f"{GREEN}[*] DB Search Results:{RESET}\n{json.dumps(response, indent=2)}")
        time.sleep(3)
        print()
        print()
        print()
    else:
        print(f"{RED}Error: No data returned for search username query.{RESET}")
        time.sleep(2)


def lookup_ip(ip):
    if ip:
        try:
            response = requests.get(f"{IP_API_URL}{ip}")
            response.raise_for_status()
            data = response.json()
            print(f"{GREEN}[*] IP Information for {ip}:{RESET}")
            for key, value in data.items():
                print(f"{key}: {value}")
            time.sleep(3)
            print()
            print()
            print()
            print()
        except requests.RequestException as e:
            print(f"{RED}Error fetching IP information: {e}{RESET}")
            time.sleep(2)


def search_ip(ip):
    response = post_request(
        "data/search",
        {
            "terms": [ip],
            "types": ["lastip"],
            "wildcard": False,
        },
    )
    if response:
        print(f"{GREEN}[*] DB Search Results:{RESET}\n{json.dumps(response, indent=2)}")
        time.sleep(3)
        print()
        print()
        print()
    else:
        print(f"{RED}Error: No data returned for search IP query.{RESET}")


def check_services(email):
    if email:
        result = subprocess.run(
            ["holehe", email],
            capture_output=True,
            text=True,
        )
        services = extract_services(result.stdout)
        for service in services:
            print(f"{WHITE}{service}{RESET}")
        time.sleep(3)
        print()
        print()
        print()


def extract_services(output):
    services = []
    lines = output.splitlines()
    plus_indices = [i for i, line in enumerate(lines) if line.startswith("[+]")]
    if plus_indices:
        plus_indices = plus_indices[:-1]
    for index in plus_indices:
        services.append(lines[index].strip())
    return services


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def display_ascii_art():
    ascii_art = rf"""





  _____                   .__        __          
_/ ____\__________   ____ |__| _____/  |_ ___.__.
\   __\/  ___/  _ \_/ ___\|  |/ __ \   __<   |  |
 |  |  \___ (  <_> )  \___|  \  ___/|  |  \___  |
 |__| /____  >____/ \___  >__|\___  >__|  / ____|
           \/           \/        \/      \/     
   _____ ____ __                                 
  /  |  /_   |  | __                             
 /   |  ||   |  |/ /                            derrick rose prime (dont fw us!)
/    ^   /   |    <                              
\____   ||___|__|_ \                             
     |__|         \/                              """
     
    print(fade.blackwhite(ascii_art))
    
    print(f"{RED}{WHITE}{BLUE} {DARK_GRAY}41k#0614 on revolt{RESET}")
    
    print(f"{RED}[{WHITE}?{BLUE}] {WHITE}Select an option :{RESET}")

def dox_creator():
    clear()
    
    full_name = input(f"{DARK_GRAY}Full name: {RESET}")
    doxed_by = input(f"{DARK_GRAY}Doxed by: {RESET}")
    ip_address = input(f"{DARK_GRAY}IP Address: {RESET}")
    username = input(f"{DARK_GRAY}Username: {RESET}")
    bros_sis = input(f"{DARK_GRAY}Bros/Sis: {RESET}")
    mom = input(f"{DARK_GRAY}Mom: {RESET}")
    dad = input(f"{DARK_GRAY}Dad: {RESET}")
    links_photos = input(f"{DARK_GRAY}Links/Photos: {RESET}")
    discord_invite = input(f"{DARK_GRAY}Discord.gg/: {RESET}")

    
    with open("41kdoox.txt", "w") as file:
        file.write("d0x (fsociety)\n")
        file.write(f"Full Name: {full_name}\n")
        file.write(f"Doxed By: {doxed_by}\n")
        file.write(f"IP address: {ip_address}\n")
        file.write(f"Username: {username}\n")
        file.write(f"Bros/Sis: {bros_sis}\n")
        file.write(f"Mom: {mom}\n")
        file.write(f"Dad: {dad}\n")
        file.write(f"Links/Photos {links_photos}\n")
        file.write(f"Discord Invite: {discord_invite}\n")
        file.write("------------------------\n")

    print(f"{GREEN}Dox information saved in '41kdoox.txt'!{RESET}")
    time.sleep(3)



    if choice == "1":
        email = input(f"{BLUE}Enter email address: {RESET}")
        check_email(email)
    elif choice == "2":
        username = input(f"{BLUE}Enter username: {RESET}")
        check_username(username)
    elif choice == "3":
        ip = input(f"{BLUE}Enter IP address: {RESET}")
        lookup_ip(ip)
    elif choice == "4":
        email = input(f"{BLUE}Enter email address: {RESET}")
        search_email(email)
    elif choice == "5":
        username = input(f"{BLUE}Enter username: {RESET}")
        search_username(username)
    elif choice == "6":
        ip = input(f"{BLUE}Enter IP address: {RESET}")
        search_ip(ip)
    elif choice == "7":
        email = input(f"{BLUE}Enter email address: {RESET}")
        check_services(email)
    elif choice == "8":
        email = input(f"{BLUE}Enter email address: {RESET}")
        leak_lookup(email)
    elif choice == "9":
        run()
    elif choice == "10":
        dox_creator()  
    elif choice == "!":
        print(f"{GREEN}Exiting...{RESET}")
        exit()
    else:
        print(f"{RED}Invalid choice. Please try again.{RESET}")
        
def credits():
    print(f"{BLUE}[credits]{RED}{RESET}")
    print(f"{DARK_GRAY}Made by 41k/9kis(just me){RESET}")
    print(f"{BLUE}[01] {BLUE}Discord{RESET}")
    print(f"{RED}[02] {RED}Revolt{RESET}")
    
    print()
    
    choice = input(f"{WHITE}{RESET}{GREEN}Choose: {RESET}")

    if choice == "01":
        print(f"{BLUE}discord: {RESET}{BLUE}atlpp{RESET}")
    elif choice == "02":
        print(f"{WHITE}revolt: {RESET}{RED}41k#0614{RESET}")
    else:
        print(f"{RED}Invalid choice. Returning to main menu.{RESET}")
    print()

def menu():
    display_ascii_art()
    print()
    print(f"{RED}[{WHITE}1{BLUE}] {WHITE}LeakCheck Email")
    print(f"{RED}[{WHITE}2{BLUE}] {WHITE}LeakCheck Username")
    print(f"{RED}[{WHITE}3{BLUE}] {WHITE}IP Lookup")
    print(f"{RED}[{WHITE}4{BLUE}] {WHITE}DB Search Email")
    print(f"{RED}[{WHITE}5{BLUE}] {WHITE}DB Search Username(lag)")
    print(f"{RED}[{WHITE}6{BLUE}] {WHITE}DB Search IP")
    print(f"{RED}[{WHITE}7{BLUE}] {WHITE}Email Service Checker")
    print(f"{RED}[{WHITE}8{BLUE}] {WHITE}Info Stealer Lookup")
    print(f"{RED}[{WHITE}9{BLUE}] {WHITE}Phone Number Osint")
    print(f"{RED}[{WHITE}10{BLUE}] {WHITE}d0x Creator")  
    print(f"{RED}[{WHITE}11{BLUE}] {WHITE}Credits")  
    print(f"{DARK_GRAY}[{DARK_GRAY}e{DARK_GRAY}] {DARK_GRAY}Exit")
    print()
    
    user = ""
    choice = input(f"{WHITE}{user}{RESET}{RED}fsociety{RESET}{GREEN}[os1nt]{RESET}:{WHITE}~ ")

    if choice == "1":
        email = input(f"{BLUE}Enter email address: {RESET}")
        check_email(email)
    elif choice == "2":
        username = input(f"{BLUE}Enter username: {RESET}")
        check_username(username)
    elif choice == "3":
        ip = input(f"{BLUE}Enter IP address: {RESET}")
        lookup_ip(ip)
    elif choice == "4":
        email = input(f"{BLUE}Enter email address: {RESET}")
        search_email(email)
    elif choice == "5":
        username = input(f"{BLUE}Enter username: {RESET}")
        search_username(username)
    elif choice == "6":
        ip = input(f"{BLUE}Enter IP address: {RESET}")
        search_ip(ip)
    elif choice == "7":
        email = input(f"{BLUE}Enter email address: {RESET}")
        check_services(email)
    elif choice == "8":
        email = input(f"{BLUE}Enter email address: {RESET}")
        leak_lookup(email)
    elif choice == "9":
        run()  
    elif choice == "10":
        dox_creator()  
    elif choice == "11":  
        credits()
    elif choice == "e":
        print(f"{GREEN}Exiting...{RESET}")
        exit()
    else:
        print(f"{RED}Invalid choice. Please try again.{RESET}")

def print_cowsay(message):
    cowsay.tux(message)


def main():
    clear()
    while True:
        menu()


if __name__ == "__main__":
    os.system("cls")
    main()