# github.com/xyele

import requests,re,argparse,random,json
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor, as_completed

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

colors = ["red","green","yellow","blue","magenta","cyan","white"]
patterns = json.load(open("patterns.json", "r"))
patterns = list(zip(patterns.keys(), patterns.values()))
alreadyfound = []

ap = argparse.ArgumentParser()
ap.add_argument("--list", required=True,help="Set URL's")
ap.add_argument("--threads",required=True,help="Threads")
ap.add_argument("--colorless",required=False,help="Colorless", action='store_true')
args = vars(ap.parse_args())
threadPool = ThreadPoolExecutor(max_workers=int(args["threads"]))

def printBanner():
	print("""                                         
                                                     /$$             
                                                    | $$             
  /$$$$$$$  /$$$$$$   /$$$$$$$  /$$$$$$   /$$$$$$  /$$$$$$  /$$   /$$
 /$$_____/ /$$__  $$ /$$_____/ /$$__  $$ /$$__  $$|_  $$_/ |  $$ /$$/
|  $$$$$$ | $$$$$$$$| $$      | $$  \__/| $$$$$$$$  | $$    \  $$$$/ 
 \____  $$| $$_____/| $$      | $$      | $$_____/  | $$ /$$ >$$  $$ 
 /$$$$$$$/|  $$$$$$$|  $$$$$$$| $$      |  $$$$$$$  |  $$$$//$$/\  $$
|_______/  \_______/ \_______/|__/       \_______/   \___/ |__/  \__/
                                                                                                                                          
 """)
	pass

def printResult(name,key,url):
	if not key in alreadyfound:
		if args["colorless"] == True:
			print("Name: {}, Key: {}, URL: {}".format(name,key,url))
			pass
		else:
			print(colored("Name: {}, Key: {}, URL: {}".format(name,key,url),random.choice(colors)))
			pass
		alreadyfound.append(key)
		pass
	pass

def extractSecrets(url):
	reqHeaders = {"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36 OPR/65.0.3467.62"}
	req = requests.get(url, verify=False,allow_redirects=False,headers=reqHeaders)
	for p in patterns:
		thePattern = r"[:|=|\'|\"|\s*|`|´| |,|?=|\]|\|//|/\*}]("+p[1]+r")[:|=|\'|\"|\s*|`|´| |,|?=|\]|\}|&|//|\*/]"
		findPattern = re.findall(re.compile(thePattern),req.text)
		findPattern and [printResult(str(p[0]),str(result),url) for result in findPattern]
		pass
	pass

printBanner()

urlList = open(args["list"], "r").read().split("\n")
for url in urlList:
	threadPool.submit(extractSecrets,url)
	pass
