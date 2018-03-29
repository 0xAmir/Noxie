#!/usr/bin/python3

from urllib import parse
import argparse
import requests
from colorama import init,Fore, Back, Style
from pyfiglet import Figlet
from http.cookies import SimpleCookie
from os import system
from requests.packages.urllib3.exceptions import InsecureRequestWarning

def main():
	fx = Figlet(font = 'colossal')
	print(Fore.BLUE + (fx.renderText("Noxie")).rstrip())
	print("The Mass Web Fuzzer", end='')
	print(Style.RESET_ALL.rstrip())
	print("By 0xAmir\n\n")
	init()
	requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
	parser = argparse.ArgumentParser()

	parser.add_argument('-u', '--url',
		dest='url', 
		help="Url to be scanner (Single Mode)")

	parser.add_argument('-f','--file',	 
		dest='url_file', 
		default = 'list.txt',
		help="File containing line separated URLs to scan (Multi Mode)")

	parser.add_argument('-p','--payfile',
		dest='payload_file', 
		default='payloads.txt', 
		help="File containing line serparated Payloads to use")

	parser.add_argument('-c','--cookies',
		dest='cookie_file', 
		default ='cookies.txt',
		help="file containing cookies to pass to the request")

	args = parser.parse_args()

	vuln=False
	url_list = []


	try:
		if(args.url):
			url_list.append(args.url)

		elif(args.url_file):	
			with open(args.url_file, 'r') as url_file:
				for line in url_file.readlines():
					if '?' in line:
						url_list.append(line.rstrip())
			print(Fore.GREEN + "[*] Loaded {0} urls from file.".format(len(url_list)))
		else:
			raise argparse.ArgumentError

		payload_list = []
		if(args.payload_file):
			pay_file = args.payload_file
		with open(pay_file, 'r') as pay_file:
			for line in pay_file.readlines():
				payload_list.append(line.rstrip())
		print(Fore.GREEN + "[*] Loaded {0} payloads from file.\n\n".format(len(payload_list)))


		if(args.cookie_file):
			with open('cookies.txt', 'r') as cfile:
				c_cont = cfile.read()
			if("Cookie: " in c_cont): c_cont = c_cont[c_cont.find(": ")+2::]
			cookies = SimpleCookie()
			cookies.load(c_cont)
			cookies = {key: val.value for key, val in cookies.items()}
		else:
			cookies = None
				
	except Exception as e:
		print("[-] " + str(e))
		exit(2)


	scanned_paths = [] #check for tuple(path,params)

	for url in url_list: 
		clr = ""
		vuln_pays = []
		print(Fore.GREEN + "\n[*] Testing: {0}\n".format(url))
		parsed = parse.urlparse(url)
		params = parse.parse_qsl(parsed.query)
		if(parsed.path in scanned_paths):
				print(Fore.WHITE + Back.GREEN + "[-] Reapeated Endpoint, Ignoring..", end='')
				print(Style.RESET_ALL)
				continue
		for i in range(len(params)):
			no = 0
			scanned_paths.append(parsed.path)
			print(Fore.GREEN + "Found Parameter {0} = {1}".format(params[i][0],params[i][1]))
			for payload in payload_list:
				parsed = parse.urlparse(url)
				params = parse.parse_qsl(parsed.query)
				params[i] = tuple((params[i][0],"\"/>" +payload))
				parsed = parsed._replace(query=parse.urlencode(params))
				req = requests.get(parse.urlunparse(parsed), 
					cookies=cookies,
					verify=False,
					allow_redirects=True)
				no+=1
				print("\t{0}{1:.2f}%[{2}]".format(clr,((no/len(payload_list))*100),(chr(9618)*no)), end='\r')
				if(no == len(payload_list)): print('\n')
				
				if payload in req.content.decode(errors="ignore"):
					clr = Fore.RED
					vuln_pays.append(payload)
					vuln = True
				else:
					vuln = False
					continue
		
		if not vuln:
			print("\n[-] URL's Not Vulnerable.\n")
		else:
			print("[!]Vulnerable!\n")
			for i in vuln_pays:
				print("{0}\n".format(i))
			print(Style.RESET_ALL)
			system("modprobe pcspkr")
			system("./ff-victory.sh")
if __name__ == '__main__':
	try:
		main()
	except Exception as e:
		print("[-] " + str(e))
		exit(2)
