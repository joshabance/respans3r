"""
	ResPans3r v0.1 - HEADER RESPONSE GRABBER
		by: Anna Kushina
"""
# import system utilities
import os, sys, platform

import socket
#import requests
from requests import get as respGetter

#colorama for beautiful looking ui
from colorama import init 
from colorama import Fore, Style

#initialize colorama
init()

#main class
class Respanser():
	def __init__(self, baseUrl):
		super(Respanser, self).__init__()
		self.__baseUrl = baseUrl
		if self.__baseUrl.startswith("http://") or self.__baseUrl.startswith("https://"):
			self.__mainUrl = self.__baseUrl
		else:
			self.__mainUrl = "http://" + self.__baseUrl
	def runGetResp(self):
		headersRaw = respGetter(self.__mainUrl).headers
		try:
			hDate = headersRaw['Date']
		except KeyError:
			hDate = False
		try:
			hExpires = headersRaw['Expires']
		except KeyError:
			hExpires = False
		try:
			hCacheControl = headersRaw['Cache-Control']
		except KeyError:
			hCacheControl = False
		try:
			hContentType = headersRaw['Content-Type']
		except KeyError:
			hContentType = False
		try:
			hP3P = headersRaw['P3P']
		except KeyError:
			hP3P = False
		try:
			hContentEncoding = headersRaw['Content-Encoding']
		except KeyError:
			hContentEncoding = False
		try:
			hServer = headersRaw['Server']
		except KeyError:
			hServer = False
		try:
			hAltSvc = headersRaw['Alt-Svc']
		except:
			hAltSvc = False
		try:
			hAllow = headersRaw['Allow']
		except KeyError:
			hAllow = False
		try:
			hAccessControlAllowCredentials = headersRaw['Access-Control-Allow-Credentials']
		except KeyError:
			hAccessControlAllowCredentials = None
		try:
			hAccessControlAllowHeaders = headersRaw['Access-Control-Allow-Headers']
		except KeyError:
			hAccessControlAllowHeaders = False
		try:
			hAccessControlAllowMethods = headersRaw['Access-Control-Allow-Methods']
		except KeyError:
			hAccessControlAllowMethods = False
		try:
			hAccessControlAllowOrigin = headersRaw['Access-Control-Allow-Origin']
		except KeyError:
			hAccessControlAllowOrigin = False
		try:
			hAccessControlExposeHeaders = headersRaw['Access-Control-Expose-Headers']
		except KeyError:
			hAccessControlExposeHeaders = False
		try:
			hAccessControlMaxAge = headersRaw['Access-Control-Max-Age']
		except KeyError:
			hAccessControlMaxAge = False
		try:
			hAcceptRanges = headersRaw['Accept-Ranges']
		except KeyError:
			hAcceptRanges = False
		try:
			hAge = headersRaw['Age']
		except KeyError:
			hAge = False
		try:
			hAlternateProtocol = headersRaw['Alternate-Protocol']
		except KeyError:
			hAlternateProtocol = False
		try:
			hConnection = headersRaw['Connection']
		except KeyError:
			hConnection = False
		try:
			hContentLanguage = headersRaw['Content-Language']
		except KeyError:
			hContentLanguage = False
		try:
			hContentLength = headersRaw['Content-Length']
		except KeyError:
			hContentLength = False
		try:
			hContentRange = headersRaw['Content-Range']
		except KeyError:
			hContentRange = False
		try:
			hContentDisposition = headersRaw['Content-Disposition']
		except KeyError:
			hContentDisposition = False
		try:
			hHTTP = headersRaw['HTTP']
		except KeyError:
			hHTTP = False
		try:
			hLastModified = headersRaw['Last-Modified']
		except KeyError:
			hLastModified = False
		try:
			hPragma = headersRaw['Pragma']
		except KeyError:
			hPragma = False
		try:
			hProxyAuthenticate = headersRaw['Proxy-Authenticate']
		except KeyError:
			hProxyAuthenticate = False
		try:
			hProxyConnection = headersRaw['Proxy-Connection']
		except KeyError:
			hProxyConnection = False
		try:
			hSetCookie = headersRaw['Set-Cookie']
		except KeyError:
			hSetCookie = False
		try:
			hStatus = headersRaw['Status']
		except KeyError:
			hStatus = False
		try:
			hStrictTransportSecurity = headersRaw['Strict-Transport-Security']
		except KeyError:
			hStrictTransportSecurity = False
		try:
			hTransferEncoding = headersRaw['Transfer-Encoding']
		except KeyError:
			hTransferEncoding = False
		try:
			hUpgrade = headersRaw['Upgrade']
		except KeyError:
			hUpgrade = False
		try:
			hVary = headersRaw['Vary']
		except KeyError:
			hVary = False
		try:
			hVia = headersRaw['Via']
		except KeyError:
			hVia = False
		try:
			hWarning = headersRaw['Warning']
		except KeyError:
			hWarning = False
		try:
			hWWWAuthenticate = headersRaw['WWW-Authenticate']
		except KeyError:
			hWWWAuthenticate = False
		try:
			hXAspnetVersion = headersRaw['X-Aspnet-Version']
		except KeyError:
			hXAspnetVersion = False
		try:
			hXContentTypeOptions = headersRaw['X-Content-Type-Options']
		except KeyError:
			hXContentTypeOptions = False
		try:
			hXFrameOptions = headersRaw['X-Frame-Options']
		except KeyError:
			hXFrameOptions = False
		try:
			hXPermittedCrossDomainPolicies = headersRaw['X-Permitted-Cross-Domain-Policies']
		except KeyError:
			hXPermittedCrossDomainPolicies = False
		try:
			hXPingback = headersRaw['X-Pingback']
		except KeyError:
			hXPingback = False
		try:
			hXPoweredBy = headersRaw['X-Powered-By']
		except KeyError:
			hXPoweredBy = False
		try:
			hXRobotsTag = headersRaw['X-Robots-Tag']
		except KeyError:
			hXRobotsTag = False
		try:
			hXUACompatible = headersRaw['X-UA-Compatible']
		except KeyError:
			hXUACompatible = False
		try:
			hXXSSProtection = headersRaw['X-XSS-Protection']
		except KeyError:
			hXXSSProtection = False

		print(Fore.BLUE + "\n\n\t\t [i] Domain / URL:" + Fore.MAGENTA, self.__baseUrl)
		print(Fore.LIGHTMAGENTA_EX + "\n\t\t [+]---------------  RESPONSE  ---------------[+]")

		if hAccessControlAllowCredentials != None:
			print(Fore.YELLOW + "\t\t  [i] Access-Control-Allow-Credentials:" + Fore.MAGENTA, hAccessControlAllowCredentials)
		else:
			pass
		if hAccessControlAllowHeaders != False:
			print(Fore.YELLOW + "\t\t  [i] Access-Control-Allow-Headers:" + Fore.MAGENTA, hAccessControlAllowHeaders)
		else:
			pass
		if hAccessControlAllowMethods != False:
			print(Fore.YELLOW + "\t\t  [i] Access-Control-Allow-Methods:" + Fore.MAGENTA, hAccessControlAllowMethods)
		else:
			pass
		if hAccessControlAllowOrigin != False:
			print(Fore.YELLOW + "\t\t  [i] Access-Control-Allow-Origin:" + Fore.MAGENTA, hAccessControlAllowOrigin)
		else:
			pass
		if hAccessControlExposeHeaders != False:
			print(Fore.YELLOW + "\t\t  [i] Access-Control-Expose-Headers:" + Fore.MAGENTA, hAccessControlExposeHeaders)
		else:
			pass
		if hAccessControlMaxAge != False:
			print(Fore.YELLOW + "\t\t  [i] Access-Control-Max-Age:" + Fore.MAGENTA, hAccessControlMaxAge)
		else:
			pass
		if hAcceptRanges != False:
			print(Fore.YELLOW + "\t\t  [i] Accept-Ranges:" + Fore.MAGENTA, hAcceptRanges)
		else:
			pass
		if hAge != False:
			print(Fore.YELLOW + "\t\t  [i] Age:" + Fore.MAGENTA, hAge)
		else:
			pass
		if hAltSvc != False:
			print(Fore.YELLOW + "\t\t  [i] Alt-Svc:" + Fore.MAGENTA, hAltSvc)
		else:
			pass
		if hAllow != False:
			print(Fore.YELLOW + "\t\t  [i] Allow:" + Fore.MAGENTA, hAllow)
		else:
			pass
		if hAlternateProtocol != False:
			print(Fore.YELLOW + "\t\t  [i] Alternate-Protocol:" + Fore.MAGENTA, hAlternateProtocol)
		else:
			pass
		if hCacheControl != False:
			print(Fore.YELLOW + "\t\t  [i] Cache-Control:" + Fore.MAGENTA, hCacheControl)
		else:
			pass
		if hConnection != False:
			print(Fore.YELLOW + "\t\t  [i] Connection:" + Fore.MAGENTA, hConnection)
		else:
			pass
		if hContentEncoding != False:
			print(Fore.YELLOW + "\t\t  [i] Content-Encoding:" + Fore.MAGENTA, hContentEncoding)
		else:
			pass
		if hContentLength != False:
			print(Fore.YELLOW + "\t\t  [i] Content-Length:" + Fore.MAGENTA, hContentLength)
		else:
			pass
		if hContentLanguage != False:
			print(Fore.YELLOW + "\t\t  [i] Content-Language:" + Fore.MAGENTA, hContentLanguage)
		else:
			pass
		if hContentRange != False:
			print(Fore.YELLOW + "\t\t  [i] Content-Range:" + Fore.MAGENTA, hContentRange)
		else:
			pass
		if hContentType != False:
			print(Fore.YELLOW + "\t\t  [i] Content-Type:" + Fore.MAGENTA, hContentType)
		else:
			pass
		if hContentDisposition != False:
			print(Fore.YELLOW + "\t\t  [i] Content-Disposition:" + Fore.MAGENTA, hContentDisposition)
		else:
			pass
		if hDate != False:
			print(Fore.YELLOW + "\t\t  [i] Date:" + Fore.MAGENTA, hDate)
		else:
			pass
		if hExpires != False:
			print(Fore.YELLOW + "\t\t  [i] Expires:" + Fore.MAGENTA, hExpires)
		else:
			pass
		if hHTTP != False:
			print(Fore.YELLOW + "\t\t  [i] HTTP:" + Fore.MAGENTA, hHTTP)
		else:
			pass
		if hLastModified != False:
			print(Fore.YELLOW + "\t\t  [i] Last-Modified: " + Fore.MAGENTA, hLastModified)
		else:
			pass
		if hPragma != False:
			print(Fore.YELLOW + "\t\t  [i] Pragma:")
		else:
			pass
		if hP3P != False:
			print(Fore.YELLOW + "\t\t  [i] P3P:" + Fore.MAGENTA, hP3P)
		else:
			pass
		if hProxyAuthenticate != False:
			print(Fore.YELLOW + "\t\t  [i] Proxy-Authenticate:" + Fore.MAGENTA, hProxyAuthenticate)
		else:
			pass
		if hProxyConnection != False:
			print(Fore.YELLOW + "\t\t  [i] Proxy-Connection:" + Fore.MAGENTA, hProxyAuthenticate)
		else:
			pass
		if hServer != False:
			print(Fore.YELLOW + "\t\t  [i] Server:" + Fore.MAGENTA, hServer)
		else:
			pass
		if hStatus != False:
			print(Fore.YELLOW + "\t\t  [i] Status:" + Fore.MAGENTA, hStatus)
		else:
			pass
		if hStrictTransportSecurity != False:
			print(Fore.YELLOW + "\t\t  [i] Strict-Transport-Security:" + Fore.MAGENTA, hStrictTransportSecurity)
		else:
			pass
		if hTransferEncoding != False:
			print(Fore.YELLOW + "\t\t  [i] Transfer-Encoding:" + Fore.MAGENTA, hTransferEncoding)
		else:
			pass
		if hUpgrade != False:
			print(Fore.YELLOW + "\t\t  [i] Upgrade:" + Fore.MAGENTA, hUpgrade)
		else:
			pass
		if hVary != False:
			print(Fore.YELLOW + "\t\t  [i] Vary:" + Fore.MAGENTA, hVary)
		else:
			pass
		if hVia != False:
			print(Fore.YELLOW + "\t\t  [i] Via:" + Fore.MAGENTA, hVia)
		else:
			pass
		if hWarning != False:
			print(Fore.YELLOW + "\t\t  [i] Warning:" + Fore.MAGENTA, hWarning)
		else:
			pass
		if hWWWAuthenticate != False:
			print(Fore.YELLOW + "\t\t  [i] WWW-Authenticate:" + Fore.MAGENTA, hWWWAuthenticate)
		else:
			pass
		if hXAspnetVersion != False:
			print(Fore.YELLOW + "\t\t  [i] X-Aspnet-Version:" + Fore.MAGENTA, hXAspnetVersion)
		else:
			pass
		if hXContentTypeOptions != False:
			print(Fore.YELLOW + "\t\t  [i] X-Content-Type-Options:" + Fore.MAGENTA, hXContentTypeOptions)
		else:
			pass
		if hXFrameOptions != False:
			print(Fore.YELLOW + "\t\t  [i] X-Frame-Options:" + Fore.MAGENTA, hXFrameOptions)
		else:
			pass
		if hXPermittedCrossDomainPolicies != False:
			print(Fore.YELLOW + "\t\t  [i] X-Permitted-Cross-Domain-Policies:" + Fore.MAGENTA, hXPermittedCrossDomainPolicies)
		else:
			pass
		if hXPingback != False:
			print(Fore.YELLOW + "\t\t  [i] X-Pingback:" + Fore.MAGENTA, hXPingback)
		else:
			pass
		if hXPoweredBy != False:
			print(Fore.YELLOW + "\t\t  [i] X-Powered-By:" + Fore.MAGENTA, hXPoweredBy)
		else:
			pass
		if hXRobotsTag != False:
			print(Fore.YELLOW + "\t\t  [i] X-Robots-Tag:" + Fore.MAGENTA, hXRobotsTag)
		else:
			pass
		if hXUACompatible != False:
			print(Fore.YELLOW + "\t\t  [i] X-UA-Compatible:" + Fore.MAGENTA, hXUACompatible)
		else:
			pass
		if hXXSSProtection != False:
			print(Fore.YELLOW + "\t\t  [i] X-XSS-Protection:" + Fore.MAGENTA, hXXSSProtection)
		else:
			pass
		print(Fore.LIGHTMAGENTA_EX + "\t\t [+]---------------  RESPONSE  ---------------[+]" + Style.RESET_ALL)
def checkUrl(rUrl):
	if rUrl.isalpha() or rUrl.isalnum():
		return False
	else:
		return True
		
def main():
	print(Fore.LIGHTGREEN_EX + banner() + Style.RESET_ALL)
	print(Fore.CYAN + "\n\t Enter the DOMAIN / Website URL (ex: www.google.com)")
	print(Fore.LIGHTCYAN_EX + "\n\t  Type 'exit' or '00' to exit the script...")
	reqUrl = 'www.google.com'
	try:
		while reqUrl != '00' or reqUrl != 'exit':
			print(Fore.GREEN)
			reqUrl = input("\n\t\t  [resPan3r] ~#: ")
			if reqUrl == '00' or reqUrl == 'exit':
				checkOs()
				print(Fore.YELLOW + "\n\t\t  [ok] Exiting...")
				sys.exit(0)
			elif reqUrl == "" or reqUrl == None:
				pass # do nothing
			else:
				if checkUrl(reqUrl) == False:
					print(Fore.RED + "\n\t\t [!] Invalid DOMAIN or Website URL! Try Again...")
				else:
					respTemp = Respanser(reqUrl)
					respTemp.runGetResp()
	except KeyboardInterrupt:
		checkOs()
		print(Fore.YELLOW + "\n\t\t  [ok] Exiting...")
		sys.exit(0)
	except EOFError:
		checkOs()
		print(Fore.YELLOW + "\n\t\t  [ok] Exiting...")
		sys.exit(0)


def checkNet():
	try:
        # connect to the host -- tells us if the host is actually reachable
        # use two process connection
		socket.create_connection(("www.google.com", 80))
		socket.create_connection(("www.facebook.com", 443))
		return True
	except OSError:
		pass
	return False

def checkOs():
	if platform.system() == "Windows":
		os.system("cls")
	else:
		os.system("clear")

def banner():
 	__mainBanner = """

		    ____                                  _____     
		   / __ \___  _________  ____ _____  ____|__  /_____
		  / /_/ / _ \/ ___/ __ \/ __ `/ __ \/ ___//_ </ ___/
		 / _, _/  __(__  ) /_/ / /_/ / / / (__  )__/ / /    
		/_/ |_|\___/____/ .___/\__,_/_/ /_/____/____/_/     
		               /_/                              

				ResP4ns3r - HTTP Response Grabber v0.1   

 	"""
 	return __mainBanner

if __name__ == '__main__':
	if checkNet() == True:
		checkOs()
		main()
	else:
		print(Fore.LIGHTRED_EX + "\n\t [!] An INTERNET Connection is required by this script to run!")