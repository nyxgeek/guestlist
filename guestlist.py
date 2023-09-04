#!/usr/bin/env python3
#
# GUESTLIST
# 2023 @nyxgeek - TrustedSec
# check for guest users either silently or via Graph
#   silent - performed via web request, use fireprox to avoid false-positives
#   graph - performed via logon attempt (cannot actually be used to auth or identify password), shows up in logs
#
#
# Thanks to @DrAzureAD, @thetechr0mancer, @ustayready !
# references:
#   https://aadinternals.com/post/desktopsso/ (@DrAzureAD - silent guest enum)
#   https://github.com/blacklanternsecurity/TREVORspray (@thetechr0mancer)
#   https://github.com/ustayready/fireprox (@ustayready)
#
# Update Log
#   23.09.04  1.00 - initial release



import requests
from requests.exceptions import ConnectionError, ReadTimeout, Timeout
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import sqlite3
#import datetime
from datetime import datetime
import os
import sys
import time
import re
import socket
import json
import signal
import argparse
import configparser
#import subprocess
from fire import FireProx

############ OUR CONSTANTS HERE:'
sqldb_location = 'data/guest_enum.db'
outputfilename = "output.log"
hostname = socket.gethostname()
fakeuser = "bingbangbong202320232023@notafakedomain.com"
silent_url = "https://login.microsoftonline.com/common/GetCredentialType"
logon_base = "https://login.microsoftonline.com/"
graph_url = "https://login.microsoftonline.com/common/oauth2/token"

############ NEW GLOBAL VARIABLES HERE:
enable_db = True
exitRequested = False
verbose = False
debug = False
halt_logging = False
isPaused = False
fireprox_threshold = 500
fireprox_enabled = False
fireprox_key = ""
fireprox_secret = ""
fireprox_region = ""
fireprox_command = ""
fireprox_region = "us-east-2" # at some point update this to grab random



print("")
print("*********************************************************************************************************")
print("")
print("                            G U E S T L I S T  v1.00                  ")
print("                                                   ")
print("                           2023 @nyxgeek - TrustedSec                   ")
print("*********************************************************************************************************")
                                                                            
                                                                            

class UrlChecker:
    """Check URLs and handle associated operations."""
    def __init__(self, tenant_name, userdata, enum_method):
        self.tenant_name = tenant_name.rstrip().lower()
        self.userdata = userdata
        self.original_userdata = userdata
        self.enum_method = enum_method
        self.verbose = verbose
        self.debug = debug
        self.errorcount = 0
        self.validcount = 0
        self.currentcount = 0
        self.totalcount = 0
        self.sanitycount = 0
        self.sanitylimit = 100 #this is how many users to try before performing a sanitycheck
        self.start_unix_time = 0
        self.status = '0'
        self.last_5_response_results = []
        self.retest_users_list = []
        #self.current_endpoint = ""
        if enum_method == "graph":
            self.current_endpoint = graph_url
            if fireprox_enabled:
                # do this immediately
                print("firprox is enabled")

                if fireprox_command != "":
                    print("firefox command detected. running now")
                    self.control_fireprox_endpoint("graph", fireprox_command)
                    exit()
                else:
                    self.control_fireprox_endpoint("graph", "create")
                    print("Initial fireprox endpoint has been configured")
        else:
            self.current_endpoint = silent_url
            if fireprox_enabled:
                # do this immediately
                print("firprox is enabled")

                if fireprox_command != "":
                    print("firefox command detected. running now")
                    self.control_fireprox_endpoint("silent", fireprox_command)
                    exit()
                else:
                    self.control_fireprox_endpoint("silent", "create")
                    print("Initial fireprox endpoint has been configured")

    def __delete__(self, instance):
        print("deleted in descriptor object")
        self.control_fireprox_endpoint(self.enum_method,"delete")
        del self.value


    # FireProx connector
    def control_fireprox_endpoint(self, method, command):
        class Object(object):
            pass
 
        fakeargs = Object()
        fakeargs.access_key = fireprox_key
        fakeargs.secret_access_key = fireprox_secret
        fakeargs.region = fireprox_region
        if method == "graph":
            fakeargs.url = logon_base
        else:
            fakeargs.url = logon_base
        if command == "create":
            fakeargs.command = "create"
        elif command == "delete":
            fakeargs.command = "delete"
        elif command == "list":
            fakeargs.command = "list"
        elif command == "renew":
            fakeargs.command = "renew"
        fakeargs.help_text = None
        fakeargs.profile_name = None
        fakeargs.session_token = None
        fakeargs.api_id = None

        if verbose:
            print(f"Command is: {command}, method is {method}")
        fp = FireProx(fakeargs, fakeargs.help_text)


        if command == "create":
            result = fp.list_api()
            if debug:
                print(f"{result}")
            if result:
                print("Hold up - we have an old one in here. Removing first. Waiting 30s")
                extracted_id = result[0].get('id', 'N/A')
                result = fp.delete_api(extracted_id)

            result = fp.create_api(fp.url)
            if debug:
                print(f"{result}")

            result = fp.list_api()
            if debug:
                print(f"{result}")

            extracted_id = result[0].get('id', 'N/A') 
            if verbose:
                print(f"Endpoint ID: {extracted_id}")
                print(f"https://{extracted_id}.execute-api.{fireprox_region}.amazonaws.com/fireprox/")

            if method == "silent":
                self.current_endpoint = f"https://{extracted_id}.execute-api.{fireprox_region}.amazonaws.com/fireprox/common/GetCredentialType"
                if verbose:
                    print(f"Current endpoint: {self.current_endpoint}")

            else: # then it is graph
                self.current_endpoint = f"https://{extracted_id}.execute-api.{fireprox_region}.amazonaws.com/fireprox/common/oauth2/token"



        elif command == "list":
            result = fp.list_api()
            if debug:
                print(f"{result}")
            if result:
                extracted_id = result[0].get('id', 'N/A') 
                if verbose:
                    print(f"Extracted ID: {extracted_id}")
            else:
                print("No endpoints found.")

        elif command == "delete":
            print("Deleting endpoints, please wait...")
            # if we delete too fast we get an error
            time.sleep(5)
            result = fp.list_api()
            if result:
                if verbose:
                    print(f"list result:\n{result}")
                extracted_id = result[0].get('id', 'N/A')
                if verbose:
                    print(f"Extracted ID: {extracted_id}")
                time.sleep(5)
                result = fp.delete_api(extracted_id)
                if debug:
                    print(f"{result}")
                if result:
                    print("SUCCESS - deleted endpoint")
                else:
                    print("FAIL -- did not remove endpoint")
            else:
                if verbose:
                    print("No endpoints to delete")

            
        elif command == "renew":
            print("Renewing endpoints. This will take some time (60s). Pauses built in to handle rate limiting max of 2 api calls/minute")
            result = fp.list_api()
            if debug:
                print(f"{result}")
            extracted_id = result[0].get('id', 'N/A') 
            if verbose:
                print(f"Extracted ID: {extracted_id}")
            print("Deleting endpoint...")
            time.sleep(31)
            result = fp.delete_api(extracted_id)
            if debug:
                print(f"{result}")
            if result:
                print("SUCCESS - deleted endpoint")
            else:
                print("FAIL - did not delete endpoint")
            print("creating new endpoint...")
            time.sleep(31)
            result = fp.create_api(fp.url)
            if debug:
                print(f"{result}")

            result = fp.list_api()
            if debug:
                print(f"{result}")
            extracted_id = result[0].get('id', 'N/A')
            if verbose:
                print(f"Extracted ID: {extracted_id}")
                print(f"https://{extracted_id}.execute-api.{fireprox_region}.amazonaws.com/fireprox/")

            if method == "silent":
                self.current_endpoint = f"https://{extracted_id}.execute-api.{fireprox_region}.amazonaws.com/fireprox/common/GetCredentialType"
                if verbose:
                    print(f"Current endpoint: {self.current_endpoint}")

            else: # then it is graph
                self.current_endpoint = f"https://{extracted_id}.execute-api.{fireprox_region}.amazonaws.com/fireprox/common/oauth2/token"
                

    #>>>>> Database Functions

    def sql_create_table(self):
        #if table does not exist
        #create_onedrive_enum = f"create table guestlist_enum(email_address text, username text, domain text, tenant text, scrape_date_unix int, environment text);"
        create_onedrive_enum = f"create table guestlist_enum(email_address text, source_domain text, target_tenant text, scrape_date_unix int, hostname text, UNIQUE(email_address,target_tenant));"


    def sql_insert_user(self, email_address, source_domain, target_tenant, scrape_date_unix, hostname):
        if not halt_logging:
            try:
                conn = sqlite3.connect(sqldb_location)
                sql_query = f"INSERT OR IGNORE INTO guestlist_enum (email_address, source_domain, target_tenant, scrape_date_unix, hostname) VALUES ('{email_address}', '{source_domain}','{target_tenant}','{scrape_date_unix}','{hostname}');"

                if debug:
                    print(sql_query)
                conn.execute(sql_query)
                conn.commit()
                conn.close()
            except:
                print("Some SQLite error in sql_insert_user! Maybe write some better logging next time.")


    #>>>>> requests special function
    def requests_retry_session(self,
        retries=4,
        backoff_factor=1.5,
        status_forcelist=(500, 502, 504),
        session=None,
        ):
        session = session or requests.Session()
        retry = Retry(
            total=retries,
            read=retries,
            connect=retries,
            backoff_factor=backoff_factor,
            status_forcelist=status_forcelist,
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        return session



    #>>>>> Guest Lookup Functions

    # try a random username and if it is false postivie, stop, or do something
    def sanityCheck(self):
        #test for a fake user
        self.nestoriLookup(fakeuser)


    # method courtesy of @DrAzureAD - https://aadinternals.com/post/desktopsso/
    def nestoriLookup(self,username):
        global halt_logging, isPaused



        #now convert email address to guest account format
        guest_username = f"{username.replace('@','_')}#EXT#@{self.tenant_name}.onmicrosoft.com"

        if debug:
            print(f"Guest Username: {guest_username}")

        headers = {
            "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.141 Safari/537.36",
            "Content-Type":"application/json; charset=UTF-8",
            "Accept-Encoding":"gzip, deflate",
            "Accept-Language":"en-US,en;q=0.9",
            "Connection": "close"
        }
        body = {
            "username":f"{guest_username}",
            "isOtherIdpSupported":"True"
        }

        if debug:
            print(f"DEBUG: {body}")


        try:
            #response = self.requests_retry_session().post(f"https://login.microsoftonline.com/common/GetCredentialType", headers=headers, json=body, timeout=10.0)
            response = self.requests_retry_session().post(f"{self.current_endpoint}", headers=headers, json=body, timeout=10.0)
            if debug:
                print(f"Endpoint: {self.current_endpoint}")
                print(f"Response: {response.content}")


            # Get JSON data from response
            response_data = response.json()

            # Access the value of 'IfExistsResult'
            if_exists_result = response_data.get('IfExistsResult')
            throttle_status = response_data.get('ThrottleStatus')

            if throttle_status == 1:
                # WE ARE THROTTLED!!! STOP - valid results will not show up at this point
                print("ENCOUNTERED THROTTLING!")
                halt_logging = True
                isPaused = True
                
                #update the if_exists_result value to 1
                if_exists_result = 1

            #append result to our last_5_response_results array
            self.last_5_response_results.append(if_exists_result)

            #trim the array down, fifo style
            if len(self.last_5_response_results) > 5:
                self.last_5_response_results.pop(0)

            num_0_responses = self.last_5_response_results.count(0)
            if debug:
                print(f"Number of '0' responses in queue is {num_0_responses}")

            # If 4 or more of the last 5 were 200, stop
            if num_0_responses >= 3:
                halt_logging = True
                isPaused = True
                print("Stopping because 3 or more of the last 5 responses were showing valid (false positives).")




            # a 1 denotes it does not exist
            if if_exists_result == 1:                    
                english_status = "INVALID"

            elif if_exists_result == 0:
                english_status = "VALID USERNAME"
                source_domain = username.split("@")[1]
                currenttime = str(int(time.time()))
                try:
                    self.sql_insert_user(username, source_domain, self.tenant_name, currenttime, hostname)
                except:
                    print("Error running SQL query!")

                # see if it's our fake user that is returning positive
                if username == fakeuser:
                    print(f"DETECTED FALSE POSITIVE at COUNT {self.currentcount}!")
                    halt_logging = True
                    isPaused = True

            else:
                english_status = f"UNKNOWN RESPONSE ({response.status_code})\n{response_data}\n"
            



            if verbose:
                if username != fakeuser:
                    print(f'{username}:{guest_username}:{self.tenant_name}.onmicrosoft.com:{english_status}')

            else:
                if username != fakeuser:
                    print(f'{username}:{self.tenant_name}:{english_status}')



        except Exception as e:
            print("Well, I'm not sure what just happened. Onward we go...")
            print(e)



    def graphLookup(self,username):

        #now convert email address to guest account format
        guest_username = f"{username.replace('@','_')}#EXT#@{self.tenant_name}.onmicrosoft.com"

        if debug:
            print(f"Guest Username: {guest_username}")

        headers = {
            "User-Agent": "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.12026; Pro",
            "Accept": "application/json",
        }
        body = {
            "resource": "https://graph.windows.net",
            "client_id": "72f988bf-86f1-41af-91ab-2d7cd011db42",
            "client_info": '1',
            "grant_type": "password",
            "username": guest_username,
            "password": "FAKEPASS_72f988bf-86f1-41af-91ab-2d7cd011db42_NOT_REAL_CANT_LOGIN_THIS_WAY",
            "scope": "openid"
        }
        codes = {
            0: ['AADSTS50034'], # INVALID USERNAME
            1: ['AADSTS50126'], # VALID USERNAME, INVALID PASSWORD
            3: ['AADSTS50079', 'AADSTS50076'], # MICROSOFT MFA
            4: ['AADSTS50158'], # OTHER MFA
            5: ['AADSTS50053'], # SMART LOCKOUT
            6: ['AADSTS50057'], # DISABLED
            7: ['AADSTS50055'], # EXPIRED
            8: ['AADSTS50128', 'AADSTS50059'], # INVALID TENANT
            9: ['AADSTS700016'] # VALID USER/PASS
        }

        state = -1

        try:
            #response = self.requests_retry_session().post(f"https://login.microsoftonline.com/common/oauth2/token", headers=headers, data=body, timeout=10.0)
            response = self.requests_retry_session().post(f"{self.current_endpoint}", headers=headers, data=body, timeout=10.0)

            if response.status_code == 200:
                state = 2
            else:
                respErr = response.json()['error_description']
                for k, v in codes.items():
                    if any(e in respErr for e in v):
                        state = k
                        break
                if state == -1:
                    #logging.info(f"UNKERR: {respErr}")
                    print(f"UNKERR: {respErr}")

            # Call the login function
            status = state
            if status == 9:
                english_status = "VALID ACCOUNT CREDS"
            elif status == 1:
                english_status = "VALID USERNAME"
            elif status == 5:
                english_status = "SMART LOCKOUT"
            elif status == 6:
                english_status = "DISABLED"
            elif status == 7:
                english_status = "EXPIRED - UPDATE PASSWORD"
            else:
                english_status = "INVALID"

            if verbose:
                print(f'{username}:{guest_username}:{self.tenant_name}.onmicrosoft.com:{english_status}')

            else:
                print(f'{username}:{self.tenant_name}:{english_status}')



            if status == 1:
                #print("WE HAVE A STATUS 1")
                currenttime = str(int(time.time()))
                source_domain = username.split("@")[1]
                sql_query=f"{username}, {source_domain}, {self.tenant_name}, {currenttime}, {hostname}"
                if verbose:
                    print(sql_query)
                try:
                    self.sql_insert_user(username, source_domain, self.tenant_name, currenttime,hostname)
                except:
                    print("Error running SQL query!")


            if status == 5:
                #global tenant_endpoint
                tenant_endpoint = random.choice(tenant_array)

        except Exception as e:
            print("Well, I'm not sure what just happened. Onward we go...")
            print(e)




    def check_url(self, username):
        """Check a URL and handle associated operations."""


        #increment our number
        self.currentcount+=1

        if fireprox_enabled:
            # see if we are at our fireprox_threshold yet - and if so, renew IP
            if self.currentcount % fireprox_threshold == 0:
                print(f"Currently at {self.currentcount} / {fireprox_threshold}")
                print("DING DING - triggered our fireprox renewal")
                self.control_fireprox_endpoint(self.enum_method, "renew")       


        if debug:
            print(f"Our CURRENT COUNT IS {self.currentcount} and the sanitylimit is {self.sanitylimit}")

        #remove any return char and lowercase the username
        username = (username.rstrip()).lower()
        if not ( "@" in username ):
            if verbose:
                print("Username is not in email address format")
            pass
        else:
            # HERE WE WILL THEN CALL EITHER OUR SILENT OR GRAPH LOOKUP
            if self.enum_method == "graph":
                self.graphLookup(username)
                exit
            if self.enum_method == "silent":
                # see if we are divisible by our sanitylimit - if so, do sanitycheck
                if self.currentcount % self.sanitylimit == 0:
                    self.sanityCheck()

                self.nestoriLookup(username)
                exit




    def check_user(self):
        """Check a specific user."""
        print("In check_user")
        self.check_url(self.userdata)

    def check_user_file(self):
        global isPaused
        """Check all users from a file."""
        if verbose:
            print("Our file is {}".format(self.userdata))
        
        if verbose:
            print(f"\nENUM METHOD: {self.enum_method}")

        print(f"\n")
        print("---------------------------------------------------------------------------------------------------------")



        f = open(self.userdata)
        for userline in f:
            if exitRequested:
                print("\nOkay, exiting now\n")
                sys.exit(0)

            if isPaused and fireprox_enabled:
                #get new fireprox if possible
                print("getting new fireprox... stand by")
                isPaused = False
                self.control_fireprox_endpoint(self.enum_method, "renew")
                print("Pausing for 15 seconds before resuming")
                time.sleep(15)
                print("okay go")

            self.check_url(userline,)


        f.close()
        if fireprox_enabled:
            try:
                self.control_fireprox_endpoint(self.enum_method, "delete")
            except:
                pass
        print("\n\nGuest Enumeration Complete\n")





# look up tenant if it's missing
def lookup_tenant(domain):
    #identify primary tenant(s)
    # will always display list of alternate tenants
    # this will pick one based on mail.onmicrosoft.com record, or failing that, matching domain that was given.

    if verbose:
        print(f"Performing lookup for {domain}")

    def resolve_hostname(hostname):
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None

    # this lookup trick is from AADInternals and TREVORspray
    url = f'https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc'
    headers = { 'Content-Type': 'text/xml; charset=utf-8',
            'SOAPAction': '"http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation"',
            'User-Agent' : 'AutodiscoverClient',
            'Accept-Encoding' : 'identity'
    }
    xml = f'<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><soap:Header><a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action><a:To soap:mustUnderstand="1">https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc</a:To><a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo></soap:Header><soap:Body><GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover"><Request><Domain>{domain}</Domain></Request></GetFederationInformationRequestMessage></soap:Body></soap:Envelope>'
    #print(xml)

    tenant_list = []
    mail_list = []
    onedrive_list = []

    try:
        r = requests.post(url, data=xml, headers=headers, timeout=8.0)
        domain_extract = re.findall('<Domain>(.*?)<\/Domain>', r.content.decode('utf-8'))
        tenant_extract = [i for i, x in enumerate(domain_extract) if ".onmicrosoft.com" in x and ".mail.onmicrosoft.com" not in x] # this line gets the matching list item numbers only
        if ( len(tenant_extract) > 0):
            print(f"\nTenants Identified:\n---------------------")
            for found_tenant in tenant_extract:
                cleaned_tenant = (domain_extract[found_tenant]).replace('.onmicrosoft.com','').lower()
                print(f'{cleaned_tenant}')
                tenant_list.append(cleaned_tenant)
            print("")
        else:
            print("No tenants found. Exiting.")
            exit()

        mail_extract = [i for i, x in enumerate(domain_extract) if ".mail.onmicrosoft.com" in x] # this line gets the matching list item numbers only
        if ( len(mail_extract) > 0):
            if verbose:
                print(f"\nMail records identified:\n---------------------")
            for found_tenant in mail_extract:
                cleaned_mail = (domain_extract[found_tenant]).replace('.mail.onmicrosoft.com','').lower()
                if verbose:
                    print(f'{cleaned_mail}')
                mail_list.append(cleaned_mail)

        for test_tenant in tenant_list:
            test_hostname = f'{test_tenant}-my.sharepoint.com'
            if verbose:
                print(f"Testing {test_hostname}")
            if resolve_hostname(test_hostname):
                onedrive_list.append(test_tenant)
        #print(onedrive_list)
        if ( len(onedrive_list) > 0 ):
            print(f"OneDrive hosts found:\n---------------------")
            for onedrive_host in onedrive_list:
                print(f"{onedrive_host}-my.sharepoint.com")
            print("\n")
            if len(onedrive_list) == 1:
                tenantname = onedrive_list[0]
            else:       #list is longer than 1, so iterated
                # we want to see if any of our onedrive URLs match the mail server address
                #matching_mail =  (any(item in onedrive_list for item in mail_list)):
                matching_mail =  list(set(onedrive_list) & set(mail_list))
                if matching_mail:
                    if verbose:
                        print("INFO: Found matching mail record shared with onedrive URL. This is probably it. If you do not get results, re-run and manually choose a different tenant")
                    #print(matching_mail)
                    tenantname = matching_mail[0]
                else:
                    print("Could not reliably determine the primary domain. Try specifying different ones using the '-t' flag until you find it.")
                    for tenant in tenant_list:
                        print(f"{tenant}")
            #print("--------------------------------------------------------------------------------------------------------")
            print(f"++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")

            if verbose:
                print(f"INFO: Tenant name has been set to: {tenantname}")
            return tenantname

        else:
            print(f"ERROR: NO ONEDRIVE DETECTED!")
            exit()
    except requests.exceptions.HTTPError as errh:
        print ("Http Error:",errh)
    except requests.exceptions.ConnectionError as errc:
        print ("Error Connecting:",errc)
    except requests.exceptions.Timeout as errt:
        print ("Timeout Error:",errt)
    except requests.exceptions.RequestException as err:
        print ("OOps: Something Else",err)

# handle ctrl-c with log file
# stole from https://stackoverflow.com/questions/1112343/how-do-i-capture-sigint-in-python
def signal_handler(sig, frame):
    global exitRequested
    print("\nCTRL-C Detected.")
    # see if this is our first or if we already tried quitting
    # if it's our second time hitting ctrl-c, then close immediately, otherwise wait for graceful
    #print("\nExit status is: {0}\n".format(exitRequested))
    if exitRequested:
        
        sys.exit(1)
    else:
        #global exitRequested
        exitRequested = True


def export_sql_users():
    if enable_db:
        if verbose:
            print("Exporting users")
        try:
            conn = sqlite3.connect(sqldb_location)


            ##### FIX THIS
            getUsersQuery = f"SELECT * FROM guestlist_enum;"
            #print(getUsersQuery)
            result = conn.execute(getUsersQuery)
            #resultcount = len(result.fetchall())
            export_results = result.fetchall()
            resultcount = len(export_results)
            conn.commit()
            #print(result.fetchall())
            now = datetime.now()
            formatted_date = now.strftime("%Y%m%d")
            output_filename = f'export_guestlist_{formatted_date}.txt'
            with open(output_filename, 'w') as f:  # 'w' means write mode which overwrites existing contents
                for user in export_results:
                    f.write(user[0] + '\n')  # write each email on a new line
            conn.close()
            print(f"{resultcount} guestlist lines have been written to {output_filename}")
        except sqlite3.Error as er:
            print("Some SQLite error in export_sql_users()! Maybe write some better logging next time.")
            print('SQLite error: %s' % (' '.join(er.args)))
            print("Exception class is: ", er.__class__)
            print('SQLite traceback: ')
            exc_type, exc_value, exc_tb = sys.exc_info()
            print(traceback.format_exception(exc_type, exc_value, exc_tb))

def main():
    global enable_db, verbose, debug, fireprox_enabled, fireprox_key, fireprox_secret, fireprox_region, fireprox_command

    #set up our ctrl-c checker
    signal.signal(signal.SIGINT, signal_handler)

    # define our variables
    exitRequested = False

    
    # initiate the parser
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--method", help="silent or interactive (default:silent)", required=False, metavar='')
    parser.add_argument("-d", "--domain", help="target domain name (required)", required=False, metavar='')
    parser.add_argument("-t", "--tenant", help="tenant name if known, otherwise specify domain and will lookup", metavar='')
    parser.add_argument("-u", "--username", help="email address to target", metavar='')
    parser.add_argument("-U", "--userfile", help="file containing usernames (wordlists) -- will also take a directory", metavar='')
    parser.add_argument("-o", "--output", help="file to write output to (default: output.log)", default="output.log", metavar='')
    parser.add_argument("-n", "--no-db", help="disable logging to db", action='store_true', default=False)
    parser.add_argument("-v", "--verbose", help="enable verbose output", action='store_true', default=False)
    parser.add_argument("-D", "--debug", help="enable debug output", action='store_true', default=False)
    parser.add_argument("-a", "--access", help="fireprox AWS access_key", metavar='')
    parser.add_argument("-s", "--secret", help="fireprox AWS secret key", metavar='')
    parser.add_argument("-f", "--credfile", help="fireprox - file containing aws_secret and aws_key values", metavar='')
    parser.add_argument("-r", "--region", help="fireprox AWS region", metavar='')
    parser.add_argument("-c", "--command",  help="fireprox command (create, delete, list)", metavar='')


    # read arguments from the command line
    args = parser.parse_args()

    verbose = args.verbose
    debug = args.debug
    isUser = False
    isUserFile = False
    enum_method = "silent"

    if verbose:
        print("Verbose is ON")

    if debug:
        print("Debug is ON")

    if (args.access and args.secret):
        fireprox_enabled = True
        fireprox_key = args.access.rstrip()
        fireprox_secret = args.secret.rstrip()
    elif (args.access or args.secret or args.region):
        print("You have not specified all required values for fireprox: --access, --secret, and --region")
        print(" **** WARNING: FIREPROX IS NOT ENABLED. Waiting for 10 seconds before continuing ...  ****")
        time.sleep(10)

    if args.command:
        fireprox_command = args.command.rstrip()

    if args.method:
        if args.method == "silent":
            enum_method = "silent"
        elif args.method == "interactive":
            enum_method = "graph"
        elif args.method == "graph":
            enum_method = "graph"
        elif args.method == "nestori":
            enum_method = "silent"
        else:
            print("Please select either silent or interactive")
            exit
        if verbose:
            print(f"Method is: {enum_method}")


    if args.domain:
        tenantname = (lookup_tenant(args.domain)).lower()
        if verbose:
            print(f"Tenant name for {args.domain} is {tenantname}")


    if args.tenant:
        tenantname = (args.tenant).lower()
        if verbose:
            print("Tenant is: %s" % args.tenant)


    if args.username:
        print("Checking username: %s" % args.username)
        isUser = True

    if args.userfile:
        if verbose:
            print("Checking file: %s" % args.userfile)
        userfile = args.userfile
        isUserFile = True

    if args.credfile:
        credfile = args.credfile
        if verbose:
            print(f"Cred file: {credfile}")
                
        config = configparser.ConfigParser()

        # check if file exists
        try:
            with open(credfile) as f:
                config.read_file(f)
        except IOError:
            raise MyError()


        # parse for key
        fireprox_key = config.get('default', 'aws_access_key_id')
        # then parse for aws_secret
        fireprox_secret = config.get('default', 'aws_secret_access_key')
        if verbose:
            print(f"key: {fireprox_key}")
            print(f"secret: {fireprox_secret}")
        fireprox_enabled = True


    outputfilename = args.output
    if verbose:
        print(f"Output file: {outputfilename}")

    if args.no_db:
        enable_db = False
    else:
        enable_db = True

    if verbose:
        print(f"Enable DB is: {enable_db}")



    # Here we see what type of input it is: username, userfile, user directory, playlist -- and process accordingly
    if isUser:
        if verbose:
            print("We are checking on a username")
        userdata = args.username
        try:
            url_checker = UrlChecker(tenantname, userdata, enum_method)
            url_checker.check_user()
        except:
            if verbose:
                print("Error with username")
            pass
        finally:
            if fireprox_enabled:
                print("Attempting to delete endpoints")
                try:
                    result = url_checker.control_fireprox_endpoint(enum_method,"delete")
                except:
                    pass
            try:
                del url_checker
            except:
                pass





    if isUserFile:
        userdata = userfile
        #first check for file or folder status
        if os.path.exists(userfile):    #first see if it exists
            if os.path.isfile(userfile):    #then see if it's a file
                try:
                    url_checker = UrlChecker(tenantname, userdata, enum_method)
                    url_checker.check_user_file()
                except Exception as userfileerror:
                    print(userfileerror)
                    if verbose:
                        print("Whoops something happened there with a userfile")
                    pass
                finally:
                    if fireprox_enabled:
                        #do a final cleanup
                        try:
                            if verbose:
                                print("Attempting to delete endpoints")
                            result = url_checker.control_fireprox_endpoint(enum_method,"delete") 
                        except:
                            pass
                    try:
                        del url_checker
                    except:
                        pass
                #print("Completed")

                # do our export now
                export_sql_users()


        else:
            print(f"ERROR: {userfile} does not exist.")
            exit()



if __name__ == "__main__":
    main()