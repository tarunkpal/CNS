#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Jul 27 17:58:48 2020

@author: hannousse
"""
from datetime import datetime
from bs4 import BeautifulSoup
import requests
import whois
import time
import re


#################################################################################################################################
#               Domain registration age 
#################################################################################################################################

def domain_registration_length(domain):
    try:
        res = whois.whois(domain)
        expiration_date = res.expiration_date
        today = time.strftime('%Y-%m-%d')
        today = datetime.strptime(today, '%Y-%m-%d')
        # Some domains do not have expiration dates. The application should not raise an error if this is the case.
        if expiration_date:
            if type(expiration_date) == list:
                expiration_date = min(expiration_date)
            return abs((expiration_date - today).days)
        else:
            return 0
    except:
        return -1

def domain_registration_length1(domain):
    v1 = -1
    v2 = -1
    try:
        host = whois.whois(domain)
        hostname = host.domain_name
        expiration_date = host.expiration_date
        today = time.strftime('%Y-%m-%d')
        today = datetime.strptime(today, '%Y-%m-%d')
        if type(hostname) == list:
            for host in hostname:
                if re.search(host.lower(), domain):
                    v1 = 0
            v1= 1
        else:
            if re.search(hostname.lower(), domain):
                v1 = 0
            else:
                v1= 1  
        if expiration_date:
            if type(expiration_date) == list:
                expiration_date = min(expiration_date)
            return abs((expiration_date - today).days)
        else:
            v2= 0
    except:
        v1 = 1
        v2 = -1
        return v1, v2
    return v1, v2

#################################################################################################################################
#               Domain recognized by WHOIS
#################################################################################################################################

 
def whois_registered_domain(domain):
    try:
        hostname = whois.whois(domain).domain_name
        if type(hostname) == list:
            for host in hostname:
                if re.search(host.lower(), domain):
                    return 0
            return 1
        else:
            if re.search(hostname.lower(), domain):
                return 0
            else:
                return 1     
    except:
        return 1

#################################################################################################################################
#               Unable to get web traffic (Page Rank)
#################################################################################################################################
import urllib

def web_traffic(short_url):
        try:
            rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + short_url).read(), "xml").find("REACH")['RANK']
        except:
            return 0
        return int(rank)


#################################################################################################################################
#               Domain age of a url
#################################################################################################################################

import json

import whois
import datetime
import re  # Import re for more robust URL parsing


def domain_age(domain_input):
    """
    Checks the age of a domain using WHOIS lookup.

    Args:
        domain_input (str): The domain name or a URL containing the domain.

    Returns:
        int: The age of the domain in years.
             Returns -1 if the creation date cannot be found or there's a WHOIS error.
             Returns -2 if the domain input is invalid or cannot be parsed.
    """
    # 1. Extract the clean domain name from the input
    # Use re.findall to get all potential domains from the string
    # This regex tries to find a domain-like string (e.g., example.com, sub.domain.co.uk)
    # It handles common URL prefixes (http/https, www) and paths/query strings.
    match = re.findall(r"(?:https?://)?(?:www\.)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?:/.*)?", domain_input)

    if not match:
        print(f"Error: Could not extract a valid domain from '{domain_input}'")
        return -2  # Indicate invalid domain input

    domain = match[0]  # Take the first matched domain

    try:
        w = whois.whois(domain)

        if w.creation_date:
            # The creation_date attribute can sometimes be a list if there are multiple dates.
            # We usually care about the first one (original creation date).
            if isinstance(w.creation_date, list):
                creation_date = w.creation_date[0]
            else:
                creation_date = w.creation_date

            # Ensure it's a datetime object (whois library usually returns this, but good to check)
            if not isinstance(creation_date, datetime.datetime):
                print(f"Warning: Creation date for {domain} is not a datetime object: {creation_date}")
                return -1  # Indicate a parsing issue

            today = datetime.datetime.now()
            age_in_days = (today - creation_date).days

            if age_in_days < 0:  # Future date, implies an error or very strange data
                print(f"Warning: Creation date for {domain} is in the future: {creation_date}")
                return -1

            age_in_years = age_in_days // 365
            return age_in_years
        else:
            # Creation date not found in WHOIS record (might be redacted or missing for some TLDs)
            print(f"Error: Creation date not found for domain '{domain}' in WHOIS record.")
            return -1

    except whois.parser.PywhoisError as e:
        # This handles errors like "No match for domain" or server errors from WHOIS.
        print(f"WHOIS lookup error for '{domain}': {e}")
        return -1
    except Exception as e:
        # Catch any other unexpected errors
        print(f"An unexpected error occurred while checking '{domain}': {e}")
        return -1


#################################################################################################################################
#               Global rank
#################################################################################################################################

def global_rank(domain):
    rank_checker_response = requests.post("https://www.checkpagerank.net/index.php", {
        "name": domain
    })
    
    try:
        return int(re.findall(r"Global Rank: ([0-9]+)", rank_checker_response.text)[0])
    except:
        return -1


#################################################################################################################################
#               Google index
#################################################################################################################################


from urllib.parse import urlencode

def google_index(url):
    #time.sleep(.6)
    user_agent =  'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36'
    headers = {'User-Agent' : user_agent}
    query = {'q': 'site:' + url}
    google = "https://www.google.com/search?" + urlencode(query)
    data = requests.get(google, headers=headers)
    data.encoding = 'ISO-8859-1'
    soup = BeautifulSoup(str(data.content), "html.parser")
    try:
        if 'Our systems have detected unusual traffic from your computer network.' in str(soup):
            return -1
        check = soup.find(id="rso").find("div").find("div").find("a")
        #print(check)
        if check and check['href']:
            return 0
        else:
            return 1
        
    except AttributeError:
        return 1

#print(google_index('http://www.google.com'))
#################################################################################################################################
#               DNSRecord  expiration length
#################################################################################################################################

import dns.resolver

def dns_record(domain):
    try:
        nameservers = dns.resolver.query(domain,'NS')
        if len(nameservers)>0:
            return 0
        else:
            return 1
    except:
        return 1

#################################################################################################################################
#               Page Rank from OPR
#################################################################################################################################


def page_rank(key, domain):
    url = 'https://openpagerank.com/api/v1.0/getPageRank?domains%5B0%5D=' + domain
    try:
        request = requests.get(url, headers={'API-OPR':key})
        result = request.json()
        result = result['response'][0]['page_rank_integer']
        if result:
            return result
        else:
            return 0
    except:
        return -1


