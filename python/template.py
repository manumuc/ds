!/usr/bin/python

DOCUMENTATION = '''
---
module: <name>.py

short_description: <write here shortly what the script is good for i.e. Retrieves IPS rule identifiers coverering a given list of CVEs
                   and sets all the found rules to the computers policy>

description:
     <write here shortly what the script is good for i.e. 
     - "This module retrieves IPS rule identifiers to protect against a list of
       CVEs. The identified rules are set within the policy of the given
       computer object within Deep Security.
       Beware of the fact, that we add any rule even if it requires some
       configuration.>

options:
    --hostName    hostname of the targeted host
    --dsm_url     url of deep security manager
    --api_key     api-key for deep security
    --query       cves to handle

author:
    - Manuela Rotter (manuela_rotter@trendmicro.com)
'''

EXAMPLES = '''
python ds_script.py \
    --dsm_url=https://<URL>:<PORT> \
    --api_key=<API-KEY> \
    --hostname=<hostname> \
    #--query $(./parse.sh qualys_scan.csv)

python s_script.py \
    --dsm_url=https://<URL>:<PORT> \
    --api_key=<API-KEY> \
    --hostname=<hostname> \
    #--query CVE-2017-5715

python s_script.py \
    --dsm_url=https://<URL>:<PORT> \
    --api_key=<API-KEY> \
    --hostname=<hostname> \
    #--query CVE-2016-2118
'''

RETURN = '''
Rules covering CVEs:  set([u'1008828'])
CVEs matched:         set(['CVE-2017-5715'])
CVEs matched count:   1
CVEs unmatched:       set([])
CVEs unmatched count: 0
Accessing computer object for ubuntu1
Ensuring that the rules are set
All set.

Rules covering CVEs:  set([u'1007586', u'1007584', u'1007585', u'1007593', u'1007588'])
CVEs matched:         set(['CVE-2016-2118'])
CVEs matched count:   1
CVEs unmatched:       set([])
CVEs unmatched count: 0
Accessing computer object for ubuntu1
Ensuring that the rules are set
All set.
'''

import ssl
ssl._create_default_https_context = ssl._create_unverified_context
import urllib3
urllib3.disable_warnings()
import sys
import time
#
import pickle
import os
import os.path
import argparse
import requests
import json

'''

 # Constants
    RESULT_SET_SIZE = 1000
    MAX_RULE_ID= 10000

    # Return dictionary
    rules_cves = {}
    
    
url = dsm_url +
api-call = "/api/intrusionprevention/search"

data = ("maxItems": RESULT_SET_SIZE,
                 "searchCriteria": [ { "fieldName": "CVE", "stringTest": "not-equal", "stringValue": "" },
                                     { "fieldName": "ID", "idTest": "greater-than-or-equal", "idValue": i },
                                     { "fieldName": "ID", "idTest": "less-than", "idValue": i + RESULT_SET_SIZE } ] }
        post_header = { "Content-type": "application/json",
                        "api-secret-key": api_key,
                        "api-version": "v1"}
        response = requests.post(url, data=json.dumps(data), headers=post_header, verify=False



def build_rules_cves_map(dsm_url, api_key,dsm_api_call):
def build_rules_cves_map(dsm_url, api_key):
    '''
    Build dictionary of application control whitelist / baseline rules with the ability to cover CVEs
    '''
    # Constants
    RESULT_SET_SIZE = 1000
    MAX_RULE_ID= 10000

    # Return dictionary
    rules_ac = {}

    for i in range(0, MAX_RULE_ID, RESULT_SET_SIZE):
        dsm_api_call = ""/api/intrusionpreventionrules/search""
        url = dsm_url + dsm_api_call
        data = { "maxItems": RESULT_SET_SIZE,
                 "searchCriteria": [ { "fieldName": "CVE", "stringTest": "not-equal", "stringValue": "" },
                                     { "fieldName": "ID", "idTest": "greater-than-or-equal", "idValue": i },
                                     { "fieldName": "ID", "idTest": "less-than", "idValue": i + RESULT_SET_SIZE } ] }
        post_header = { "Content-type": "application/json",
                        "api-secret-key": api_key,
                        "api-version": "v1"}
        response = requests.post(url, data=json.dumps(data), headers=post_header, verify=False).json()

        # Error handling
        if 'message' in response:
            if response['message'] == "Invalid API Key":
                raise ValueError("Invalid API Key")
        if 'intrusionPreventionRules' not in response:
            if 'message' in response:
                raise KeyError(response['message'])
            else:
                raise KeyError(response)

        rules = response['intrusionPreventionRules']

        # Build dictionary ID: CVEs
        for rule in rules:
            cves = set()

            if 'CVE' in rule:
                for cve in rule['CVE']:
                    cves.add(str(cve.strip()))

            cves = sorted(cves)
            rules_cves[str(rule['ID']).strip()] = cves

    return rules_cves
    
def run_module(dsm_url, api_key, hostname, query):

    # Result dictionary
    result = dict(
        changed=False,
        message=''
    )

    #
    # Module logic
    #
    # Build intrusion prevention ips rules CVEs dictionary
    rules_cves = {}
    rules_cves = build_rules_cves_map(dsm_url, api_key)

    # Retrieves intrusion prevention rules based on a list of given CVEs
    rules = set()
    rules_mapping = set()
    matched_list = set()
    unmatched_list = set()
    match_counter = 0
    unmatch_counter = len(query)

    cves_list = {}
    if os.path.isfile('cves_network.cache'):
        with open('cves_network.cache', 'rb') as fp:
            cves_list = pickle.load(fp)

    for cve in query:
        matched = False
        attack_vector = ""
        criticality = ""
        for rule in rules_cves:
            if str(cve) in cves_list:
                attack_vector = " NETWORK"
                criticality = " : " + cves_list[str(cve)]
            if str(cve) in rules_cves[str(rule)]:
                # Query rule identifier
                url = dsm_url + "/api/intrusionpreventionrules/search"
                data = { "maxItems": 1,
                         "searchCriteria": [ { "fieldName": "ID",
                                               "idTest": "equal",
                                               "idValue": str(rule) } ] }
                post_header = { "Content-type": "application/json",
                                "api-secret-key": api_key,
                                "api-version": "v1"}
                response = requests.post(url, data=json.dumps(data), headers=post_header, verify=False).json()
                rules.add(response['intrusionPreventionRules'][0]['identifier'])
                
                rules_mapping.add(response['intrusionPreventionRules'][0]['identifier'] + " (" + str(cve) + ")" + attack_vector + criticality)
                matched_list.add(str(cve) + attack_vector + criticality)
                if (matched == False):
                    match_counter += 1
                    unmatch_counter -= 1
                    matched = True
        if (matched == False):
            unmatched_list.add(str(cve) + attack_vector + criticality)

    # Populate result set
    result['json'] = { "rules_covering": rules,
                       "rules_mapping": rules_mapping,
                       "cves_matched": matched_list,
                       "cves_unmatched": unmatched_list,
                       "cves_matched_count": match_counter,
                       "cves_unmatched_count": unmatch_counter }

    # Return key/value results
    print("Rules covering CVEs:  {}".format(result['json']['rules_covering']))
    print("CVEs matched:         {}".format(result['json']['cves_matched']))
    print("CVEs matched count:   {}".format(result['json']['cves_matched_count']))
    print("CVEs unmatched:       {}".format(result['json']['cves_unmatched']))
    print("CVEs unmatched count: {}".format(result['json']['cves_unmatched_count']))

    print("Accessing computer object for {}".format(hostname))
    computer = search_computer(hostname, dsm_url, api_key)

    print("Ensuring that the rules are set")
    for identifier in result['json']['rules_covering']:
        rule_present(computer, search_ipsrule(identifier, dsm_url, api_key), dsm_url, api_key)

    print("All set.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dsm_url", help="url of deep security manager")
    parser.add_argument("--api_key", help="api-key for deep security")
    parser.add_argument("--hostname", help="hostname of the targeted host")
    # parser.add_argument("--query", nargs='*', type=str, help="cves to handle")
    args = parser.parse_args()
        run_module(args.dsm_url, args.api_key, args.hostname, args.query)

if __name__ == '__main__':
    main()
