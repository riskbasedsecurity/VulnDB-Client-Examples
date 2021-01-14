################################
###
###  This code is intended to provide a general reference only 
###    for accessing vulnerability data
###
################################

import requests
import math

# get `client_id` and `client_secret` by registering an application in the API section of VulnDB
def authenticate():
    token_url = 'https://vulndb.cyberriskanalytics.com/oauth/token'
    data = {
        'grant_type': 'client_credentials',
        'client_id': 'ReplaceMe',
        'client_secret': 'ReplaceMe'
    }

    access_token_response = requests.post(token_url, data=data)
    return access_token_response.json()['access_token']

# no need to touch this function
def call(end, page):
    url = end + str(page)
    access_token = authenticate()
    api_call_headers = {'Authorization': 'Bearer ' + access_token}

    response = requests.get(url, headers=api_call_headers)

    return response.json()

# this will iterate through all vulnerabilities in VulnDB and store each page as "resp"
def load(size):
    end = 'https://vulndb.cyberriskanalytics.com/api/v1/vulnerabilities/1/find_next_to_vulndb_id_full/?size=' + \
        str(size) + '&page='

    total = call(end, 1)['total_entries']

    print('There are', total, 'vulnerabilities.')

    for i in range(1, math.ceil(total / size) + 1):
        print('Pulling page', str(i), '- entries', size *
              i - size + 1, 'to', str(size * i) + '.')

        resp = call(end, i)

# this will iterate through all changed vulnerabilities in x hours and store each page as "resp"
def sync(size, hours):
    end = 'https://vulndb.cyberriskanalytics.com/api/v1/vulnerabilities/find_by_time_full?size=' + \
        str(size) + '&hours_ago=' + str(hours) + '&page='

    total = call(end, 1)['total_entries']

    print('There are', total,
          'new or changed vulnerabilities in the last', hours, 'hour(s).')

    for i in range(1, math.ceil(total / size) + 1):
        print('Pulling page', str(i), '(entries', size *
              i - size + 1, 'to', str(size * i) + ').')

        resp = call(end, i)

sync(100, 1)