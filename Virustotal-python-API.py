import requests
import time
import json
import pandas


file_path = str(input('please Enter The File Path: '))
domain_CSV = pandas.read_csv((file_path))

Urls = domain_CSV['Domain'].tolist()

API_key = 'yourAPIkey'
url = 'https://www.virustotal.com/vtapi/v2/url/report'

for i in Urls:
    parameters = {'apikey': API_key, 'resource': i}

    response= requests.get(url=url, params=parameters)
    json_response= json.loads(response.text)
    if json_response['positives'] <= 0:
        with open('Virustotal Clean result.txt', 'a')  as clean:
            clean.write(i) and clean.write("\tNOT malicious\n")
    else:
        with open('Virustotal Malicious result.txt', 'a')  as malicious:
            malicious.write(i) and malicious.write("\t Malicious\n")

    time.sleep(20)

