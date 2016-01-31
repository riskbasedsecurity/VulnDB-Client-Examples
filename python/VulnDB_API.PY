from __future__ import print_function
from restkit import OAuthFilter, request
import oauth2, json
from pprint import pprint
import sys
import codecs
import locale
from datetime import date, timedelta

today = date.today()
yesterday = date.today() - timedelta(1)

sys.stdout = codecs.getwriter(locale.getpreferredencoding())(sys.stdout)

url = 'https://vulndb.cyberriskanalytics.com/api/v1/vulnerabilities/q?start_date=' + yesterday.strftime('%Y-%m-%d') + '&size=100'

consumer = oauth2.Consumer(key='CONSUMERKEY',secret='SECRET')
auth = OAuthFilter('*',consumer)
resp = request(url, filters=[auth])
print (resp.status_int)
if (resp.status_int != 200):
    sys.exit(0)	
data = json.loads(resp.body_string())

header = ["osvdb_id", "title", "keywords", "description", "solution", "vulndb_last_modified", "solution_date", "disclosure_date", "discovery_date", "exploit_publish_date", "vendor_informed_date", "vendor_ack_date", "third_party_solution_date",
"Nessus Script ID", "Snort Signature ID", "CVE ID", "Bugtraq ID", "Microsoft Security Bulletin", "Generic Exploit URL", "Vendor Specific Advisory URL",
"Vendor Specific Solution URL", "Keyword", "Generic Informational URL", "Related OSVDB ID", "ISS X-Force ID", "CERT", "CERT VU", "External Reference Data: RedHat RHSA",
"Secunia Advisory ID", "Vendor URL", "Microsoft Knowledge Base Article", "CIAC Advisory", "Other Advisory URL", "Other Solution URL", "US-CERT Cyber Security Alert",
"Mail List Post", "Security Tracker", "Packet Storm", "Vendor Specific News/Change Log Entry", "OVAL ID", "News Article", "VUPEN Advisory", "Nikto Item ID",
"Milw0rm", "Metasploit ID", "Exploit Database", "SCIP VulDB ID", "Tenable PVS", "DISA IAVA", "Immunity CANVAS(White Phosphorus)", "Immunity CANVAS",
"Immunity CANVAS(D2ExploitPack)", "Japan Vulnerability Notes", "vendor_0", "vendor_1", "vendor_2", "vendor_3", "product_0", "versions_0", "product_1", "versions_1", "product_2", "versions_2", "product_3", "versions_3", "score_0", "source_0", "generated_on_0", "access_vector_0" , "access_complexity_0", "authentication_0" , "confidentiality_impact_0" , "integrity_impact_0" , "availability_impact_0", "score_1", "source_1", "generated_on_1", "access_vector_1" ,"access_complexity_1", "authentication_1" , "confidentiality_impact_1" , "integrity_impact_1" , "availability_impact_1", "score_2", "source_2", "generated_on_2", "access_vector_2" , "access_complexity_2", "authentication_2" ,"confidentiality_impact_2" ,"integrity_impact_2" ,"availability_impact_2","score_3", "source_3", "generated_on_3", "access_vector_3" , "access_complexity_3", "authentication_3" , "confidentiality_impact_3" , "integrity_impact_3" , "availability_impact_3", "authors"]

filename = today.strftime('%Y-%m-%d') + '.txt'

f = codecs.open(filename, "wb", "utf-8")

header_print = ""
for attrib in header:
	# Tab delimited
    header_print = header_print + '"' + str(attrib) + '"\t'
print(header_print, file=f)

hash = {}

attributes = ["osvdb_id", "title", "keywords", "description", "solution", "vulndb_last_modified", "solution_date", "disclosure_date", "discovery_date", "exploit_publish_date", "vendor_informed_date", "vendor_ack_date", "third_party_solution_date"]

results = data["results"]

for result in results:
    for attribute in attributes:
        if result.get(attribute):
            hash[attribute] = result.get(attribute)
  
    references = result["ext_references"]
    for reference in references:
        if hash.get(reference["type"]):
            hash[reference["type"]] = hash[reference["type"]] + ";" + reference["value"]
        else:
            hash[reference["type"]] = reference["value"]
        
    cvss_metrics = result["cvss_metrics"]
    i = 0
    for cvss_metric in cvss_metrics:
        hash["score_" + str(i)] = cvss_metric["score"]
        hash["source_" + str(i)] = cvss_metric["source"]
        hash["generated_on_" + str(i)] = cvss_metric["generated_on"]
        hash["access_vector_" + str(i)] = cvss_metric["access_vector"]
        hash["access_complexity_" + str(i)] = cvss_metric["access_complexity"]
        hash["authentication_" + str(i)] = cvss_metric["authentication"]
        hash["confidentiality_impact_" + str(i)] = cvss_metric["confidentiality_impact"]
        hash["integrity_impact_" + str(i)] = cvss_metric["integrity_impact"]
        hash["availability_impact_" + str(i)] = cvss_metric["availability_impact"]
        i = i + 1
    vendors = result["vendors"]
    i = 0
    for vendor in vendors:
        hash["vendor_" + str(i)] = vendor["vendor"]["name"]
        i = i + 1
    products = result["products"]
    i = 0
    for product in products:
        hash["product_" + str(i)] = product["name"]
        versions = product["versions"]
        vers = ""
        for version in versions:
            vers = vers + ";" + version["name"]
        hash["versions" + str(i)] = vers
        i = i + 1
    classifications = result["classifications"]
    i = 0
    for classification in classifications:
        hash["classification_" + str(i)] = classification["longname"]
        i = i + 1
      
    authors = result["authors"]
    auts = ""
    for author in authors:
        if author["name"]:
            if auts is "":
                auts = author["name"]
            else:
                auts = auts + ";" + author["name"]
    hash["authors"] = auts
    record = ""
    for attrib in header:
        if hash.get(attrib):
            print('"', end='', file=f)
            if (isinstance(hash[attrib], str)) or (attrib in ["title", "description", "solution"]):
	        combined = str(unicode(hash[attrib]).encode('utf-8'))
                value = combined.replace(r'\r', ' ').replace(r'\n', ' ').replace(r'\t', ' ')
                print(value.decode('utf-8'), end='', file=f)
            else:
                print(hash[attrib], end='', file=f)            
            print('"\t', end='', file=f)
        else:
            print('""\t', end='', file=f)
            
    print("", file=f)

    hash = {}

f.close()

import subprocess as sub
cmd = "sed -i ':a;N;$!ba;s/\\r\\n//g' \"" + filename + "\""
p = sub.Popen(cmd, shell=True)