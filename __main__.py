from thunter.loganalyzer.importer import *
from thunter.loganalyzer.analyzer import *

import pprint
import csv


es_server = "127.0.0.1:9200"


send_pan_logs_to_es(es_server=es_server, index_name="log_traffic_pan",
                csv_file_location=r"test/log_traffic_pan_vm01_all.csv", log_type="PAN_TRAFFIC")
print("done traffic")

send_pan_logs_to_es(es_server=es_server, index_name="log_threat_pan",
                csv_file_location=r"test/log_threat_pan_vm01_all.csv", log_type="PAN_THREAT")
print("done threat")

send_pan_logs_to_es(es_server=es_server, index_name="log_url_pan",
                    csv_file_location=r"test/log_url_pan_vm01_all.csv", log_type="PAN_URL")
print("done url")


for row in get_long_lived_sessions(es_server=es_server, index_name="log_traffic_pan", top_rows=100):
    row_src = row["_source"]
    print(row_src["Source address"], row_src["Destination address"], row_src["Application"],
          row_src["Elapsed Time (sec)"])


for row in get_dns_sessions_cnt(es_server=es_server, index_name="log_traffic_pan", top_rows=100):
    print(row["key"], row["doc_count"])


for row in get_unknown_apps_ips(es_server=es_server, index_name="log_traffic_pan", top_rows=100):
    print(row["key"], row["doc_count"])


for row in get_unusual_port_comm(es_server=es_server, index_name="log_traffic_pan"):
    row_src = row["_source"]
    print(row_src["Source address"], row_src["Source Port"], row_src["Destination address"],
          row_src["Destination Port"], row_src["Application"])


urls = get_domains_from_url(es_server=es_server, index_name="log_url_pan")


print(len(urls))






