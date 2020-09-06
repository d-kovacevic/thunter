from thunter.loganalyzer.importer import *
from thunter.loganalyzer.analyzer import *

import pprint
import csv


es_server = "127.0.0.1:9200"


"""send_pan_logs_to_es(es_server=es_server, index_name="log_traffic_pan",
                csv_file_location=r"test/log_traffic_pan_vm01_all.csv", log_type="PAN_TRAFFIC")
print("done traffic")

send_pan_logs_to_es(es_server=es_server, index_name="log_threat_pan",
                csv_file_location=r"test/log_threat_pan_vm01_all.csv", log_type="PAN_THREAT")
print("done threat")


send_pan_logs_to_es(es_server=es_server, index_name="log_url_pan",
                    csv_file_location=r"test/log_url_pan_vm01_all.csv", log_type="PAN_URL")
print("done url")"""


"""for row in get_long_lived_sessions(es_server=es_server, index_name="log_traffic_pan", top_rows=100):
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


a, urls = get_domains_from_url(es_server=es_server, index_name="log_url_pan")

for url in urls:
    print(url)"""


"""send_pan_logs_to_es(es_server=es_server, index_name="01456202_traffic_all_dst_public_09_05",
                    csv_file_location=r"test/01456202_traffic_all_dst_public_09_05.csv", log_type="PAN_TRAFFIC")
print("done 01456202_traffic_all_dst_public_09_05")

send_pan_logs_to_es(es_server=es_server, index_name="01456202_traffic_10_10_100_3_AD_09_05",
                    csv_file_location=r"test/01456202_traffic_10_10_100_3_AD_09_05.csv", log_type="PAN_TRAFFIC")
print("done 01456202_traffic_10_10_100_3_AD_09_05")"""

send_pan_logs_to_es(es_server=es_server, index_name="01578134_threat_log_all",
                    csv_file_location=r"test/01578134_threat_log_all.csv", log_type="PAN_THREAT")
print("done 01456202_threat__09_05")



