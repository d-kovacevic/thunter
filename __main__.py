from thunter.loganalyzer.importer import *
from thunter.loganalyzer.analyzer import *
from thunter.helper.helperfuncs import *

import pprint
import csv

ES_SERVER = "127.0.0.1:9200"

LOG_TYPE = {"threat": "PAN_THREAT", "traffic": "PAN_TRAFFIC", "url": "PAN_URL"}


def import_logs_to_es(es_server, index_name, csv_file_location, log_type):
    """
    Function used to import PAN firewall logs from CSV format into ELK stack
    :return:
    """

    send_pan_logs_to_es(es_server=es_server, index_name=index_name,
                        csv_file_location=csv_file_location, log_type=log_type)


def print_long_lived_sessions(es_server, index_name, top_rows=100):

    print_table("Get long lived sessions", "=")
    for i, row in enumerate(get_long_lived_sessions(es_server=es_server, index_name=index_name, top_rows=top_rows)):
        if i == 0:
            print_table("Source address, Destination address, Application, Elapsed Time (sec)", "-")
        row_src = row["_source"]
        print(row_src["Source address"], row_src["Destination address"], row_src["Application"],
              row_src["Elapsed Time (sec)"], sep=",")
    print(("-" * 50) + "\n\n")


def print_dns_session_cnt(es_server, index_name, top_rows=100):

    print_table("Get DNS session count per IP address", "=")
    for i, row in enumerate(get_dns_sessions_cnt(es_server=es_server, index_name=index_name, top_rows=top_rows)):
        if i == 0:
            print_table("Source address, Number of DNS sessions", "-")
        print(row["key"], row["doc_count"], sep=",")
    print(("-" * 50) + "\n\n")


def print_unknown_apps_ips(es_server, index_name, top_rows=100):

    print_table("Get IP addresses which had \"unknown-application\" traffic", "=")
    for i, row in enumerate(get_unknown_apps_ips(es_server=es_server, index_name=index_name, top_rows=top_rows)):
        if i == 0:
            print_table("Source address, Number of \"unknown-application\" sessions", "-")
        print(row["key"], row["doc_count"], sep=",")
    print(("-" * 50) + "\n\n")


def print_unusual_port_comm(es_server, index_name):

    print_table("Get IP addresses which were using unusual src/dst port", "=")
    for i, row in enumerate(get_unusual_port_comm(es_server=es_server, index_name=index_name)):
        if i == 0:
            print_table("Source address, Source Port, Destination address, Destination Port, Application", "-")
        row_src = row["_source"]
        print(row_src["Source address"], row_src["Source Port"], row_src["Destination address"],
              row_src["Destination Port"], row_src["Application"], sep=",")
    print(("-" * 50) + "\n\n")


def main():
    print_long_lived_sessions(es_server=ES_SERVER, index_name="log_traffic_pan")
    print_dns_session_cnt(es_server=ES_SERVER, index_name="log_traffic_pan")
    print_unknown_apps_ips(es_server=ES_SERVER, index_name="log_traffic_pan")
    print_unusual_port_comm(es_server=ES_SERVER, index_name="log_traffic_pan")

    import_logs_to_es(es_server=ES_SERVER, index_name="log_threat_pan",
                      csv_file_location=r"test/01599875_threat_log.csv", log_type=LOG_TYPE["threat"])


if __name__ == "__main__":
    main()







