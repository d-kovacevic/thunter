"""
Module that will parse Palo Alto Networks Firewall (PAN-OS 9.0.x) logs from CSV file
"""
from datetime import datetime
import ipaddress
from thunter.helper.helperfuncs import timeit

from collections import deque
import elasticsearch
from elasticsearch import helpers
import csv
import re


def convert_to_datetime(datetime_str):
    year, month, day = datetime_str.split(" ")[0].split("/")
    hour, minute, second = datetime_str.split(" ")[1].split(":")
    return datetime(int(year), int(month), int(day), int(hour), int(minute), int(second))


def convert_common_pan_log_fields(dict_row):
    dict_row["Domain"] = int(dict_row["Domain"])
    dict_row["Receive Time"] = convert_to_datetime(dict_row["Receive Time"])
    dict_row["Config Version"] = int(dict_row["Config Version"])
    dict_row["Generate Time"] = convert_to_datetime(dict_row["Generate Time"])
    dict_row["NAT Source IP"] = dict_row["NAT Source IP"] \
        if dict_row["NAT Source IP"] != "" else "0.0.0.0"
    dict_row["NAT Destination IP"] = dict_row["NAT Destination IP"] \
        if dict_row["NAT Destination IP"] != "" else "0.0.0.0"
    dict_row["Time Logged"] = convert_to_datetime(dict_row["Time Logged"])
    dict_row["Session ID"] = int(dict_row["Session ID"])
    dict_row["Repeat Count"] = int(dict_row["Repeat Count"])
    dict_row["Source Port"] = int(dict_row["Source Port"])
    dict_row["Destination Port"] = int(dict_row["Destination Port"])
    dict_row["NAT Source Port"] = int(dict_row["NAT Source Port"])
    dict_row["NAT Destination Port"] = int(dict_row["NAT Destination Port"])
    return dict_row


def fix_domain_field(dict_row):
    if '\ufeffDomain' in dict_row.keys():
        dict_row['Domain'] = dict_row['\ufeffDomain']
        del dict_row['\ufeffDomain']
        dict_row.move_to_end('Domain', last=False)
    return dict_row


def fix_url_field(field):
    field = field.replace(" '", "")
    field = field.replace("'", "")
    field = field.replace("[", "")
    return field


@timeit
def get_pan_traffic_row(csv_file_location):
    """
    Generator function that will parse PAN traffic logs from the CSV and return one CSV row dict
    :param csv_file_location:
    :return: returns one entry(csv row) of traffic log as dictionary
    """
    csv_dict_file = csv.DictReader(open(csv_file_location, mode="r", encoding="utf-8"))

    for dict_row in csv_dict_file:

        # Fix garbage in the field 'Domain'
        dict_row = fix_domain_field(dict_row)

        # Convert common PAN log fields
        dict_row = convert_common_pan_log_fields(dict_row)

        # Convert specific PAN traffic log fields
        dict_row["Bytes"] = int(dict_row["Bytes"])
        dict_row["Bytes Sent"] = int(dict_row["Bytes Sent"])
        dict_row["Bytes Received"] = int(dict_row["Bytes Received"])
        dict_row["Packets"] = int(dict_row["Packets"])
        dict_row["Start Time"] = convert_to_datetime(dict_row["Start Time"])
        dict_row["Elapsed Time (sec)"] = int(dict_row["Elapsed Time (sec)"])
        dict_row["tpadding"] = int(dict_row["tpadding"])
        dict_row["Sequence Number"] = int(dict_row["Sequence Number"])
        dict_row["cpadding"] = int(dict_row["cpadding"])
        dict_row["Packets Sent"] = int(dict_row["Packets Sent"])
        dict_row["Packets Received"] = int(dict_row["Packets Received"])
        dict_row["DG Hierarchy Level 1"] = int(dict_row["DG Hierarchy Level 1"])
        dict_row["DG Hierarchy Level 2"] = int(dict_row["DG Hierarchy Level 2"])
        dict_row["DG Hierarchy Level 3"] = int(dict_row["DG Hierarchy Level 3"])
        dict_row["DG Hierarchy Level 4"] = int(dict_row["DG Hierarchy Level 4"])
        dict_row["Tunnel ID/IMSI"] = int(dict_row["Tunnel ID/IMSI"])
        dict_row["Parent Session ID"] = int(dict_row["Parent Session ID"])
        dict_row["Parent Session Start Time"] = convert_to_datetime(
            dict_row["Parent Session Start Time"]
            if dict_row["Parent Session Start Time"] != "" else "1970/01/01 00:00:00")
        dict_row["SCTP Association ID"] = int(dict_row["SCTP Association ID"])
        dict_row["SCTP Chunks"] = int(dict_row["SCTP Chunks"])
        dict_row["SCTP Chunks Sent"] = int(dict_row["SCTP Chunks Sent"])
        dict_row["SCTP Chunks Received"] = int(dict_row["SCTP Chunks Received"])

        yield dict_row


@timeit
def get_pan_threat_row(csv_file_location):
    """
    Generator function that will parse PAN threats logs from the CSV and return dict as one row
    :param csv_file_location:
    :return: returns one entry(csv row) of threats log as dictionary
    """
    csv_dict_file = csv.DictReader(open(csv_file_location, mode="r", encoding="utf-8"))

    for dict_row in csv_dict_file:

        # Fix garbage in the field 'Domain'
        dict_row = fix_domain_field(dict_row)

        # Convert common PAN log fields
        dict_row = convert_common_pan_log_fields(dict_row)

        # Convert specific PAN threat log fields
        # :TODO fix this for newer logs >=9.1
        """
        dict_row["Sequence Number"] = int(dict_row["Sequence Number"])
        dict_row["cpadding"] = int(dict_row["cpadding"])
        dict_row["pcap_id"] = int(dict_row["pcap_id"])
        dict_row["reportid"] = int(dict_row["reportid"])
        dict_row["DG Hierarchy Level 1"] = int(dict_row["DG Hierarchy Level 1"])
        dict_row["DG Hierarchy Level 2"] = int(dict_row["DG Hierarchy Level 2"])
        dict_row["DG Hierarchy Level 3"] = int(dict_row["DG Hierarchy Level 3"])
        dict_row["DG Hierarchy Level 4"] = int(dict_row["DG Hierarchy Level 4"])
        dict_row["Tunnel ID/IMSI"] = int(dict_row["Tunnel ID/IMSI"])
        dict_row["Parent Session ID"] = int(dict_row["Parent Session ID"])
        dict_row["Parent Session Start Time"] = convert_to_datetime(
            dict_row["Parent Session Start Time"]
            if dict_row["Parent Session Start Time"] != "" else "1970/01/01 00:00:00")
        dict_row["SCTP Association ID"] = int(dict_row["SCTP Association ID"])
        """

        yield dict_row


@timeit
def get_pan_url_row(csv_file_location):
    """
    Generator function that will parse PAN URL logs from the CSV and return dict as one row
    :param csv_file_location:
    :return: returns one entry(csv row) of URL log as a dictionary
    """
    csv_dict_file = csv.DictReader(open(csv_file_location, mode="r", encoding="utf-8"))

    for dict_row in csv_dict_file:

        # Fix garbage in the field 'Domain'
        dict_row = fix_domain_field(dict_row)

        # Convert common PAN log fields
        dict_row = convert_common_pan_log_fields(dict_row)

        # Test if long URL's did not brake CSV rule
        if dict_row["Threat/Content Name"] == "(9999)":
            # Convert specific PAN URL log fields
            #:TODO This needs to be fixed, CSV is broken User-agent field
            """dict_row["Sequence Number"] = int(dict_row["Sequence Number"])
            dict_row["cpadding"] = int(dict_row["cpadding"])
            dict_row["pcap_id"] = int(dict_row["pcap_id"])
            dict_row["DG Hierarchy Level 1"] = int(dict_row["DG Hierarchy Level 1"])
            dict_row["DG Hierarchy Level 2"] = int(dict_row["DG Hierarchy Level 2"])
            dict_row["DG Hierarchy Level 3"] = int(dict_row["DG Hierarchy Level 3"])
            dict_row["DG Hierarchy Level 4"] = int(dict_row["DG Hierarchy Level 4"])
            dict_row["Tunnel ID/IMSI"] = int(dict_row["Tunnel ID/IMSI"])
            dict_row["Parent Session ID"] = int(dict_row["Parent Session ID"])
            dict_row["Parent Session Start Time"] = convert_to_datetime(
                dict_row["Parent Session Start Time"]
                if dict_row["Parent Session Start Time"] != "" else "1970/01/01 00:00:00")
            dict_row["SCTP Association ID"] = int(dict_row["SCTP Association ID"])"""
            pass
        else:
            # Fix wrong CSV formatting of PAN URL logs
            try:
                s = ",".join([str(val) for val in dict_row.values()])[:-1]

                match_action = ",alert,|,block-continue,|,block-url,|,continue,|,override,|,block-override,"
                match_threat_content = ",\(9999\),|, \'\(9999\)\',|, \[\'\(9999\)\',|\[\'\(9999\)\',"
                result = re.search('(' + match_action + ')(.*)(' + match_threat_content + ')', s)

                dict_row["URL/Filename"] = result.group(2)
                dict_row["Threat/Content Name"] = "(9999)"

                result = re.search('(' + match_threat_content + ')(.*)', s)

                dict_row["Category"] = fix_url_field(result.group(2).split(",")[0])
                dict_row["Severity"] = fix_url_field(result.group(2).split(",")[1])
                dict_row["Direction"] = fix_url_field(result.group(2).split(",")[2])
                dict_row["Sequence Number"] = fix_url_field(result.group(2).split(",")[3])
                dict_row["Action Flags"] = fix_url_field(result.group(2).split(",")[4])
                dict_row["Source Country"] = fix_url_field(result.group(2).split(",")[5])
                dict_row["Destination Country"] = fix_url_field(result.group(2).split(",")[6])
                dict_row["cpadding"] = fix_url_field(result.group(2).split(",")[7])
                dict_row["contenttype"] = fix_url_field(result.group(2).split(",")[8])
                dict_row["pcap_id"] = fix_url_field(result.group(2).split(",")[9])
                dict_row["filedigest"] = fix_url_field(result.group(2).split(",")[10])
                dict_row["cloud"] = fix_url_field(result.group(2).split(",")[11])
                dict_row["url_idx"] = fix_url_field(result.group(2).split(",")[12])
                dict_row["user_agent"] = fix_url_field(result.group(2).split(",")[13])

            except Exception as e:
                print(e + "\n" + s)

        yield dict_row


@timeit
def send_pan_logs_to_es(es_server, index_name, csv_file_location, log_type):
    """
    :param es_server:
    :param index_name:
    :param csv_file_location:
    :param log_type:
    :return:
    """
    es = elasticsearch.Elasticsearch(es_server)

    get_log_row_from_csv = 0

    if log_type == "PAN_TRAFFIC":
        get_log_row_from_csv = get_pan_traffic_row
    elif log_type == "PAN_THREAT":
        get_log_row_from_csv = get_pan_threat_row
    elif log_type == "PAN_URL":
        get_log_row_from_csv = get_pan_url_row
    else:
        raise Exception("Not valid log type!")

    es.indices.delete(index=index_name, ignore=404)

    request_body = {
        "mappings": {
            "properties": {
                "Source address": {"type": "ip"},
                "Destination address": {"type": "ip"},
                "NAT Source IP": {"type": "ip"},
                "NAT Destination IP": {"type": "ip"}
            }
        }
    }

    es.indices.create(index=index_name, body=request_body)

    deque(helpers.parallel_bulk(es, get_log_row_from_csv(csv_file_location), index=index_name), maxlen=0)
    es.indices.refresh()


