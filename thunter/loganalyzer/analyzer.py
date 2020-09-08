from datetime import datetime
import ipaddress
from thunter.helper.helperfuncs import timeit

from collections import deque
import elasticsearch
from elasticsearch import helpers
import csv
import re

MAX_ES_ROWS = 10000


@timeit
def get_long_lived_sessions(es_server, index_name, top_rows=10):
    """
    :TODO
    :param es_server:
    :param index_name:
    :param top_rows:
    :return:
    """
    es = elasticsearch.Elasticsearch(es_server)
    result = es.search(
        index=index_name,
        body={
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"Threat/Content Type.keyword": "end"}}
                        ],
                        "must_not": [
                            {"term": {"Application.keyword": "netbios-ns"}},
                            {"term": {"Application.keyword": "bgp"}},
                            {"term": {"Application.keyword": "windows-push-notifications"}},
                            {"term": {"Destination address": "10.0.0.0/8"}},
                            {"term": {"Destination address": "172.16.0.0/12"}},
                            {"term": {"Destination address": "192.168.0.0/16"}}
                        ]}
                },
                "sort": [
                    {"Elapsed Time (sec)": {"order": "desc"}}
                ]
        },
        params={"size": top_rows}
    )
    return result['hits']['hits']


@timeit
def get_dns_sessions_cnt(es_server, index_name, top_rows=10):
    """
    :TODO
    :param es_server:
    :param index_name:
    :param top_rows:
    :return:
    """
    es = elasticsearch.Elasticsearch(es_server)
    result = es.search(
        index=index_name,
        body={
            "query": {
                "term": {
                    "Application.keyword": "dns"
                }
            },
            "aggs": {
                "group_by_ip": {
                    "terms": {
                        "field": "Source address",
                        "size": top_rows
                    }
                }
            }
        },
        params={"size": 0}
    )
    return result["aggregations"]["group_by_ip"]["buckets"]


@timeit
def get_unknown_apps_ips(es_server, index_name, top_rows=10):
    """
    :TODO
    :param es_server:
    :param index_name:
    :param top_rows:
    :return:
    """
    es = elasticsearch.Elasticsearch(es_server)
    result = es.search(
        index=index_name,
        body={
            "query": {
                "terms": {
                    "Application.keyword": ["unknown-tcp", "unknown-tcp"]
                }
            },
            "aggs": {
                "group_by_ip": {
                    "terms": {
                        "field": "Source address",
                        "size": top_rows
                    }
                }
            }
        },
        params={"size": 0}
    )
    return result["aggregations"]["group_by_ip"]["buckets"]


@timeit
def get_unusual_port_comm(es_server, index_name, top_rows=10):
    """
    :TODO
    :param es_server:
    :param index_name:
    :return:
    """
    es = elasticsearch.Elasticsearch(es_server)
    result_low_ports = es.search(
        index=index_name,
        body={
            "query": {
                "bool": {
                    "must": [
                        {"term": {"Threat/Content Type.keyword": "end"}}
                    ],
                    "must_not": [
                        {"term": {"Application.keyword": "netbios-dg"}},
                        {"term": {"Application.keyword": "ntp"}}
                    ],
                    "filter": {
                        "bool": {
                            "must": [
                                {"range": {"Source Port": {"gte": 0, "lte": 1024}}},
                                {"range": {"Destination Port": {"gte": 0, "lte": 1024}}}
                            ]
                        }
                    }
                }
            }
        },
        params={"size": top_rows}
    )

    result_high_ports = es.search(
        index=index_name,
        body={
            "query": {
                "bool": {
                    "must": [
                        {"term": {"Threat/Content Type.keyword": "end"}}
                    ],
                    "must_not": [
                        {"term": {"Application.keyword": "netbios-dg"}},
                        {"term": {"Application.keyword": "ntp"}}
                    ],
                    "filter": {
                        "bool": {
                            "must": [
                                {"range": {"Source Port": {"gte": 1024, "lte": 65535}}},
                                {"range": {"Destination Port": {"gte": 1024, "lte": 65535}}}
                            ]
                        }
                    }
                }
            }
        },
        params={"size": top_rows}
    )
    return result_low_ports['hits']['hits'] + result_high_ports['hits']['hits']


@timeit
def es_iterate_all_documents(es, index, pagesize=10000, scroll_timeout="1m", **kwargs):
    """
    Helper to iterate ALL values from a single index
    Yields all the documents.
    """
    is_first = True
    while True:
        if is_first:
            result = es.search(index=index, scroll="1m", **kwargs, body={
                "size": pagesize
            })
            is_first = False
        else:
            result = es.scroll(body={
                "scroll_id": scroll_id,
                "scroll": scroll_timeout
            })
        scroll_id = result["_scroll_id"]
        hits = result["hits"]["hits"]
        # Stop after no more docs
        if not hits:
            break
        # Yield each entry
        yield from (hit['_source'] for hit in hits)


@timeit
def get_domains_from_url(es_server, index_name):
    """
    :TODO
    :param es_server:
    :param index_name:
    :return:
    """
    es = elasticsearch.Elasticsearch(es_server)
    cnt_result = es.count(index=index_name)

    domains_set = set()
    domain = ""
    for row in es_iterate_all_documents(es, index_name):
        domain = row["URL/Filename"]
        if domain.find("/") != -1:
            domain = domain.split("/")[0]
        if domain.find(":") != -1:
            domain = domain.split(":")[0]
        domains_set.add(domain)

    return domains_set


@timeit
def find_unknown_app_sessions_es(index_name, subnets=None):
    unknown_app_sessions = []
    es = elasticsearch.Elasticsearch("127.0.0.1:9200")
    num_from = 0
    num_size = 100
    for i in range(10):
        result = es.search(
            index=index_name,
            body={
                "query": {
                    "match_all": {}
                }
            },
            params={"size": num_size, "from": num_from}
        )

        print("TOTAL HITSSSSS: " + str(result['hits']['total']['value']))

        num_from += num_size
        all_hits = result['hits']['hits']
        print("total hits:", len(result["hits"]["hits"]))

        # iterate the nested dictionaries inside the ["hits"]["hits"] list
        for num, doc in enumerate(all_hits):
            print("DOC ID:", doc["_id"], "--->", doc, type(doc), "\n")

            # Use 'iteritems()` instead of 'items()' if using Python 2
            for key, value in doc.items():
                print(key, "-->", value)

            # print a few spaces between each doc for readability
            print("\n\n")

    return unknown_app_sessions



@timeit
def get_mismatch_port_app(es_server, index_name, top_rows=10):
    return


@timeit
def find_top_dns_sessions_per_ip(pan_traffic_log, top_number):
    return



