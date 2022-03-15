import copy
import json
import logging
from elasticsearch5 import Elasticsearch as Elasticsearch5
from elasticsearch import Elasticsearch 

class DConfig():
    """ Simple configuration loader """
    cfg = {}
    def __init__(self, fname):
        try:
            self.cfg = (json.loads(open(fname).read()))
        except:
            logging.critical("Unable to open/parse configuration file.")
            raise ValueError

class ES():
    def __init__(self, cfg, server):
        try:
            use_ssl = bool(cfg.cfg["elastic"]["use_ssl"])
        except KeyError:
            use_ssl = False
        try:
            es_host = cfg.cfg["elastic"]["host"]
            es_version = cfg.cfg["elastic"]["version"]
            if es_version == "5":
                self.es = Elasticsearch5(es_host, use_ssl=use_ssl)
            else:
                self.es = Elasticsearch(es_host, use_ssl=use_ssl)
        except:
            logging.critical("Unable to connect to ElasticSearch node: {0}".format(es_host))
            raise
        try:
            self.es_max_size  = int(cfg.cfg["elastic"]["max_size"])
        except:
            logging.warning("ElasticSearch max_size is not set. Setting max_size = 1000.")
            self.es_max_size = 1000
        self.basic_query = { "query" : { "bool" : { "must" : [ ]} }, "size" : self.es_max_size }
        for k,v in cfg.cfg['global_filters'].items():
            self.basic_query['query']['bool']['must'].append({"match" : {k : v}})
        self.basic_query['query']['bool']['must'].append({"match" : { "server" : server}})
        self.doc_type = cfg.cfg["elastic"]["doctype"]
    
    def search(self, index, filter):
        qr = copy.deepcopy(self.basic_query)
        qr['query']['bool']['must'].extend(filter)
        res = self.es.search(index = index, body = qr)
        logging.info(qr)
        logging.info(res)
        return res
    
    def update(self, index, id, data):
        logging.info({'index': index, 'doc_type': self.doc_type, 'id': id, 'body': {"doc": data}})
        res = self.es.update(index = index, doc_type = self.doc_type, id = id, body = {"doc": data})
        logging.info(res)
        return res