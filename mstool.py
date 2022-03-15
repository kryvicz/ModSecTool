import logging
import re
import sys
from enum import unique
from itertools import count
from optparse import OptionParser 
from mstoollib import *

# region option parser
parser = OptionParser()
parser.add_option("-a","--append", 
                  dest="append",
                  action="store_true", 
                  default=False,
                  help="Automatically add new rules to the rule file")
parser.add_option("-s", "--server",
                  dest="server", 
                  help="FQDN to which we should restrict operations.")
parser.add_option("-t","--tag", 
                  dest="tag",
                  action="store_true", 
                  default=False,
                  help="Actually tag matching items in DB.")
parser.add_option("-u", "--uri",
                  dest="uri", 
                  help="Left part of relative URI")
parser.add_option("-V","--verbose", 
                  dest="verbose",
                  action="store_true", 
                  default=False,
                  help="Enable extended logging")
parser.add_option("-w", "--wlfile", 
                  dest="wl_file", 
                  help="A path to whitelist file, will find matching events in DB.")
parser.add_option("-i", "--id", 
                  dest="unique_id", 
                  help="Find events by specific unique_id.")
parser.add_option("-W","--warnoff", 
                  dest="warnings",
                  action="store_false", 
                  default=True,
                  help="Enable extended logging")

(options, args) = parser.parse_args()
#endregion

if not options.server:
    parser.error('Commandline --server option is mandatory')
else:
    server = options.server

unique_ids = []
lowlevel_ids_err = []
lowlevel_ids_warn = []

# Initialize logging
level = logging.WARNING if options.warnings and not options.verbose else (logging.ERROR if not options.warnings else logging.INFO)
logging.basicConfig( level=level,
                    format="%(asctime)s [%(levelname)s] %(message)s",
                    handlers=[
                        logging.FileHandler("mstool.log"),
                        logging.StreamHandler()
                    ])

cfg = DConfig("mstool.json")
es = ES(cfg, server)
err_index = cfg.cfg["elastic"]["search_index"]
warn_index = cfg.cfg["elastic"]["rule_index"]

if not options.uri and not options.unique_id and not options.wl_file:
    parser.error('You need to specify one of the options: --uri, --id or --wlfile')

elif options.uri:
    filter = []
    filter.append({"match" : { "uri.keyword" : options.uri}})
    
    res = es.search(index=err_index, filter = filter)

    if int(res['hits']['total']) == 0:
        print(f"There is no records with URI '{options.uri}' in the index '{err_index}'.")
        sys.exit(0)

    unique_ids.extend(list(set([item['_source']["unique_id"] for item in res['hits']['hits']])))
    lowlevel_ids_err.extend(list(set([item['_id'] for item in res['hits']['hits']])))

elif options.unique_id:
    unique_ids.append(options.unique_id)
    filter = []
    filter.append({"match" : { "unique_id" : options.unique_id}})
    res = es.search(index=err_index, filter=filter)
    if int(res['hits']['total']) > 0:
        lowlevel_ids_err.extend(list(set([item['_id'] for item in res['hits']['hits']])))

elif options.wl_file:
    try:
        with open(options.wl_file, 'r') as rule_file:
            for line in [line for line in rule_file.readlines() if line[:20].lower().lstrip().startswith("secrule request")]:
                rule = re.search(r'SecRule REQUEST_URI "@beginsWith ([^\"]+)" "phase:2,nolog,pass,id:(\d+),ctl:ruleRemoveTargetById=(\d+);*([^\"]*)\"*.*', line, re.IGNORECASE)
                rule_uri = rule.group(1)
                rule_id = rule.group(3)
                rule_var = rule.group(4)
                filter = []
                filter.append({"match" : { "uri.keyword" : rule_uri}})
                filter.append({"match" : { "rule" : rule_id}})
                filter.append({"match" : { "variable" : rule_var}})
                res_warn = es.search(index=warn_index, filter = filter)
                res_err = es.search(index=err_index, filter = filter)

                if int(res_warn['hits']['total']) == 0:
                    print(f"There is no records with URI '{options.uri}' in the index '{err_index}'.")
                    sys.exit(0)

                unique_ids.extend(list(set([item['_source']["unique_id"] for item in res_warn['hits']['hits']])))
                lowlevel_ids_warn.extend(list(set([item['_id'] for item in res_warn['hits']['hits']])))

                if int(res_err['hits']['total']) > 0:
                    lowlevel_ids_err.extend(list(set([item['_id'] for item in res_err['hits']['hits']])))

    except:
        logging.critical(f"Unable to read white rules file {options.wl_file}")
        sys.exit(2)



#region определение последнего id в файле с исключениями
rule_file_name = cfg.cfg["publications_rules"][server] if server in cfg.cfg["publications_rules"] else cfg.cfg["publications_rules"]["default"].replace('{server}',server)
rule_id = 10000
try:
    with open(rule_file_name, 'r') as rule_file:
        rule_file_lines = rule_file.readlines() 
        rule_file_lines.reverse()
        rule_line = next(((i,line) for i, line in enumerate(rule_file_lines) if line[:20].lower().lstrip().startswith("secrule request")),"id:10000")
        rule_id_search = re.search(r'(?:id:)(\d+)', rule_line[1])
        rule_line_index = -int(rule_line[0])
        rule_id = int(rule_id_search.group(1))
except:
    logging.warning(f"Unable to get the last rule id from file '{rule_file_name}'. Setting numeration since 10000.")
#endregion

#region запрос данных в elastic по индексу modsec-warn
rule_ids = []
for unique_id in unique_ids:
    filter = []
    filter.append({"match" : { "unique_id" : unique_id}})
    res = es.search(index=warn_index, filter=filter)
    if int(res['hits']['total']) == 0:
        continue
    for item in res['hits']['hits']:
        variable = item['_source']['variable'] if 'variable' in item['_source'] else ""
        rule_ids.append((item['_source']['rule'], variable, item['_source']['uri']))
        lowlevel_ids_warn.append(item['_id'])

if not options.wl_file:
    rule_unique_ids = list(set(rule_ids))
    id = count(rule_id + 1)
    rules = []
    for (rule_id, variable, uri) in rule_unique_ids:
        rule = f'SecRule REQUEST_URI "@beginsWith {uri}" "phase:2,nolog,pass,id:{next(id)},ctl:ruleRemoveTargetById={rule_id}{";" if variable else ""}{variable}"'
        rules.append(rule)
        print(rule)
        logging.info(rule)
#endregion



#region set whitelisted = true
if options.tag:
    warn_updates = 0
    err_updates = 0
    source_to_update = {'whitelisted' : 'true'}
    for id in lowlevel_ids_err:
        res = es.update(err_index,id, source_to_update)
        if res['result'] != 'updated':
            logging.warning(res)
        else:
            err_updates += 1
    lowlevel_ids_warn = list(set(lowlevel_ids_warn))
    for id in lowlevel_ids_warn:
        res = es.update(warn_index,id, source_to_update)
        if res['result'] != 'updated':
            logging.warning(res)
        else:
            warn_updates += 1
    logging.info({err_index: lowlevel_ids_err, warn_index: lowlevel_ids_warn})
    logging.info(f"Updated {err_updates} records in the '{err_index}' index and {warn_updates} records in the '{warn_index}' index")
#endregion
   
if options.append:
    try:
        with open(rule_file_name, 'w') as rule_file:
            rule_file_lines.reverse()
            for rule in rules:
                rule_file_lines.insert(rule_line_index, rule + "\n")
            rule_file.writelines(rule_file_lines)

    except:
        logging.error("Unable to update rules file. Do it manually.")
