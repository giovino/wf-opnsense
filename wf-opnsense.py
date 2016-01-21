#!/usr/bin/python2.7

"""
pfsense / opnsense uses a Circular Log format known as clog to maintain a constant log size. This script calls
clog to obtain the firewall logs in plain text.

to do:
1. check for different response codes when submitting to csirtg.io
"""

from subprocess import check_call, check_output, STDOUT
from tempfile import NamedTemporaryFile
import datetime
import requests
import json
import logging
import time
import re

# to be edited
CSIRTG_USER = ''
CSIRTG_FEED = ''
CSIRTG_TOKEN = ''

WAN_INTERFACE_NAME = 'igb0'

# should not have to be edited

CSIRTG_REMOTE = 'https://csirtg.io/api'
CSIRTG_LIMIT = 5000
CSIRTG_TIMEOUT = 300

LOG_FILE = '/var/log/filter.log'
# DEV_LOG_FILE = 'filter.log'  # used for development only
firewall_logs = []

time_now = datetime.datetime.now()
now_epoch_time = time.time()
time_previous_five_min = time_now - datetime.timedelta(minutes=5)
year_previous_five_min = time_previous_five_min.strftime('%Y')

LOG_DATEFMT = '%Y-%m-%dT%H:%M:%SZ'
LOG_FORMAT = '%(asctime)s,%(name)s,%(levelname)s,%(message)s'

# Configure Logger
logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
formatter = logging.Formatter(LOG_FORMAT, LOG_DATEFMT)
handler.setFormatter(formatter)
logging.Formatter.converter = time.gmtime  # set time to UTC
logging.getLogger("requests").setLevel(logging.WARNING)  # reduce urlib logging
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)


def get_firewall_logs():
    """
    read the file /var/log/filter.log with /usr/local/sbin/clog

    :return: list
    """
    with NamedTemporaryFile() as f:
        check_call(['/usr/local/sbin/clog', '/var/log/filter.log'], stdout=f, stderr=STDOUT, shell=False)
        f.seek(0)
        output = f.readlines()
        return output


def get_timezone():
    """
    use /bin/date to obtain current timezone, using this shell hack to achieve the goal of not without having to import
    python modules outside of the python standard library / what's already installed on opnsense

    :return: str
    """
    timezone_result = check_output(['date', '+%Z'])
    return timezone_result.rstrip()


def extract_ipv4(ipv4_log, data_dictionary):
    """
    Parse the ipv4 specific bits

    :param ipv4_log: type: str - ipv4 bits from filter.log
    :param data_dictionary: type: dict - dictionary storing parsed logs
    :return: dict
    """
    ipv4_parsed = ipv4_log.split(',')
    ipv4_parsed[7] = ipv4_parsed[7].lower()
    if ipv4_parsed[7] == 'tcp':
        data_dictionary['tos'] = ipv4_parsed[0]
        data_dictionary['ecn'] = ipv4_parsed[1]
        data_dictionary['ttl'] = ipv4_parsed[2]
        data_dictionary['id'] = ipv4_parsed[3]
        data_dictionary['offset'] = ipv4_parsed[4]
        data_dictionary['flags'] = ipv4_parsed[5]
        data_dictionary['protocol_id'] = ipv4_parsed[6]
        data_dictionary['ip_protocol'] = ipv4_parsed[7]
        data_dictionary['length'] = ipv4_parsed[8]
        data_dictionary['source_ip'] = ipv4_parsed[9]
        data_dictionary['destination_ip'] = ipv4_parsed[10]
        data_dictionary['source_port'] = ipv4_parsed[11]
        data_dictionary['destination_port'] = ipv4_parsed[12]
        data_dictionary['data_length'] = ipv4_parsed[13]
        data_dictionary['tcp_flags'] = ipv4_parsed[14]
        data_dictionary['sequence_number'] = ipv4_parsed[15]
        data_dictionary['ack'] = ipv4_parsed[16]
        data_dictionary['window'] = ipv4_parsed[17]
        data_dictionary['urg'] = ipv4_parsed[18]
        data_dictionary['options'] = ipv4_parsed[19]
    elif ipv4_parsed[7] == 'udp':
        data_dictionary['tos'] = ipv4_parsed[0]
        data_dictionary['ecn'] = ipv4_parsed[1]
        data_dictionary['ttl'] = ipv4_parsed[2]
        data_dictionary['id'] = ipv4_parsed[3]
        data_dictionary['offset'] = ipv4_parsed[4]
        data_dictionary['flags'] = ipv4_parsed[5]
        data_dictionary['protocol_id'] = ipv4_parsed[6]
        data_dictionary['ip_protocol'] = ipv4_parsed[7]
        data_dictionary['length'] = ipv4_parsed[8]
        data_dictionary['source_ip'] = ipv4_parsed[9]
        data_dictionary['destination_ip'] = ipv4_parsed[10]
        data_dictionary['source_port'] = ipv4_parsed[11]
        data_dictionary['destination_port'] = ipv4_parsed[12]
        data_dictionary['data_length'] = ipv4_parsed[13]
    elif ipv4_parsed[7] == 'icmp':
        data_dictionary['tos'] = ipv4_parsed[0]
        data_dictionary['ecn'] = ipv4_parsed[1]
        data_dictionary['ttl'] = ipv4_parsed[2]
        data_dictionary['id'] = ipv4_parsed[3]
        data_dictionary['offset'] = ipv4_parsed[4]
        data_dictionary['flags'] = ipv4_parsed[5]
        data_dictionary['protocol_id'] = ipv4_parsed[6]
        data_dictionary['ip_protocol'] = ipv4_parsed[7]
        data_dictionary['length'] = ipv4_parsed[8]
        data_dictionary['source_ip'] = ipv4_parsed[9]
        data_dictionary['destination_ip'] = ipv4_parsed[10]
        data_dictionary['icmp_unknown'] = ipv4_parsed[11]
    else:
        print("ip protocol unknown")
    
    return data_dictionary


def extract_ipv6(ipv6_log, data_dictionary):
    """
    Parse the ipv6 specific bits

    :param ipv6_log: type: str - ipv6 bits from filter.log
    :param data_dictionary: type: dict - dictionary storing parsed logs
    :return: dict
    """
    ipv6_parsed = ipv6_log.split(',')
    ipv6_parsed[3] = ipv6_parsed[3].lower()
    if ipv6_parsed[3] == 'tcp':
        data_dictionary['class'] = ipv6_parsed[0]
        data_dictionary['flow_label'] = ipv6_parsed[1]
        data_dictionary['hop_limit'] = ipv6_parsed[2]
        data_dictionary['ip_protocol'] = ipv6_parsed[3]
        data_dictionary['protocol_id'] = ipv6_parsed[4]
        data_dictionary['length'] = ipv6_parsed[5]
        data_dictionary['source_ip'] = ipv6_parsed[6]
        data_dictionary['destination_ip'] = ipv6_parsed[7]
        data_dictionary['source_port'] = ipv6_parsed[8]
        data_dictionary['destination_port'] = ipv6_parsed[9]
        data_dictionary['data_length'] = ipv6_parsed[10]
        data_dictionary['tcp_flags'] = ipv6_parsed[11]
        data_dictionary['sequence_number'] = ipv6_parsed[12]
        data_dictionary['ack'] = ipv6_parsed[13]
        data_dictionary['window'] = ipv6_parsed[14]
        data_dictionary['urg'] = ipv6_parsed[15]
        data_dictionary['options'] = ipv6_parsed[16]
    elif ipv6_parsed[3] == 'udp':
        data_dictionary['class'] = ipv6_parsed[0]
        data_dictionary['flow_label'] = ipv6_parsed[1]
        data_dictionary['hop_limit'] = ipv6_parsed[2]
        data_dictionary['ip_protocol'] = ipv6_parsed[3]
        data_dictionary['protocol_id'] = ipv6_parsed[4]
        data_dictionary['length'] = ipv6_parsed[5]
        data_dictionary['source_ip'] = ipv6_parsed[6]
        data_dictionary['destination_ip'] = ipv6_parsed[7]
        data_dictionary['source_port'] = ipv6_parsed[8]
        data_dictionary['destination_port'] = ipv6_parsed[9]
        data_dictionary['data_length'] = ipv6_parsed[10]
    elif ipv6_parsed[3] == 'icmp':
        # print(ipv6_parsed)
        # <to do>
        data_dictionary['ip_protocol'] = ipv6_parsed[3]
    elif ipv6_parsed[3] == 'fragment':
        data_dictionary['class'] = ipv6_parsed[0]
        data_dictionary['flow_label'] = ipv6_parsed[1]
        data_dictionary['hop_limit'] = ipv6_parsed[2]
        data_dictionary['ip_protocol'] = ipv6_parsed[3]
        data_dictionary['protocol_id'] = ipv6_parsed[4]
        data_dictionary['length'] = ipv6_parsed[5]
        data_dictionary['source_ip'] = ipv6_parsed[6]
        data_dictionary['destination_ip'] = ipv6_parsed[7]
        data_dictionary['unknown1'] = ipv6_parsed[8]
        data_dictionary['unknown2'] = ipv6_parsed[9]
        data_dictionary['unknown3'] = ipv6_parsed[10]
    else:
        print("ip protocol unknown")

    return data_dictionary


def parse_logfile(logfile, timezone):
    """
    Parse through the log file and build a dict

    :param logfile: type: list - log file
    :param timezone: type: str - timezone (ex: EST)
    :return: list
    """
    # parse through each line in filter.log
    for line in reversed(logfile):
        data_dictionary = {}

        if "filterlog:" not in line:
            continue  # skip lines without filterlog
        if WAN_INTERFACE_NAME not in line:
            continue  # skip lines not WAN interface

        # split out the log meta data
        # (month, day, h_m_s, source, logtype, logcsv) = line.split(' ', 5) # old, can be deleted
        (month, day, h_m_s, source, logtype, logcsv) = re.split(" +", line, 5)

        # normalize the timestamp: the timestamp does not include the current year
        # this script expects you will run it via cron every give minutes
        # parsing the previous five minutes of data, for this reason it 
        # determines the year in the previous five minutes
        normalized_log_timestamp = "{0}-{1}-{2} {3} {4}".format(year_previous_five_min,
                                                                month,
                                                                day,
                                                                h_m_s,
                                                                timezone)        
        
        # convert log time to epoch time, determine if the log time is older
        # than 5 min (300) seconds, if so stop parsing log and return results.
        # this assumes this script is run via cron every 5 min.
        normalized_date_fmt = "%Y-%b-%d %H:%M:%S %Z"
        log_epoch_time = time.mktime(time.strptime(normalized_log_timestamp, normalized_date_fmt))
        # 2015-10-14 13:21:42.245392
        seconds_past = now_epoch_time - log_epoch_time
        if seconds_past > 300:
            return firewall_logs

        # parse the firewall rules
        logcsv_parsed = logcsv.split(',', 9)
 
        # only parse the line if the firewall blocked the traffic
        # and the traffic was headed into the WAN
        if logcsv_parsed[6] == 'block' and logcsv_parsed[7] == 'in':

            # start building dictionary
            data_dictionary['timestamp'] = str(normalized_log_timestamp)
            data_dictionary['source'] = source
            data_dictionary['logtype'] = logtype
            data_dictionary['rule_number'] = logcsv_parsed[0]
            data_dictionary['sub_rule_number'] = logcsv_parsed[1]
            data_dictionary['anchor'] = logcsv_parsed[2]
            data_dictionary['tracker'] = logcsv_parsed[3]
            data_dictionary['interface'] = logcsv_parsed[4]
            data_dictionary['reason'] = logcsv_parsed[5]
            data_dictionary['action'] = logcsv_parsed[6]
            data_dictionary['direction'] = logcsv_parsed[7]
            data_dictionary['ip_version'] = logcsv_parsed[8]

            # if ip_version is ipv4
            if logcsv_parsed[8] == '4':
                data_dictionary = extract_ipv4(logcsv_parsed[9], data_dictionary)
            # if ip_version is ipv6
            elif logcsv_parsed[8] == '6':
                data_dictionary = extract_ipv6(logcsv_parsed[9], data_dictionary)
            else:
                print("unknown value in ip_version")

        # add dictionary to the list firewall_logs
        firewall_logs.append(data_dictionary)

    return firewall_logs


def submit_to_csirtg(firewall_logs, sent_count):
    """
    Submit IP addresses that have been blocked by the firewall that are TCP and have the tcp_flags = 'S' (SYN)

    :param firewall_logs: type: list - list of dictionaries
    :param sent_count: type: int - number of logs previously submitted to csirtg.io
    :return: int
    """
    uri = CSIRTG_REMOTE + '/users/{0}/feeds/{1}/indicators'.format(CSIRTG_USER, CSIRTG_FEED)
    headers = {
            'Accept': 'application/vnd.csirtg.v0',
            'Authorization': 'Token token=' + CSIRTG_TOKEN,
            'Content-Type': 'application/json',
            }

    for entry in firewall_logs:
        if entry['ip_protocol'] == 'tcp':
            if entry['tcp_flags'] == 'S':
                data = {
                    "indicator": {
                        "thing": entry['source_ip'],
                        "tags": "scanner",
                        "portlist": entry['destination_port'],
                        "portlist_src": entry['source_port'],
                        "protocol": entry['ip_protocol'],
                        "lastime": entry['timestamp'],
                        "description": "sourced from firewall logs (incomming WAN, TCP, Syn, blocked)",
                    }
                }

                sent_count = post_to_csirtg(uri, data, headers, sent_count)
    return sent_count

 
def post_to_csirtg(uri, data, headers, sent_count):
    """
    Post single records to csirtg.io

    :param uri: type: str - csirtg API endpoint
    :param data: type: dict - firewall data to be posted
    :param headers: type: dict - http headers
    :param sent_count: type: int
    :return: int
    """
    data = json.dumps(data)

    try:
        r = requests.post(uri, data, headers=headers)
        if r.status_code == 201:
            sent_count += 1
        else:
            err = "error: status code: {0} message: {1}".format(r.status_code, r.text)
            logger.debug(err)
    except requests.exceptions.ConnectionError:
        logger.debug('connection error to csirtg.io')
    return sent_count
        
   
if __name__ == "__main__":

    sent_count = 0

    logger.info('starting firewall log parser')

    timezone = get_timezone()

    logfile = get_firewall_logs()

    firewall_logs = parse_logfile(logfile, timezone)

    sent_count = submit_to_csirtg(firewall_logs, sent_count)

    logger.info('sent %s ip addresses to csirtg.io', sent_count)
    logger.info('ending firewall log parser')
