#
# IAM AWS messaging mgement
#
# create topic
#

# json classes
import simplejson as json

# import dateutil.parser
import base64
import string
import time
import re
import os.path
from sys import exit
import signal
from optparse import OptionParser

import threading

# syslog shortcuts
import syslog

log=syslog.syslog
log_debug=syslog.LOG_DEBUG
log_info=syslog.LOG_INFO
log_err=syslog.LOG_ERR
log_alert=syslog.LOG_ALERT

from iam_msglib.msglib import iam_init
from iam_msglib.aws import iam_aws_send_message
from iam_msglib.aws import iam_aws_create_topic
from iam_msglib.aws import iam_aws_create_queue
from iam_msglib.aws import iam_aws_subscribe_queue


#
# ---------------- gws_ce main --------------------------
#


# load configuration

parser = OptionParser()
parser.add_option('-o', '--operation', action='store', type='string', dest='operation', help='operation')
parser.add_option('-t', '--topic', action='store', type='string', dest='topic', help='topic')
parser.add_option('-q', '--queue', action='store', type='string', dest='queue', help='queue')
parser.add_option('-v', '--verbose', action='store_true', dest='verbose', help='?')
parser.add_option('-c', '--conf', action='store', type='string', dest='config', help='config file')
options, args = parser.parse_args()

if options.operation==None:
    print 'operation must be entered'
    exit(1)

config_file = 'etc/aws.conf.js'
if options.config!=None:
   config_file = options.config
   print 'using config=' + config_file
f = open(config_file,'r')

config = json.loads(f.read())

iam_init(config)

# logging
log_facility = syslog.LOG_SYSLOG
logf = config['syslog_facility']
if re.match(r'LOG_LOCAL[0-7]', logf): log_facility = eval('syslog.'+logf)

logname = 'aws_create_topic'
if 'log_name' in config: logname = config['log_name']
syslog.openlog(logname, syslog.LOG_PID, log_facility)
log(log_info, "sws queue monitor starting.  (conf='%s')" % (options.config))

if options.operation=='ct':
    print 'creating topic: ' + options.topic
    iam_aws_create_topic(options.topic)
    exit (0)

if options.operation=='cq':
    print 'creating queue: ' + options.queue
    iam_aws_create_queue(options.queue)

if options.operation=='sq':
    print 'subscribing queue: ' + options.queue + ' to topic ' + options.topic
    iam_aws_subscribe_queue(options.topic, options.queue)


