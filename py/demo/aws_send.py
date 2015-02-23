#
# IAM AWS messaging tools
#
# sample sns sender
#

# json classes
import simplejson as json

import dateutil.parser
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


#
# ---------------- gws_ce main --------------------------
#


# load configuration

parser = OptionParser()
parser.add_option('-m', '--message', action='store', type='string', dest='message', help='message')
parser.add_option('-v', '--verbose', action='store_true', dest='verbose', help='?')
parser.add_option('-c', '--conf', action='store', type='string', dest='config', help='config file')
parser.add_option('-n', '--nocrypt', action='store_true', dest='nocrypt', default='false', help='dont encrypt message')
options, args = parser.parse_args()

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

logname = 'iam_send'
if 'log_name' in config: logname = config['log_name']
syslog.openlog(logname, syslog.LOG_PID, log_facility)
log(log_info, "sws queue monitor starting.  (conf='%s')" % (options.config))

msg = 'Hello, world, from py.'
if options.message!=None:
   msg = options.message

cryptkey = 'iamcrypt1'
if options.nocrypt:
   cryptkey = None

#
# send
#

iam_aws_send_message(msg, 'something specific to the test', cryptkey, 'iamsig1')


