#  ========================================================================
#  Copyright (c) 2015 The University of Washington
# 
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
# 
#      http://www.apache.org/licenses/LICENSE-2.0
# 
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#  ========================================================================
#

#
# IAM messaging tools - AWS interface
#

# AWS interface classes 
from boto.sqs.connection import SQSConnection
from boto.sqs.message import RawMessage
from boto.sns import SNSConnection


# import datetime
# import dateutil.parser
# import base64
# import string
# import time
# import re
# import os.path
from sys import exit
# import signal
from copy import deepcopy

from msglib import iam_format_message
from msglib import iam_process_message

# import threading

# syslog shortcuts
import syslog

log=syslog.syslog
log_debug=syslog.LOG_DEBUG
log_info=syslog.LOG_INFO
log_err=syslog.LOG_ERR
log_alert=syslog.LOG_ALERT

# ----- global vars (mostly from config file) ------------------

# config structure
_aws_config = None

def iam_get_aws_queue():
    global _aws_config 

    sqs_connection = SQSConnection(_aws_config['sqsKeyId'], _aws_config['sqsKey'])
    queue = sqs_connection.get_queue(_aws_config['sqsQueue'])
    if queue==None:
        log(log_alert, "Could not connect to '%s'!" % (_aws_config['sqsQueue']))
        return none
    queue.set_message_class(RawMessage)
    log(log_info, '%r messages in the queue' % (queue.count()))
    # print '%r messages in the queue' % (queue.count())
    return queue


def iam_aws_send_message(msg, context, cryptid, signid):
    global _aws_config 
    b64msg = iam_format_message(msg, context, cryptid, signid)
    sns_connection = SNSConnection(_aws_config['snsKeyId'], _aws_config['snsKey'])
    if sns_connection==None:
        log.error('AWS connect failed')
        return none
    arn = _aws_config['snsArn']
    sns_connection.publish(arn, b64msg, 'iam-message')

    
def iam_aws_recv_message():
    sqs_queue = iam_get_aws_queue()
    sqs_msg = sqs_queue.read()
    if sqs_msg == None:
        return None
    msg = iam_process_message(sqs_msg)
    if msg != None:
        sqs_queue.delete_message(sqs_msg)
    return msg

def iam_aws_init(awscfg):
    global _aws_config 
    _aws_config = deepcopy(awscfg)


