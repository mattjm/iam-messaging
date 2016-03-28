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
# IAM messaging tools - DAO impl - AWS interface
#

import re


# AWS interface classes 
#from boto3.data.sqs.message import RawMessage
#import boto3
#from boto3 import Session
import boto
from boto.sqs.message import RawMessage

import json

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

from messagetools.iam_message import encode_message
from messagetools.iam_message import decode_message
from messagetools.dao_implementation.mock import get_mockdata_message

import logging
logger = logging.getLogger(__name__)

class File(object):

    def __init__(self, conf):
        self._conf = conf
        self._event_no = 0

    def recv_message(self):
        message = get_mockdata_message('aws', self._conf, self._event_no)
        self._event_no += 1
        return message
    
    def recv_and_process(self, handler, max=1):
        ntot = 0
        nvalid = 0
        logger = logging.getLogger(__name__)

        logger.debug('recv and proc: no=%d, max=%d' % (self._event_no, max))
        for n in range(0,max):
           message = get_mockdata_message('aws', self._conf, self._event_no)
    
           if message==None: 
               break
           self._event_no += 1
           ret = handler(message)
           if ret:
               nvalid += 1
           ntot += 1
        return (ntot, nvalid)
    
    

class Live(object):

    def __init__(self, conf):
        self._conf = conf
        #boto3 testing
        #self.session = Session(aws_access_key_id=self._conf['SQS_KEYID'], aws_secret_access_key=self._conf['SQS_KEY'], region_name=self._conf['REGION_NAME'])
        
    def send_message(self, msg, context, cryptid, signid):
        sns_connection = boto3.connect_sns(aws_access_key_id=self._conf['SNS_KEYID'], aws_secret_access_key=self._conf['SNS_KEY'])
        b64msg = encode_message(msg, context, cryptid, signid)
        sns_connection.publish(self._conf['SNS_ARN'], b64msg, 'iam-message')


    def get_all_queues(self):
        sqs_connection = boto.connect_sqs(aws_access_key_id=self._conf['SQS_KEYID'], aws_secret_access_key=self._conf['SQS_KEY'])
        queues = sqs_connection.get_all_queues()
        return queues
       
    def get_queue(self):
        #boto2
        #sqs_connection = boto3.connect_sqs(aws_access_key_id=self._conf['SQS_KEYID'], aws_secret_access_key=self._conf['SQS_KEY'])
        #boto3
        #sqs_connection = boto3.client('sqs', aws_access_key_id=self._conf['SQS_KEYID'], aws_secret_access_key=self._conf['SQS_KEY'])
        #sqs_connection = self.session.client('sqs')
        # sqs_connection = self.session.resource('aws/sqs')
        #queue_url = sqs_connection.get_queue_url(QueueName=self._conf['SQS_QUEUE'])
        #queue = sqs_connection.receive_message(QueueUrl=queue_url['QueueUrl'])
        sqs_connection = boto.connect_sqs(aws_access_key_id=self._conf['SQS_KEYID'], aws_secret_access_key=self._conf['SQS_KEY'])
        queue = sqs_connection.get_queue(self._conf['SQS_QUEUE'])
        if queue==None:
            logger.critical("Could not connect to '%s'!" % (self._conf['SQS_QUEUE']))
            return queue
        #queue.set_message_class(RawMessage)
        logger.debug('%r messages in the queue' % (queue.count()))
        return queue
            
        
    def create_topic(self, topic_name):
        sns_connection = boto.connect_sns(aws_access_key_id=self._conf['SNS_KEYID'], aws_secret_access_key=self._conf['SNS_KEY'])
        if sns_connection==None:
            loger.error('AWS sns connect failed')
            return none
        ret = sns_connection.create_topic(topic_name)
        if ret==None:
            log.error('AWS topic create failed for %s' % topic_name)
            return none
        return ret


    def create_queue(self, queue_name):
        sqs_connection = boto.connect_sqs(aws_access_key_id=self._conf['SQS_KEYID'], aws_secret_access_key=self._conf['SQS_KEY'])
        if sqs_connection==None:
            loger.error('AWS sqs connect failed')
            return none
        ret = sqs_connection.create_queue(queue_name)
        if ret==None:
            logger.error('AWS queue create failed for %s' % queue_name)
        return ret


    def recv_message(self):
        sqs_queue = self.get_queue()
        sqs_msg = sqs_queue.read()
        if sqs_msg == None:
            return None
        #no implicit byte/string conversions in python3
        sqsmsg = json.loads(sqs_msg.get_body().encode('utf8','ignore').decode('utf-8','ignore'))
        msg = decode_message(sqsmsg['Message'])
        logger.debug('live recv: [%s]' % json.dumps(msg))
        if msg != None:
            sqs_queue.delete_message(sqs_msg)
        return msg
    
    def recv_and_process(self, handler, max=1):
        sqs_queue = self.get_queue()
        msgs = sqs_queue.get_messages(max)
        nmsg = len(msgs)
        logger.info('live recv-proc: %d msg, max=%d' % (nmsg, max))
        nvalid = 0
        for m in msgs:
            
            #no implicit byte/string conversions in python3
            sqsmsg = json.loads(m.get_body().encode('utf8','ignore').decode('utf-8','ignore'))
            msg = decode_message(sqsmsg['Message'])
            
            if msg==None:
                sqs_queue.delete_message(m)
                continue
            nvalid += 1
            ret = handler(msg)
            if ret:
                sqs_queue.delete_message(m)
        return (nmsg, nvalid)
    
    def subscribe_queue(self, topic_name, queue_name):
        sns_connection = boto.connect_sns(aws_access_key_id=self._conf['SNS_KEYID'], aws_secret_access_key=self._conf['SNS_KEY'])
        sqs_connection = boto.connect_sqs(aws_access_key_id=self._conf['SQS_KEYID'], aws_secret_access_key=self._conf['SQS_KEY'])
        queue = sqs_connection.get_queue(queue_name)
        arn = self._conf['SNS_ARNROOT'] + topic_name
        sns_connection.subscribe_sqs_queue(arn, queue)

    def purge_queue(self):
        sqs_queue = self.get_queue()
        sqs_queue.purge()
        return

    

