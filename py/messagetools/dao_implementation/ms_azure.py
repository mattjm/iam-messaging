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
# IAM messaging tools - DAO impl - Azure interface
#

import re
import json


# Azure interface classes 
from azure.servicebus import ServiceBusService, Message, Topic, Rule, DEFAULT_RULE_NAME


from copy import deepcopy

from messagetools.iam_message import encode_message
from messagetools.iam_message import decode_message
from messagetools.dao_implementation.mock import get_mockdata_message

import logging
logger = logging.getLogger(__name__)

class File(object):

    def __init__(self, config):

        self._event_no = 0

    def recv_message(self):
        message = get_mockdata_message('ms_azure', self._config['SQS_QUEUE'], self._event_no)
        self._event_no += 1
        return message
    
    def recv_and_process(self, handler, max=1):
        ntot = 0
        nvalid = 0

        logger.debug('recv and proc: no=%d, max=%d' % (self._event_no, max))
        for n in range(0,max):
           message = get_mockdata_message('ms_azure', self._config['SQS_QUEUE'], self._event_no)
         
           if message==None: 
               break
           self._event_no += 1
           ret = handler(message)
           if ret:
               nvalid += 1
           ntot += 1
        return (ntot, nvalid)
    
    

class Live(object):

    def __init__(self, config):
        self._config = config
        self._topic = config['TOPIC_NAME']
        self._subscr = config['SUBSCRIPTION_NAME']

    def _get_bus_service(self):
        return ServiceBusService(service_namespace=self._config['NAMESPACE'],
                                 shared_access_key_name=self._config['ACCESS_KEY_NAME'],
                                 shared_access_key_value=self._config['ACCESS_KEY_VALUE'])

    def send_message(self, msg, context, cryptid, signid, properties={}):
        bus_service = self._get_bus_service()
        b64msg = encode_message(msg, context, cryptid, signid)
        ms_msg = Message(b64msg, custom_properties=properties)
        bus_service.send_topic_message(self._config['TOPIC_NAME'], ms_msg)

    def create_topic(self, topic_name):
        bus_service = self._get_bus_service()
        bus_service.create_topic(topic_name)

    def create_subscription(self, topic_name, name):
        bus_service = self._get_bus_service()
        bus_service.create_subscription(topic_name, name)

    def recv_message(self, peek=False):
        subscription_name=self._config['SUBSCRIPTION_NAME']
        topic_name = self._config['TOPIC_NAME']
        bus_service = self._get_bus_service()
        ms_msg = bus_service.receive_subscription_message(topic_name, subscription_name, peek_lock=peek)
        msg = decode_message(ms_msg.body)
        if peek:
            return (msg, ms_msg.delete, ms_msg.unlock)
        else:
            return msg
    
    def recv_and_process(self, handler, max=1):
        bus_service = self._get_bus_service()
        ms_msg = bus_service.receive_subscription_message(self._topic, self._subscr, peek_lock=True)
        ret = handler(decode_message(ms_msg.body))
        if ret:
            ms_msg.delete()
        else:
            ms_msg.unlock()
        return 1
