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
# IAM messaging tools - Azure interface
#

from sys import exit
from copy import deepcopy

import logging
import json

from .dao import Azure_DAO

class Azure(object):

    # conf is an object 
    def __init__(self, conf):
        self._conf = conf
        
    # Topic actions

    def create_topic(self, name):
        dao = Azure_DAO(self._conf)
        response = dao.create_topic(name)
        return response

    def send_message(self, msg, context, cryptid, signid, properties={}):
        dao = Azure_DAO(self._conf)
        response = dao.send_message(msg, context, cryptid, signid, properties)
        return response


    # Subscription actions

    def create_subscription(self, topic_name, name):
        dao = Azure_DAO(self._conf)
        response = dao.create_subscription(topic_name, name)
        return response

    def recv_message(self, peek=False):
        dao = Azure_DAO(self._conf)
        response = dao.recv_message(peek)
        return response

    def recv_and_process(self, handler, max=1):
        dao = Azure_DAO(self._conf)
        response = dao.recv_and_process(handler, max)
        return response

    def add_rule(self, topic_name, subscription_name, rule_name, rule_value):
        dao = Azure_DAO(self._conf)
        response = dao.add_rule(topic_name, subscription_name, rule_name, rule_value)
        return response

    def remove_rule(self, topic_name, subscription_name, rule_name):
        dao = Azure_DAO(self._conf)
        response = dao.remove_rule(topic_name, subscription_name, rule_name)
        return response
