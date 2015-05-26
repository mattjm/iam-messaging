# iam-messaging implementation for non-django applications

import settings 

# from messagetools.mock.mock_http import MockHTTP
from messagetools.dao_implementation.aws import File as AWSFile
from messagetools.dao_implementation.aws import Live as AWSLive
from messagetools.dao_implementation.ms_azure import File as AzureFile
from messagetools.dao_implementation.ms_azure import Live as AzureLive

class DAO_BASE(object):
             
    def __init__(self, conf):
        self._conf = conf

    def _create_topic(self, name):
        dao = self._getDAO()
        response = dao.create_topic(name)
        return response

    def _send_message(self, msg, context, cryptid, signid):
        dao = self._getDAO()
        response = dao.send_message(msg, context, cryptid, signid)
        return response

    def _create_queue(self, name):
        dao = self._getDAO()
        response = dao.create_queue(name)
        return response

    def _create_subscription(self, topic_name, name):
        dao = self._getDAO()
        response = dao.create_subscription(topic_name, name)
        return response

    def _recv_message(self):
        dao = self._getDAO()
        response = dao.recv_message()
        return response

    def _recv_and_process(self, handler, max=1):
        dao = self._getDAO()
        response = dao.recv_and_process(handler, max)
        return response

    def _subscribe_queue(self, topic_name, queue_name):
        dao = self._getDAO()
        response = dao.subscribe_queue(topic_name, queue_name)
        return response



class AWS_DAO(DAO_BASE):

    def create_topic(self, name):
        return self._create_topic(name)

    def send_message(self, msg, context, cryptid, signid):
        return self._send_message(msg, context, cryptid, signid)

    def create_queue(self, name):
        return self._create_queue(name)

    def recv_message(self):
        return self._recv_message()

    def recv_and_process(self, handler, max=1):
        return self._recv_and_process(handler, max)

    def subscribe_queue(self, topic_name, queue_name):
        return self._subscribe_queue(topic_name, queue_name)

    def _getDAO(self):
        if settings.RUN_MODE=='Live':
            return AWSLive(self._conf)
        return AWSFile(self._conf)



class Azure_DAO(DAO_BASE):

    def create_topic(self, name):
        return self._create_topic(name)

    def send_message(self, msg, context, cryptid, signid, properties):
        dao = self._getDAO()
        response = dao.send_message(msg, context, cryptid, signid, properties)
        return response

    def was_send_message(self, msg, context, cryptid, signid, properties):
        return self._send_message(msg, context, cryptid, signid, properties)

    def create_subscription(self, topic_name, name):
        return self._create_subscription(topic_name, name)

    def recv_message(self):
        return self._recv_message()

    def recv_and_process(self, handler, max=1):
        return self._recv_and_process(handler, max)

    def subscribe_queue(self, topic_name, queue_name):
        return self._subscribe_queue(topic_name, queue_name)

    def add_rule(self, topic_name, subscription_name, rule_name, rule_value):
        dao = self._getDAO()
        response = dao.add_rule(topic_name, subscription_name, rule_name, rule_value)
        return response

    def remove_rule(self, topic_name, subscription_name, rule_name):
        dao = self._getDAO()
        response = dao.remove_rule(topic_name, subscription_name, rule_name)
        return response

    def _getDAO(self):
        if settings.RUN_MODE=='Live':
            return AzureLive(self._conf)
        return AzureFile(self._conf)



