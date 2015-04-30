#
# IAM Azure messaging mgement
#

import json

import base64
import string
import time
import re
import os.path
from sys import exit
import signal
from optparse import OptionParser

import threading
import logging

from messagetools.iam_message import crypt_init
from messagetools.ms_azure import Azure

import settings

#
# ---------------- gws_ce main --------------------------
#

ophelp = 'ct (create topic)\ncs (create subscription)\nar (add rule)\nrr (remove rule)'
parser = OptionParser()
parser.add_option('-o', '--operation', action='store', type='string', dest='operation', help=ophelp)
parser.add_option('-t', '--topic', action='store', type='string', dest='topic', help='topic')
parser.add_option('-s', '--subscription', action='store', type='string', dest='subscription', help='subscription')
parser.add_option('-v', '--verbose', action='store_true', dest='verbose', help='?')
parser.add_option('', '--rule-name', action='store', dest='rule_name', help='the rule\'s name (-default- for the default rule)')
parser.add_option('', '--rule-value', action='store', dest='rule_value', help='the rule\'s value')
options, args = parser.parse_args()

if options.operation==None:
    print 'operation must be entered'
    exit(1)

logger = logging.getLogger()
logging.config.dictConfig(settings.LOGGING)
logging.info("Azure servicebus manager starting.")

conf = settings.AZURE_CONF_2
azure = Azure(conf)
if options.operation=='ct':
    if options.topic is None:
        print('create topic needs topic name')
        exit 
    logger.info("create topic: namespace='%s', topic='%s'" % (conf['NAMESPACE'], options.topic))
    azure.create_topic(options.topic)

if options.operation=='cs':
    if options.topic is None:
        print('create subscription needs topic name')
        exit 
    if options.subscription is None:
        print('create subscription needs subscription name')
        exit 
    logger.info("create subscription: namespace='%s', topic='%s', subscription='%s'" %
        (conf['NAMESPACE'], options.topic, options.subscription))
    azure.create_subscription(options.topic, options.subscription)

if options.operation=='ar':
    if options.topic is None:
        print('add rule needs topic name')
        exit 
    if options.subscription is None:
        print('add rule needs subscription name')
        exit 
    if options.rule_name is None:
        print('add rule needs rule name')
        exit 
    if options.rule_value is None:
        print('add rule needs rule value')
        exit 
    logger.info("add rule: namespace='%s', topic='%s', subscription='%s', name='%s', value='%s'" %
        (conf['NAMESPACE'], options.topic, options.subscription, options.rule_name, options.rule_value))
    azure.add_rule(options.topic, options.subscription, options.rule_name, options.rule_value)

if options.operation=='rr':
    if options.topic is None:
        print('remove rule needs topic name')
        exit 
    if options.subscription is None:
        print('remove rule needs subscription name')
        exit 
    if options.rule_name is None:
        print('remove rule needs rule name')
        exit 
    logger.info("remove rule: namespace='%s', topic='%s', subscription='%s', name='%s'" %
        (conf['NAMESPACE'], options.topic, options.subscription, options.rule_name))
    azure.remove_rule(options.topic, options.subscription, options.rule_name)

