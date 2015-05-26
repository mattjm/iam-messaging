#
# IAM AWS messaging mgement
#

# json classes
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
from messagetools.aws import AWS

import settings

#
# ---------------- gws_ce main --------------------------
#


# load configuration

parser = OptionParser()
parser.add_option('-o', '--operation', action='store', type='string', dest='operation', help='cq, ct, sq')
parser.add_option('-t', '--topic', action='store', type='string', dest='topic', help='topic')
parser.add_option('-q', '--queue', action='store', type='string', dest='queue', help='queue')
parser.add_option('-v', '--verbose', action='store_true', dest='verbose', help='?')
parser.add_option('-c', '--conf', action='store', type='string', dest='config', help='config file')
options, args = parser.parse_args()

if options.operation==None:
    print 'operation must be entered'
    exit(1)

crypt_init(settings.IAM_CONF)

logging.info("sws queue monitor starting.")

aws = AWS(settings.AWS_CONF)
if options.operation=='ct':
    print 'creating topic: ' + options.topic
    aws.create_topic(options.topic)

if options.operation=='cq':
    print 'creating queue: ' + options.queue
    aws.create_queue(options.queue)

if options.operation=='sq':
    print 'subscribing queue: ' + options.queue + ' to topic ' + options.topic
    aws.subscribe_queue(options.topic, options.queue)


