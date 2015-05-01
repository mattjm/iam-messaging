#
# IAM AWS messaging tools
#
# sig tester
#

import json

import dateutil.parser
import base64
import string
import time
import re
import os.path
from sys import exit

import threading

import logging.config

from messagetools.iam_message import crypt_init
from messagetools.iam_message import encode_message
from messagetools.iam_message import decode_message

import settings

#
# ---------------- gws_ce main --------------------------
#


logging.config.dictConfig(settings.LOGGING)
logger = logging.getLogger()
logger.info("sig tester starting.")

crypt_init(settings.IAM_CONF)

msg = 'Hello, world, from py.'

sigkey = 'iamsig11'
cryptkey = 'iamcrypt1'

a = encode_message(msg, 'spud', cryptkey, sigkey)
b = decode_message(a)
print(b)



