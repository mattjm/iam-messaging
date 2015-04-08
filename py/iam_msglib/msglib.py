#  ========================================================================
#  Copyright (c) 2015 The University of Washington
# 
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
# 
#        http://www.apache.org/licenses/LICENSE-2.0
# 
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#  ========================================================================
#

#
# IAM messaging tools - common 
#

# crypto class covers for openssl
import M2Crypto
from M2Crypto import BIO, RSA, EVP, X509

import simplejson as json
import uuid
import datetime
import dateutil.parser
import base64
import string
import time
import re
import os.path
from sys import exit
import signal
import importlib

import urllib3

import threading

# syslog shortcuts
import syslog

log=syslog.syslog
log_debug=syslog.LOG_DEBUG
log_info=syslog.LOG_INFO
log_err=syslog.LOG_ERR
log_alert=syslog.LOG_ALERT

# ----- global vars (to this module) ------------------

# decryption keys
_crypt_keys = {}

# public keys used for sig verify
_public_keys = {}

# private keys used for sig sign
_private_keys = {}

# ca certificate file
_ca_file = None

#
# -------------------------------------
#
def log_message_and_exit(message):
    log.info(message)
    exit(1) 

#
# accumulate header fields for signature
#
def _build_sig_msg(header, txt):
  
    sigmsg = header[u'contentType'] + '\n'
    if 'keyId' in header:
        sigmsg = sigmsg + header[u'iv'] + '\n' + header[u'keyId'] + '\n'
    sigmsg = sigmsg + header[u'messageContext'] + '\n' + header[u'messageId'] + '\n' + \
         header[u'messageType'] + '\n' + header[u'sender'] + '\n' + \
         header[u'signingCertUrl'] + '\n' + header[u'timestamp'] + '\n' + header[u'version'] + '\n' + \
         txt + '\n'
    return sigmsg


#
# send an iam message
#
#  msg is anything
#  context is string

def iam_format_message(msg, context, cryptid, signid):
    
    iamHeader = {}
    iamHeader['contentType'] = 'json'
    iamHeader['version'] = 'UWIT-1'
    iamHeader['messageType'] = 'iam-test'
    u = uuid.uuid4()
    iamHeader['messageId'] = str(u)
    iamHeader['messageContext'] = base64.b64encode(context)
    iamHeader['sender'] = 'iam-msg'

    iamHeader['timestamp'] = datetime.datetime.utcnow().isoformat()
    iamHeader['signingCertUrl'] = _private_keys[signid]['url']

    if cryptid!=None:
        iamHeader['keyId'] = cryptid
        iv = os.urandom(16)
        iamHeader['iv'] = base64.b64encode(iv)
        cipher = M2Crypto.EVP.Cipher(alg='aes_128_cbc', key=_crypt_keys[cryptid], iv=iv, op=1)
        txt = cipher.update(msg) + cipher.final()
        enctxt64 = base64.b64encode(txt)
    else:
        enctxt64 = base64.b64encode(msg)
    
    # gen the signature
    sigmsg = _build_sig_msg(iamHeader, enctxt64)

    key = _private_keys[signid]['key']
    key.sign_init()
    key.sign_update(sigmsg)
    sig = key.sign_final()
    sig64 = base64.b64encode(sig)
    iamHeader['signature'] = sig64

    body = {}
    body['Message'] = enctxt64
  
    iamMessage = {}
    iamMessage['header'] = iamHeader
    iamMessage['body'] = enctxt64

    m64 = base64.b64encode(json.dumps(iamMessage))
    return m64
    
#
# process an Iam message
#

def iam_process_message(message):
    global _crypt_keys 
    global _public_keys 
    global _ca_file 

    # get the body of the SQS message
    sqsstr = message.get_body().encode('utf8','ignore')  # signature, et.al. needs utf8
    sqsmsg = json.loads(sqsstr)

    # get the iam message
    msgstr = base64.b64decode(sqsmsg['Message']).encode('utf8','ignore')
    iam_message = json.loads(msgstr)

    if 'header' not in iam_message: 
        log.info('not an iam message')
        return None
    iamHeader = iam_message['header']

    try:
      # check the version
      if iamHeader[u'version'] != 'UWIT-1':
          log(log_err, 'unknown version: ' + iamHeader[u'version'])
          return None

      # the signing cert should be cached most of the time
      certurl = iamHeader[u'signingCertUrl']
      if not certurl in _public_keys:
          log(log_info, 'Fetching signing cert: ' + certurl)
          pem = ''

          if certurl.startswith('file:'):
              with open(certurl[5:], 'r') as f:
                  pem = f.read()

          elif certurl.startswith('http'):
              if _ca_file != None:
                  http = urllib3.PoolManager(
                      cert_reqs='CERT_REQUIRED', # Force certificate check.
                      ca_certs=_ca_file,  
                  )
              else:
                  http = urllib3.PoolManager()
              certdoc = http.request('GET', certurl)
              if certdoc.status != 200:
                  log(log_err, 'sws cert get failed: ' + certdoc.status)
                  log_message_and_exit (sqsstr)  # can't go on
              log(log_debug, 'got it')
              pem = certdoc.data
          else:
              log_message_and_exit ('invalid cert url: ' + certurl)

          x509 = X509.load_cert_string(pem)
          key = x509.get_pubkey()
          _public_keys[certurl] = key

      enctxt64 = iam_message[u'body']

      # check the signature
      sigmsg = _build_sig_msg(iamHeader, enctxt64)
      sig = base64.b64decode(iamHeader[u'signature'])
      pubkey = _public_keys[certurl]

      pubkey.reset_context(md='sha1')
      pubkey.verify_init()
      pubkey.verify_update(sigmsg)
      if pubkey.verify_final(sig)!=1:
          log(log_err, '*** signature fails verification ***')
          log_message_and_exit(sqsstr)  # can't go on

      # decrypt the message
      if 'keyId' in iamHeader:
          iv64 = iamHeader[u'iv']
          iv = base64.b64decode(iv64)
          keyid = iamHeader[u'keyId']
          if not keyid in _crypt_keys:
              log(log_err, 'key ' + keyid + ' not found')
              log_message_and_exit(sqsstr)  # can't go on
          key = _crypt_keys[keyid]
 
          enctxt =  base64.b64decode(enctxt64)
          cipher = M2Crypto.EVP.Cipher(alg='aes_128_cbc', key=key, iv=iv, op=0)
          txt = cipher.update(enctxt) + cipher.final()
      else:
          txt = base64.b64decode(enctxt64)

      txt = filter(lambda x: x in string.printable, txt)
      iam_message[u'body'] = txt
      # un-base64 the context
      try:
          iamHeader[u'messageContext'] = base64.b64decode(iamHeader[u'messageContext'])
      except TypeError:
          log(log_info,  'context not base64')
          return None
    except KeyError:
        if 'AlarmName' in iam_message:
            log(log_debug, 'alarm: ' + iam_message['AlarmName'])
            return iam_message

        log(log_err, 'Unknown message key: ' )
        return None

    return iam_message


def iam_init(cfg):
    global _crypt_keys
    global _public_keys
    global _ca_file

    # load the signing keys
    certs = cfg['certs']
    for c in certs:
        id = c['id']
        crt = {}
        crt['url'] = c['url']
        crt['key'] = EVP.load_key(c['keyfile'])
        _private_keys[id] = crt


    # load the cryption key
    keys = cfg['crypts']
    for k in keys:
        id = k['id']
        k64 = k['key']
        log(log_debug,  'adding crypt key ' + id)
        kbin = base64.b64decode(k64)
        _crypt_keys[id] = kbin

    # are we verifying certs ( just for the signing cert )
    if 'ca_file' in cfg:
        _ca_file = cfg['ca_file']
        
    # configure brokers

    if 'aws' in cfg:
        aws = importlib.import_module('iam_msglib.aws')
        aws.iam_aws_init(cfg['aws'])

    if 'azure' in cfg:
        azure = importlib.import_module('iam_msglib.azure')
        azure.iam_azure_init(cfg['azure'])

