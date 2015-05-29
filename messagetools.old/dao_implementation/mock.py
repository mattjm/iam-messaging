import sys
import os
from os.path import abspath, dirname
import re
import json
import logging
import time
import socket
import settings
# from messagetools.mock.mock_http import MockHTTP

logger = logging.getLogger(__name__)

"""
A centralized the mock data access
"""
fs_encoding = sys.getfilesystemencoding() or sys.getdefaultencoding()


def get_mockdata_message(service_name, queue_name, event_no):
    """
    :param service_name:
        possible "aws", "azure", etc.
    """

    file_path = None
    success = False
    start_time = time.time()

    dir_base = dirname(__file__)
    app_root = abspath(dir_base)
    response = _load_resource_from_path(app_root, service_name, queue_name, event_no)
    if response:
        return response

    # If no event has been found return None
    return response

def _load_resource_from_path(app_root, service_name, queue_name, event_no):

    mock_root = app_root + '/../mock' 
    std_root = mock_root
    if hasattr(settings, 'MESSAGETOOLS_MOCK_ROOT'):
        mock_root = settings.MESSAGETOOLS_MOCK_ROOT
    root = mock_root
    fname = 'event'
    if hasattr(settings, 'MESSAGETOOLS_MOCK_FILENAME'):
        fname = settings.MESSAGETOOLS_MOCK_FILENAME
    fpath = '/' + service_name + '/' + queue_name + '/' + fname + '.' + str(event_no)

    try:
        file_path = convert_to_platform_safe(root + fpath)
        logger.info('mock file: ' + file_path)
        handle = open(file_path)
    except IOError:
        try:
            file_path = convert_to_platform_safe(std_root + fpath)
            logger.info('mock file: ' + file_path)
            handle = open(file_path)
        except IOError:
            return

    data = handle.read()
    logger.debug('data[%s]' % data)
    response = json.loads(data)
    return response



def post_mockdata_url(service_name, implementation_name,
                     url, headers, body,
                     dir_base = dirname(__file__)):
    """
    :param service_name:
        possible "sws", "pws", "book", "hfs", etc.
    :param implementation_name:
        possible values: "file", etc.
    """
    #Currently this post method does not return a response body
    response = MockHTTP()
    if body is not None:
        if "dispatch" in url:
            response.status = 200
        else:
            response.status = 201
        response.headers = {"X-Data-Source": service_name + " file mock data", "Content-Type": headers['Content-Type']}
    else:
        response.status = 400
        response.data = "Bad Request: no POST body"
    return response


def put_mockdata_url(service_name, implementation_name,
                     url, headers, body,
                     dir_base = dirname(__file__)):
    """
    :param service_name:
        possible "sws", "pws", "book", "hfs", etc.
    :param implementation_name:
        possible values: "file", etc.
    """
    #Currently this put method does not return a response body
    response = MockHTTP()
    if body is not None:
        response.status = 204
        response.headers = {"X-Data-Source": service_name + " file mock data", "Content-Type": headers['Content-Type']}
    else:
        response.status = 400
        response.data = "Bad Request: no POST body"
    return response


def delete_mockdata_url(service_name, implementation_name,
                     url, headers,
                     dir_base = dirname(__file__)):
    """
    :param service_name:
        possible "sws", "pws", "book", "hfs", etc.
    :param implementation_name:
        possible values: "file", etc.
    """
    #Http response code 204 No Content:
    #The server has fulfilled the request but does not need to return an entity-body
    response = MockHTTP()
    response.status = 204

    return response

def convert_to_platform_safe(dir_file_name):
    """
    :param dir_file_name: a string to be processed
    :return: a string with all the reserved characters replaced
    """
    return  re.sub('[\?|<>=:*,;+&"@]', '_', dir_file_name)
