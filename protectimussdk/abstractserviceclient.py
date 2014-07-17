# -*- coding: utf-8 -*-

import sys
import urllib
import urllib2
import base64
import hashlib
import calendar
from datetime import datetime
from rfc3987 import parse
from protectimussdk.exception.protectimusapiexception import ProtectimusApiException
from protectimussdk.enum.responseformat import ResponseFormat, XMLResponseFormat

PUT_METHOD = 0
DELETE_METHOD = 1

class AbstractServiceClient(object):
    def __init__(self, apiUrl, username, apiKey, responseFormat, version):
        try:
            self.apiUrl = parse(apiUrl, rule='URI')
        except ValueError:
            raise ProtectimusApiException("API URL = [%s] has invalid format" % apiUrl)

        if username is None:
            raise ProtectimusApiException("Authentication is required. Please, specify username.")
        self.username = username

        if apiKey is None:
            raise ProtectimusApiException("Authentication is required. Please, specify apiKey.")
        self.apiKey = apiKey

        if responseFormat is None or not isinstance(responseFormat, ResponseFormat):
            self.responseFormat = XMLResponseFormat()
        else:
            self.responseFormat = responseFormat

        self.baseUrl = '%s://%s%s' % (self.apiUrl['scheme'], self.apiUrl['authority'], self.apiUrl['path'])
        if self.baseUrl[-1:] != '/':
            self.baseUrl += '/'

        self.version = version

    def serviseUri(self):
        servUri = self.baseUrl + 'api'
        if self.version is not None:
            servUri = '%s/%s/%s/' % (servUri, self.version, self.serviseName())
        else:
            servUri = '%s/%s/' % (servUri, self.serviseName())
        return servUri

    def serviseName(self):
        raise NotImplementedError("Please Implement this method")

    def extension(self):
        return self.responseFormat.extension()

    def webResource(self, path, form = None, params = None, method = None):
        if params is not None:
            encoded_params = '?%s' % urllib.urlencode(params)
        else:
            encoded_params = ''
        req = urllib2.Request('%s%s%s' % (self.serviseUri(), path, encoded_params))
        if method is not None:
            if method == PUT_METHOD:
                req.get_method = lambda: 'PUT'

            if method == DELETE_METHOD:
                req.get_method = lambda: 'DELETE'

        m = hashlib.sha256()
        m.update("%s:%s" % (self.apiKey, datetime.utcnow().strftime('%Y%m%d:%H')))
        hashVal = m.hexdigest()
        base64string = base64.encodestring('%s:%s' % (self.username, hashVal)).replace('\n', '')
        req.add_header("Authorization", "Basic %s" % base64string)

        try:
            if form is None:
                handle = urllib2.urlopen(req)
            else:
                form_data = urllib.urlencode(form)
                handle = urllib2.urlopen(req, form_data)
        except urllib2.HTTPError:
            e = sys.exc_info()[1]
            raise ProtectimusApiException("Failed to create API client: %s" % e)

        return handle.read()

    def processFormData(self, form):
        for key in form.keys():
            if form[key] is None:
                form[key] = ''
            if isinstance(form[key], bool):
                form[key] = str(form[key]).lower()
        return form
