# -*- coding: utf-8 -*-

class ResponseFormat(object):
    def extension(self):
        raise NotImplementedError("Please Implement this method")

class XMLResponseFormat(ResponseFormat):
    def extension(self):
        return '.xml'

class JSONResponseFormat(ResponseFormat):
    def extension(self):
        return '.json'