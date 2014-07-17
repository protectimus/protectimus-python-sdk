# -*- coding: utf-8 -*-

import sys
from lxml import etree
from StringIO import StringIO
from decimal import *
from protectimussdk.entity.resource import Resource
from protectimussdk.entity.token import Token
from protectimussdk.entity.user import User
from protectimussdk.entity.prepare import Prepare
from protectimussdk.exception.protectimusapiexception import ProtectimusApiException
from protectimussdk.enum.tokentype import getTokenTypeByName

def toBool(value):
    """
       Converts 'something' to boolean. Raises exception for invalid formats
           Possible True  values: 1, True, "1", "TRue", "yes", "y", "t"
           Possible False values: 0, False, None, [], {}, "", "0", "faLse", "no", "n", "f", 0.0, ...
    """
    if str(value).lower() in ("yes", "y", "true",  "t", "1"): return True
    if str(value).lower() in ("no",  "n", "false", "f", "0", "0.0", "", "none", "[]", "{}"): return False
    raise Exception('Invalid value for boolean conversion: ' + str(value))

def checkStatus(input):
    tree = etree.parse(StringIO(input))
    status = tree.xpath('/responseHolder/status')
    if len(status) == 1:
        if status[0].text == 'FAILURE':
            message = tree.xpath('/responseHolder/error/message')
            developerMessage = tree.xpath('/responseHolder/error/developerMessage')
            exceptionText = ''
            if len(message) == 1:
                exceptionText = message[0].text
            if len(developerMessage) == 1:
                exceptionText += ' ' + developerMessage[0].text
            raise ProtectimusApiException(exceptionText)
        else:
            return tree
    else:
        raise ProtectimusApiException("Failed to parse response")

def parseBalance(input):
    tree = checkStatus(input)
    balance = tree.xpath('/responseHolder/response/balance')
    if len(balance) > 0:
        try:
            return Decimal(balance[0].text)
        except InvalidOperation:
            e = sys.exc_info()[0]
            raise ProtectimusApiException("Failed to parse response: %s" % e)
    else:
        raise ProtectimusApiException("Failed to parse response")

def parsePrepareString(input):
    tree = checkStatus(input)
    p = Prepare()
    if len(tree.xpath('/responseHolder/response/challenge')) > 0:
        p.challenge = tree.xpath('/responseHolder/response/challenge')[0].text
    if len(tree.xpath('/responseHolder/response/tokenName')) > 0:
        p.tokenName = tree.xpath('/responseHolder/response/tokenName')[0].text
    if len(tree.xpath('/responseHolder/response/tokenType')) > 0:
        p.tokenType = tree.xpath('/responseHolder/response/tokenType')[0].text
    return p

def parseAuthenticationResult(input):
    tree = checkStatus(input)
    result = tree.xpath('/responseHolder/response/result')
    if len(result) == 1:
        try:
            return toBool(result[0].text)
        except Exception:
            raise ProtectimusApiException("Failed to parse response")
    else:
        raise ProtectimusApiException("Failed to parse response")

def __parseResourceEntity(res):
    r = Resource()
    if len(res.xpath('id')) == 1:
        r.id = int(res.xpath('id')[0].text)
    if len(res.xpath('name')) == 1:
        r.name = res.xpath('name')[0].text
    if len(res.xpath('failedAttemptsBeforeLock')) == 1:
        r.failedAttemptsBeforeLock = int(res.xpath('failedAttemptsBeforeLock')[0].text)

    if len(res.xpath('geoFilterId')) == 1:
        r.geoFilterId = int(res.xpath('geoFilterId')[0].text)
    if r.geoFilterId is not None:
        r.geoFilterName = int(res.xpath('geoFilterName')[0].text)
        r.geoFilterEnabled = toBool(res.xpath('geoFilterEnabled')[0].text)

    if len(res.xpath('timeFilterId')) == 1:
        r.timeFilterId = int(res.xpath('timeFilterId')[0].text)
    if r.timeFilterId is not None:
        r.timeFilterName = int(res.xpath('timeFilterName')[0].text)
        r.timeFilterEnabled = toBool(res.xpath('timeFilterEnabled')[0].text)

    if len(res.xpath('creatorId')) == 1:
        r.creatorId = int(res.xpath('creatorId')[0].text)
    if r.creatorId is not None and len(res.xpath('creatorUsername')) == 1:
        r.creatorUsername = res.xpath('creatorUsername')[0].text

    return r

def parseResources(input):
    result = []
    tree = checkStatus(input)
    resList = tree.xpath('/responseHolder/response/resources//resource')
    for res in resList:
        result.append(__parseResourceEntity(res))

    return result

def parseResource(input):
    tree = checkStatus(input)
    res = tree.xpath('/responseHolder/response/resource')
    if len(res) == 1:
        return __parseResourceEntity(res[0])
    else:
        raise ProtectimusApiException("Failed to parse response")

def parseQuantity(input):
    tree = checkStatus(input)
    quantity = tree.xpath('/responseHolder/response/quantity')
    if len(quantity) == 1:
        return int(quantity[0].text)
    else:
        raise ProtectimusApiException("Failed to parse response")

def parseId(input):
    tree = checkStatus(input)
    idval = tree.xpath('/responseHolder/response/id')
    if len(idval) == 1:
        return int(idval[0].text)
    else:
        raise ProtectimusApiException("Failed to parse response")

def __parseTokenEntity(token):
    t = Token()
    if len(token.xpath('id')) == 1:
        t.id = int(token.xpath('id')[0].text)
    if len(token.xpath('name')) == 1:
        t.name = token.xpath('name')[0].text
    if len(token.xpath('type')) == 1:
        t.type = getTokenTypeByName(token.xpath('type')[0].text)
    if len(token.xpath('serialNumber')) == 1:
        t.serialNumber = token.xpath('serialNumber')[0].text
    if len(token.xpath('enabled')) == 1:
        t.enabled = toBool(token.xpath('enabled')[0].text)
    if len(token.xpath('apiSupport')) == 1:
        t.apiSupport = toBool(token.xpath('apiSupport')[0].text)
    if len(token.xpath('userId')) == 1:
        t.userId = int(token.xpath('userId')[0].text)
    if len(token.xpath('clientStaffId')) == 1:
        t.clientStaffId = int(token.xpath('clientStaffId')[0].text)
    if len(token.xpath('creatorId')) == 1:
        t.creatorId = int(token.xpath('creatorId')[0].text)
    if len(token.xpath('username')) == 1:
        t.username = token.xpath('username')[0].text
    if len(token.xpath('clientStaffUsername')) == 1:
        t.clientStaffUsername = token.xpath('clientStaffUsername')[0].text
    if t.creatorId is not None and len(token.xpath('creatorUsername')) == 1:
        t.creatorUsername = token.xpath('creatorUsername')[0].text

    return t

def parseTokens(input):
    result = []
    tree = checkStatus(input)
    resList = tree.xpath('/responseHolder/response/tokens//token')
    for token in resList:
        result.append(__parseTokenEntity(token))

    return result

def parseToken(input):
    tree = checkStatus(input)
    token = tree.xpath('/responseHolder/response/token')
    if len(token) == 1:
        return __parseTokenEntity(token[0])
    else:
        raise ProtectimusApiException("Failed to parse response")

def __parseUserEntity(user):
    u = User()
    if len(user.xpath('id')) == 1:
        u.id = int(user.xpath('id')[0].text)
    if len(user.xpath('login')) == 1:
        u.login = user.xpath('login')[0].text
    if len(user.xpath('email')) == 1:
        u.email = user.xpath('email')[0].text
    if len(user.xpath('phoneNumber')) == 1:
        u.phoneNumber = user.xpath('phoneNumber')[0].text
    if len(user.xpath('firstName')) == 1:
        u.firstName = user.xpath('firstName')[0].text
    if len(user.xpath('secondName')) == 1:
        u.secondName = user.xpath('secondName')[0].text
    if len(user.xpath('apiSupport')) == 1:
        u.apiSupport = toBool(user.xpath('apiSupport')[0].text)
    if len(user.xpath('hasTokens')) == 1:
        u.hasTokens = toBool(user.xpath('hasTokens')[0].text)
    if len(user.xpath('creatorId')) == 1:
        u.creatorId = int(user.xpath('creatorId')[0].text)
    if u.creatorId is not None and len(user.xpath('creatorUsername')) == 1:
        u.creatorUsername = user.xpath('creatorUsername')[0].text

    return u

def parseUsers(input):
    result = []
    tree = checkStatus(input)
    userList = tree.xpath('/responseHolder/response/users//user')
    for user in userList:
        result.append(__parseUserEntity(user))

    return result

def parseUser(input):
    tree = checkStatus(input)
    user = tree.xpath('/responseHolder/response/user')
    if len(user) == 1:
        return __parseUserEntity(user[0])
    else:
        raise ProtectimusApiException("Failed to parse response")
