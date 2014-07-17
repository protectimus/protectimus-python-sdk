#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging

from protectimussdk import xmlutils
from protectimussdk.entity.resource import Resource
from protectimussdk.authserviceclient import AuthServiceClient
from protectimussdk.resourceserviceclient import ResourceServiceClient
from protectimussdk.tokenserviceclient import TokenServiceClient
from protectimussdk.userserviceclient import UserServiceClient
from protectimussdk.enum.responseformat import XMLResponseFormat
from protectimussdk.enum.tokentype import *
from protectimussdk.enum.pinotpformat import PinOtpFormat
from protectimussdk.exception.protectimusapiexception import ProtectimusApiException

class ProtectimusAPI(object):
    def __init__(self, apiUrl, username, apiKey, debug = False, version = None):
        self.apiUrl = apiUrl
        self.username = username
        self.apiKey = apiKey
        self.version = version
        self.currentFormat = XMLResponseFormat()
        self.debug = debug

        if not debug:
            return
        else:
            streamformat = "%(levelname)s (%(module)s:%(lineno)d) %(message)s"
            # Set up the root logger to debug so that the submodules can
            # print debug messages
            logging.basicConfig(level=logging.DEBUG,
                                format=streamformat)
            self.logger = logging.getLogger(__name__)

    ##
    # Gets current balance of the client
    ##
    def balance(self):
        a = AuthServiceClient(self.apiUrl, self.username, self.apiKey, self.currentFormat, self.version)
        balance = xmlutils.parseBalance(a.balance())
        if self.debug:
            self.logger.debug('balance=%s' % balance)
        return balance

    ##
    # Prepares token for authentication. In case of use tokens with type such
	# as SMS, MAIL or PROTECTIMUS_ULTRA this method must be called before
	# authentication to send sms for SMS-token or send e-mail for MAIL-token or
	# get challenge string for PROTECTIMUS_ULTRA-token.
    #
	# @param resourceId
	# @param tokenId
	# @return Challenge string for PROTECTIMUS_ULTRA-token or empty string for
	#         SMS and MAIL tokens
	# @throws ProtectimusApiException
    ##
    def prepareAuthentication(self, resourceId, tokenId, userId, userLogin):
        a = AuthServiceClient(self.apiUrl, self.username, self.apiKey, self.currentFormat, self.version)
        prepAuth = xmlutils.parsePrepareString(a.prepare(resourceId, None, tokenId, userId, userLogin))
        if self.debug:
            self.logger.debug('prepareAuthentication=%s' % prepAuth)
        return prepAuth

    ##
    # Performs authentication for token with id <code>tokenId</code>, which is
	# assigned to resource with id <code>resourceId</code>.
	#
	# @param resourceId
	# @param tokenId
	# @param otp
	#            - one-time password from token
	# @param ip
	#            - IP-address of the end user. Must be specified to perform the
	#            validation of geo-filter.
	# @return true if authentication was successful; false otherwise.
	# @throws ProtectimusApiException
    ##
    def authenticateToken(self, resourceId, tokenId, otp, ip):
        a = AuthServiceClient(self.apiUrl, self.username, self.apiKey, self.currentFormat, self.version)
        authToken = xmlutils.parseAuthenticationResult(a.authenticateToken(resourceId, None, tokenId, otp, ip))
        if self.debug:
            self.logger.debug('authenticateToken=%s' % authToken)
        return authToken

    ##
    # Performs password authentication for user with id <code>userId</code> or
	# login <code>userLogin</code>, which is assigned to resource with id
	# <code>resourceId</code>.
	#
	# @param resourceId
	# @param userId
	# @param userLogin
	# @param password
	#            - password of the user
	# @param ip
	#            - IP-address of the end user. Must be specified to perform the
	#            validation of geo-filter.
	# @return true if authentication was successful; false otherwise.
	# @throws ProtectimusApiException
    ##
    def authenticateUserPassword(self, resourceId, userId, userLogin, password, ip):
        a = AuthServiceClient(self.apiUrl, self.username, self.apiKey, self.currentFormat, self.version)
        authUserPass = xmlutils.parseAuthenticationResult(a.authenticateUserPassword(resourceId, None,
                                                                             userId, userLogin, password, ip))
        if self.debug:
            self.logger.debug('authenticateUserPassword=%s' % authUserPass)
        return authUserPass

    ##
    # Performs one-time password authentication for user with id
	# <code>userId</code> or login <code>userLogin</code>, which is assigned
	# with token to resource with id <code>resourceId</code>.
	#
	# @param resourceId
	# @param userId
	# @param userLogin
	# @param otp
	#            - one-time password from token
	# @param ip
	#            - IP-address of the end user. Must be specified to perform the
	#            validation of geo-filter.
	# @return true if authentication was successful; false otherwise.
	# @throws ProtectimusApiException
    ##
    def authenticateUserToken(self, resourceId, userId, userLogin, otp, ip):
        a = AuthServiceClient(self.apiUrl, self.username, self.apiKey, self.currentFormat, self.version)
        authUserToken = xmlutils.parseAuthenticationResult(a.authenticateUserToken(resourceId, None,
                                                                             userId, userLogin, otp, ip))
        if self.debug:
            self.logger.debug('authenticateUserToken=%s' % authUserToken)
        return authUserToken

    ##
    # Performs one-time password and static password authentication for user
	# with id <code>userId</code> or login <code>userLogin</code>, which is
	# assigned with token to resource with id <code>resourceId</code>.
	#
	# @param resourceId
	# @param userId
	# @param userLogin
	# @param otp
	#            - one-time password from token
	# @param password
	#            - password of the user
	# @param ip
	#            - IP-address of the end user. Must be specified to perform the
	#            validation of geo-filter.
	# @return true if authentication was successful; false otherwise.
	# @throws ProtectimusApiException
    ##
    def authenticateUserPasswordToken(self, resourceId, userId, userLogin, otp, password, ip):
        a = AuthServiceClient(self.apiUrl, self.username, self.apiKey, self.currentFormat, self.version)
        authUserPassToken = xmlutils.parseAuthenticationResult(a.authenticateUserPasswordToken(resourceId, None,
                                                                                  userId, userLogin, otp, password, ip))
        if self.debug:
            self.logger.debug('authenticateUserPasswordToken=%s' % authUserPassToken)
        return authUserPassToken

    ##
    # Gets the list of resources (10 records starting from <code>offset</code>)
	#
	# @param offset
	# @return list of resources
	# @throws ProtectimusApiException
    ##
    def resources(self, offset):
        r = ResourceServiceClient(self.apiUrl, self.username, self.apiKey, self.currentFormat, self.version)
        resources = xmlutils.parseResources(r.resources(offset))
        if self.debug:
            self.logger.debug('resources=%s' % resources)
        return resources

    ##
    # Gets a resource by <code>resourceId</code>
	#
	# @param resourceId
	# @return resource
	# @throws ProtectimusApiException
    ##
    def resource(self, resourceId):
        r = ResourceServiceClient(self.apiUrl, self.username, self.apiKey, self.currentFormat, self.version)
        resource = xmlutils.parseResource(r.resource(resourceId))
        if self.debug:
            self.logger.debug('resource=%s' % resource)
        return resource

    ##
    # Gets quantity of resources
	#
	# @return quantity of resources
	# @throws ProtectimusApiException
    ##
    def resourcesQuantity(self):
        r = ResourceServiceClient(self.apiUrl, self.username, self.apiKey, self.currentFormat, self.version)
        resQuantity = xmlutils.parseQuantity(r.resourcesQuantity())
        if self.debug:
            self.logger.debug('resourcesQuantity=%s' % resQuantity)
        return resQuantity

    ##
    # Adds a new resource
	#
	# @param resourceName
	# @param failedAttemptsBeforeLock
	# @return id of a new resource
	# @throws ProtectimusApiException
    ##
    def addResource(self, resourceName, failedAttemptsBeforeLock):
        r = ResourceServiceClient(self.apiUrl, self.username, self.apiKey, self.currentFormat, self.version)
        res = xmlutils.parseId(r.addResource(resourceName, failedAttemptsBeforeLock))
        if self.debug:
            self.logger.debug('addResource=%s' % res)
        return res

    ##
    # Edits an existing resource with <code>resourceId</code>
	#
	# @param resourceId
	# @param resourceName
	# @param failedAttemptsBeforeLock
	# @return edited resource
	# @throws ProtectimusApiException
    ##
    def editResource(self, resourceId, resourceName, failedAttemptsBeforeLock):
        r = ResourceServiceClient(self.apiUrl, self.username, self.apiKey, self.currentFormat, self.version)
        res = xmlutils.parseResource(r.editResource(resourceId, resourceName, failedAttemptsBeforeLock))
        if self.debug:
            self.logger.debug('editResource=%s' % res)
        return res

    ##
    # Edits an existing resource
	#
	# @param resource
	# @return edited resource
	# @throws ProtectimusApiException
    ##
    def editResourceEntity(self, res):
        if isinstance(res, Resource):
            r = ResourceServiceClient(self.apiUrl, self.username, self.apiKey, self.currentFormat, self.version)
            resEntity = self.editResource(res.id, res.name, res.failedAttemptsBeforeLock)
            if self.debug:
                self.logger.debug('editResourceEntity=%s' % resEntity)
            return resEntity
        else:
            if self.debug:
                self.logger.debug('editResourceEntity %s is not instance of Resource' % res)
            return None

    ##
    # Deletes an existing resource with <code>resourceId</code>
	#
	# @param resourceId
	# @return id of deleted resource
	# @throws ProtectimusApiException
    ##
    def deleteResource(self, resourceId):
        r = ResourceServiceClient(self.apiUrl, self.username, self.apiKey, self.currentFormat, self.version)
        res = xmlutils.parseResource(r.deleteResource(resourceId))
        if self.debug:
            self.logger.debug('deleteResource=%s' % res)
        return res

    ##
    # Deletes an existing resource
	#
	# @param resource
	# @return id of deleted resource
	# @throws ProtectimusApiException
    ##
    def deleteResourceEntity(self, res):
        return self.deleteResource(res.id)

    ##
    # Assigns user with <code>userId</code> to resource with
	# <code>resourceId</code>
	#
	# @param resourceId
	# @param resourceName
	# @param userId
	# @param userLogin
	# @throws ProtectimusApiException
    ##
    def assignUserToResource(self, resourceId, resourceName, userId, userLogin):
        r = ResourceServiceClient(self.apiUrl, self.username, self.apiKey, self.currentFormat, self.version)
        xmlutils.checkStatus(r.assignUserToResource(resourceId, resourceName, userId, userLogin))
        if self.debug:
            self.logger.debug('assignUserToResource')

    ##
    # Assigns token with <code>tokenId</code> to resource with
	# <code>resourceId</code>
	#
	# @param resourceId
	# @param resourceName
	# @param tokenId
	# @throws ProtectimusApiException
    ##
    def assignTokenToResource(self, resourceId, resourceName, tokenId):
        r = ResourceServiceClient(self.apiUrl, self.username, self.apiKey, self.currentFormat, self.version)
        xmlutils.checkStatus(r.assignTokenToResource(resourceId, resourceName, tokenId))
        if self.debug:
            self.logger.debug('assignTokenToResource')

    ##
    # Assigns together user with <code>userId</code> and token with
	# <code>tokenId</code> to resource with <code>resourceId</code>
	#
	# @param resourceId
	# @param resourceName
	# @param userId
	# @param userLogin
	# @param tokenId
	# @throws ProtectimusApiException
    ##
    def assignUserAndTokenToResource(self, resourceId, resourceName, userId, userLogin, tokenId):
        r = ResourceServiceClient(self.apiUrl, self.username, self.apiKey, self.currentFormat, self.version)
        xmlutils.checkStatus(r.assignUserAndTokenToResource(resourceId, resourceName, userId, userLogin, tokenId))
        if self.debug:
            self.logger.debug('assignUserAndTokenToResource')

    ##
    # Assigns together token with <code>tokenId</code> and user, which has
	# given token, to resource with <code>resourceId</code>
	#
	# @param resourceId
	# @param resourceName
	# @param tokenId
	# @throws ProtectimusApiException
    ##
    def assignTokenWithUserToResource(self, resourceId, resourceName, tokenId):
        r = ResourceServiceClient(self.apiUrl, self.username, self.apiKey, self.currentFormat, self.version)
        xmlutils.checkStatus(r.assignTokenWithUserToResource(resourceId, resourceName, tokenId))
        if self.debug:
            self.logger.debug('assignTokenWithUserToResource')

    ##
    # Unassigns user with <code>userId</code> from resource with
	# <code>resourceId</code>
	#
	# @param resourceId
	# @param resourceName
	# @param userId
	# @param userLogin
	# @throws ProtectimusApiException
    ##
    def unassignUserFromResource(self, resourceId, resourceName, userId, userLogin):
        r = ResourceServiceClient(self.apiUrl, self.username, self.apiKey, self.currentFormat, self.version)
        xmlutils.checkStatus(r.unassignUserFromResource(resourceId, resourceName, userId, userLogin))
        if self.debug:
            self.logger.debug('unassignUserFromResource')

    ##
    # Unassigns token with <code>tokenId</code> from resource with
	# <code>resourceId</code>
	#
	# @param resourceId
	# @param resourceName
	# @param tokenId
	# @throws ProtectimusApiException
    ##
    def unassignTokenFromResource(self, resourceId, resourceName, tokenId):
        r = ResourceServiceClient(self.apiUrl, self.username, self.apiKey, self.currentFormat, self.version)
        xmlutils.checkStatus(r.unassignTokenFromResource(resourceId, resourceName, tokenId))
        if self.debug:
            self.logger.debug('unassignTokenFromResource')

    ##
    # Unassigns together user with <code>userId</code> and token with
	# <code>tokenId</code> from resource with <code>resourceId</code>
	#
	# @param resourceId
	# @param resourceName
	# @param userId
	# @param userLogin
	# @param tokenId
	# @throws ProtectimusApiException
    ##
    def unassignUserAndTokenFromResource(self, resourceId, resourceName, userId, userLogin, tokenId):
        r = ResourceServiceClient(self.apiUrl, self.username, self.apiKey, self.currentFormat, self.version)
        xmlutils.checkStatus(r.unassignUserAndTokenFromResource(resourceId, resourceName, userId, userLogin, tokenId))
        if self.debug:
            self.logger.debug('unassignUserAndTokenFromResource')

    ##
    # Unassigns together token with <code>tokenId</code> and user, which has
	# given token, from resource with <code>resourceId</code>
	#
	# @param resourceId
	# @param resourceName
	# @param tokenId
	# @throws ProtectimusApiException
    ##
    def unassignTokenWithUserFromResource(self, resourceId, resourceName, tokenId):
        r = ResourceServiceClient(self.apiUrl, self.username, self.apiKey, self.currentFormat, self.version)
        xmlutils.checkStatus(r.unassignTokenWithUserFromResource(resourceId, resourceName, tokenId))
        if self.debug:
            self.logger.debug('unassignTokenWithUserFromResource')

    ##
    # Gets the list of tokens (10 records starting from <code>offset</code>)
	#
	# @param offset
	# @return list of tokens
	# @throws ProtectimusApiException
    ##
    def tokens(self, offset):
        t = TokenServiceClient(self.apiUrl, self.username, self.apiKey, self.currentFormat, self.version)
        tokens = xmlutils.parseTokens(t.tokens(offset))
        if self.debug:
            self.logger.debug('tokens=%s' % tokens)
        return tokens

    ##
    # Gets a token by <code>tokenId</code>
	#
	# @param tokenId
	# @return token
	# @throws ProtectimusApiException
    ##
    def token(self, tokenId):
        t = TokenServiceClient(self.apiUrl, self.username, self.apiKey, self.currentFormat, self.version)
        token = xmlutils.parseToken(t.token(tokenId))
        if self.debug:
            self.logger.debug('token=%s' % token)
        return token

    ##
    # Gets quantity of tokens
	#
	# @return quantity of tokens
	# @throws ProtectimusApiException
    ##
    def tokensQuantity(self):
        t = TokenServiceClient(self.apiUrl, self.username, self.apiKey, self.currentFormat, self.version)
        tokensQuantity = xmlutils.parseQuantity(t.tokensQuantity())
        if self.debug:
            self.logger.debug('tokensQuantity=%s' % tokensQuantity)
        return tokensQuantity

    ##
    # Adds unify token
    #
    # @param userId
    #            - id of the user to whom the token will be assigned
    # @param userLogin
    #            - login of the user to whom the token will be assigned
    # @param unifyType
    #            - uniry token type
    # @param unifyKeyAlgo
    #            - token key algorythm
    # @param unifyKeyFormat
    #            - token key algorythm
    # @param serialNumber
    #            - token serial number
    # @param name
    #            - token name
    # @param secret
    #            - token secret key
    # @param otp
    #            - one-time password from token
    # @param otpLength
    #            - length of the one-time password (6 or 8 digits)
    # @param pin
    #            - pin-code (optional)
    # @param pinOtpFormat
    #            - usage of a pin-code with one-time password (adding pin-code
    #            before or after one-time password)
    # @param counter
    #            - counter for token
    # @param challenge
    #            - challenge for token
    # @return id of a new token
    # @throws ProtectimusApiException
    ##
    def addUnifyToken(self, userId, userLogin, unifyType, unifyKeyAlgo, unifyKeyFormat, serialNumber, name, secret, otp, otpLength, pin, pinOtpFormat, counter, challenge):
        if unifyType is None:
            raise ProtectimusApiException("Unify token type is requried")
        if unifyKeyAlgo is None:
            raise ProtectimusApiException("Unify token key algorithm is requried")
        if unifyKeyFormat is None:
            raise ProtectimusApiException("Unify token key format is requried")

        t = TokenServiceClient(self.apiUrl, self.username, self.apiKey, self.currentFormat, self.version)
        addUnifyToken = xmlutils.parseId(t.addUnifyToken(userId, userLogin, unifyType, unifyKeyAlgo, unifyKeyFormat,
                                                   serialNumber, name, secret, otp, otpLength, pin, pinOtpFormat, counter, challenge))
        if self.debug:
            self.logger.debug('addUnifyToken=%s' % addUnifyToken)
        return addUnifyToken

    ##
    # Adds software token
	#
	# @param userId
	#            - id of the user to whom the token will be assigned
	# @param userLogin
	#            - login of the user to whom the token will be assigned
	# @param type
	#            - token type
	# @param serialNumber
	#            - token serial number
	# @param name
	#            - token name
	# @param secret
	#            - token secret key
	# @param otp
	#            - one-time password from token
	# @param pin
	#            - pin-code (optional)
	# @param pinOtpFormat
	#            - usage of a pin-code with one-time password (adding pin-code
	#            before or after one-time password)
	# @return id of a new token
	# @throws ProtectimusApiException
    ##
    def addSoftwareToken(self, userId, userLogin, type, serialNumber, name, secret, otp, pin, pinOtpFormat):
        if type is None or not isinstance(type, TokenType):
            raise ProtectimusApiException("Token type is requried")

        if type.tokenType() != SOFTWARE_TYPE:
            raise ProtectimusApiException("Token of this type is not a software token")

        if isinstance(type, SmsTokenType) or isinstance(type, MailTokenType):
            otp = '123456'
            secret = otp

        if pin is None:
            pin = ''

        pinOtpFormatValue = ''
        if pinOtpFormat is not None and isinstance(pinOtpFormat, PinOtpFormat):
            pinOtpFormatValue = pinOtpFormat.pinOtpFormatValue()

        t = TokenServiceClient(self.apiUrl, self.username, self.apiKey, self.currentFormat, self.version)
        addSoftToken = xmlutils.parseId(t.addSoftwareToken(userId, userLogin, type.tokenValue(), serialNumber,
                                                   name, secret, otp, pin, pinOtpFormatValue))
        if self.debug:
            self.logger.debug('addSoftwareToken=%s' % addSoftToken)
        return addSoftToken

    ##
    # Adds hardware token
	#
	# @param userId
	#            - id of the user to whom the token will be assigned
	# @param userLogin
	#            - login of the user to whom the token will be assigned
	# @param type
	#            - token type
	# @param serialNumber
	#            - token serial number
	# @param name
	#            - token name
	# @param secret
	#            - token secret key
	# @param otp
	#            - one-time password from token
	# @param isExistedToken
	#            - false indicates that you are adding or own token or token,
	#            true indicates that you are adding token, which is provided by
	#            Protectimus
	# @param pin
	#            - pin-code (optional)
	# @param pinOtpFormat
	#            - usage of a pin-code with one-time password (adding pin-code
	#            before or after one-time password)
	# @return id of a new token
	# @throws ProtectimusApiException
    ##
    def addHardwareToken(self, userId, userLogin, type, serialNumber, name, secret,
                         otp, isExistedToken, pin, pinOtpFormat):
        if type is None or not isinstance(type, TokenType):
            raise ProtectimusApiException("Token type is requried")

        if type.tokenType() != HARDWARE_TYPE:
            raise ProtectimusApiException("Token of this type is not a hardware token")

        if pin is None:
            pin = ''

        pinOtpFormatValue = ''
        if pinOtpFormat is not None and isinstance(pinOtpFormat, PinOtpFormat):
            pinOtpFormatValue = pinOtpFormat.pinOtpFormatValue()

        t = TokenServiceClient(self.apiUrl, self.username, self.apiKey, self.currentFormat, self.version)
        addHardToken = xmlutils.parseId(t.addHardwareToken(userId, userLogin, type.tokenValue(), serialNumber,
                                                   name, secret, otp, isExistedToken, pin, pinOtpFormatValue))
        if self.debug:
            self.logger.debug('addHardwareToken=%s' % addHardToken)
        return addHardToken

    ##
    # Edits an existing token with <code>tokenId</code>
	#
	# @param tokenId
	# @param name
	# @param enabled
	# @param apiSupport
	# @return edited token
	# @throws ProtectimusApiException
    ##
    def editToken(self, tokenId, name, enabled, apiSupport):
        t = TokenServiceClient(self.apiUrl, self.username, self.apiKey, self.currentFormat, self.version)
        editToken = xmlutils.parseToken(t.editToken(tokenId, name, enabled, apiSupport))
        if self.debug:
            self.logger.debug('editToken=%s' % editToken)
        return editToken

    ##
    # Edits an existing token
	#
	# @param token
	# @return edited token
	# @throws ProtectimusApiException
    ##
    def editTokenEntity(self, token):
        return self.editToken(token.id, token.name, token.enabled, token.apiSupport)

    ##
    # Deletes an existing token with <code>tokenId</code>
	#
	# @param tokenId
	# @return id of deleted token
	# @throws ProtectimusApiException
    ##
    def deleteToken(self, tokenId):
        t = TokenServiceClient(self.apiUrl, self.username, self.apiKey, self.currentFormat, self.version)
        delToken = xmlutils.parseToken(t.deleteToken(tokenId))
        if self.debug:
            self.logger.debug('deleteToken=%s' % delToken)
        return delToken

    ##
    # Deletes an existing token
	#
	# @param token
	# @return id of deleted token
	# @throws ProtectimusApiException
    ##
    def deleteTokenEntity(self, token):
        return self.deleteToken(token.id)

    ##
    # Unassigns token with <code>tokenId</code> from user
	#
	# @param tokenId
	# @throws ProtectimusApiException
    ##
    def unassignToken(self, tokenId):
        t = TokenServiceClient(self.apiUrl, self.username, self.apiKey, self.currentFormat, self.version)
        xmlutils.checkStatus(t.unassignToken(tokenId))
        if self.debug:
            self.logger.debug('unassignToken')

    ##
    # Unassigns token with from user
	#
	# @param token
	# @throws ProtectimusApiException
    ##
    def unassignTokenEntity(self, token):
        self.unassignToken(token.id)

    ##
    # Gets the list of users (10 records starting from <code>offset</code>)
	#
	# @param offset
	# @return list of users
	# @throws ProtectimusApiException
    ##
    def users(self, offset):
        u = UserServiceClient(self.apiUrl, self.username, self.apiKey, self.currentFormat, self.version)
        users = xmlutils.parseUsers(u.users(offset))
        if self.debug:
            self.logger.debug('users=%s' % users)
        return users

    ##
    # Gets a user by <code>userId</code>
	#
	# @param userId
	# @return user
	# @throws ProtectimusApiException
    ##
    def user(self, userId):
        u = UserServiceClient(self.apiUrl, self.username, self.apiKey, self.currentFormat, self.version)
        user = xmlutils.parseUser(u.user(userId))
        if self.debug:
            self.logger.debug('user=%s' % user)
        return user

    ##
    # Gets quantity of users
	#
	# @return quantity of users
	# @throws ProtectimusApiException
    ##
    def usersQuantity(self):
        u = UserServiceClient(self.apiUrl, self.username, self.apiKey, self.currentFormat, self.version)
        usersQuantity = xmlutils.parseQuantity(u.usersQuantity())
        if self.debug:
            self.logger.debug('usersQuantity=%s' % usersQuantity)
        return usersQuantity

    ##
    # Adds a new user
	#
	# @param login
	# @param email
	# @param phoneNumber
	# @param password
	# @param firstName
	# @param secondName
	# @param apiSupport
	# @return id of a new user
	# @throws ProtectimusApiException
    ##
    def addUser(self, login, email, phoneNumber, password, firstName, secondName, apiSupport):
        u = UserServiceClient(self.apiUrl, self.username, self.apiKey, self.currentFormat, self.version)
        addUser = xmlutils.parseId(u.addUser(login, email, phoneNumber, password, firstName, secondName, apiSupport))
        if self.debug:
            self.logger.debug('addUser=%s' % addUser)
        return addUser

    ##
    # Edits an existing user with <code>userId</code>
	#
	# @param userId
	# @param login
	# @param email
	# @param phoneNumber
	# @param password
	# @param firstName
	# @param secondName
	# @param apiSupport
	# @return edited user
	# @throws ProtectimusApiException
    ##
    def editUser(self, userId, login, email, phoneNumber, password, firstName, secondName, apiSupport):
        u = UserServiceClient(self.apiUrl, self.username, self.apiKey, self.currentFormat, self.version)
        editUser = xmlutils.parseUser(u.editUser(userId, login, email, phoneNumber, password, firstName, secondName, apiSupport))
        if self.debug:
            self.logger.debug('editUser=%s' % editUser)
        return editUser

    ##
    # Change raw users password with <code>userId</code>
	#
	# @param userId
	# @param rawPassword
	# @param rawSalt
	# @param encodingType
	# @param encodingFormat
	# @return edited user
	# @throws ProtectimusApiException
    ##
    def editUsersPassword(self, userId, rawPassword, rawSalt, encodingType, encodingFormat):
        u = UserServiceClient(self.apiUrl, self.username, self.apiKey, self.currentFormat, self.version)
        editUser = xmlutils.parseUser(u.editUsersPassword(userId, rawPassword, rawSalt, encodingType, encodingFormat))
        if self.debug:
            self.logger.debug('editUsersPassword=%s' % editUser)
        return editUser

    ##
    # Edits an existing user
	#
	# @param user
	# @return edited user
	# @throws ProtectimusApiException
    ##
    def editUserEntity(self, user, password):
        return self.editUser(user.id, user.login, user.email, user.phoneNumber, password,
                             user.firstName, user.secondName, user.apiSupport)

    ##
    # Deletes an existing user with <code>userId</code>
	#
	# @param userId
	# @return id of deleted user
	# @throws ProtectimusApiException
    ##
    def deleteUser(self, userId):
        u = UserServiceClient(self.apiUrl, self.username, self.apiKey, self.currentFormat, self.version)
        delUser = xmlutils.parseUser(u.deleteUser(userId))
        if self.debug:
            self.logger.debug('deleteUser=%s' % delUser)
        return delUser

    ##
    # Deletes an existing user
	#
	# @param user
	# @return id of deleted user
	# @throws ProtectimusApiException
    ##
    def deleteUserEntity(self, user):
        return self.deleteUser(user.id)

    ##
    # Gets the list of user tokens by <code>userId</code> (10 records starting
	# from <code>offset</code>)
	#
	# @param userId
	# @param offset
	# @return list of user tokens
	# @throws ProtectimusApiException
    ##
    def userTokens(self, userId, offset):
        u = UserServiceClient(self.apiUrl, self.username, self.apiKey, self.currentFormat, self.version)
        userTokens = xmlutils.parseTokens(u.userTokens(userId, offset))
        if self.debug:
            self.logger.debug('userTokens=%s' % userTokens)
        return userTokens

    ##
    # Gets quantity of user tokens by <code>userId</code>
	#
	# @param userId
	# @return quantity of users
	# @throws ProtectimusApiException
    ##
    def userTokensQuantity(self, userId):
        u = UserServiceClient(self.apiUrl, self.username, self.apiKey, self.currentFormat, self.version)
        userTokensQ = xmlutils.parseQuantity(u.userTokensQuantity(userId))
        if self.debug:
            self.logger.debug('userTokensQuantity=%s' % userTokensQ)
        return userTokensQ

    ##
    # Assigns token with <code>tokenId</code> to user with <code>userId</code>
	#
	# @param userId
	# @param tokenId
	# @throws ProtectimusApiException
    ##
    def assignUserToken(self, userId, tokenId):
        u = UserServiceClient(self.apiUrl, self.username, self.apiKey, self.currentFormat, self.version)
        xmlutils.checkStatus(u.assignUserToken(userId, tokenId))
        if self.debug:
            self.logger.debug('assignUserToken')

    ##
    # Unassigns token with <code>tokenId</code> from user with
	# <code>userId</code>
	#
	# @param userId
	# @param tokenId
	# @throws ProtectimusApiException
    ##
    def unassignUserToken(self, userId, tokenId):
        u = UserServiceClient(self.apiUrl, self.username, self.apiKey, self.currentFormat, self.version)
        xmlutils.checkStatus(u.unassignUserToken(userId, tokenId))
        if self.debug:
            self.logger.debug('unassignUserToken')
