# -*- coding: utf-8 -*-

from protectimussdk.abstractserviceclient import AbstractServiceClient, PUT_METHOD, DELETE_METHOD

class TokenServiceClient(AbstractServiceClient):
    def __init__(self, apiUrl, username, apiKey, responseFormat, version):
        super(TokenServiceClient, self).__init__(apiUrl, username, apiKey, responseFormat, version)

    def serviseName(self):
        return 'token-service'

    def tokens(self, offset):
        return self.webResource("tokens" + self.extension(), None, {'start': offset})

    def token(self, tokenId):
        return self.webResource("tokens/%s%s" % (tokenId, self.extension()))

    def tokensQuantity(self):
        return self.webResource("tokens/quantity%s" % self.extension())

    def addUnifyToken(self, userId, userLogin, unifyType, unifyKeyAlgo, unifyKeyFormat, serialNumber, name, secret, otp, otpLength, pin, pinOtpFormat, counter, challenge):
        return self.webResource("tokens/unify" + self.extension(), self.processFormData({'userId': userId,
                                                                       'userLogin': userLogin,
                                                                       'unifyType': unifyType,
                                                                       'unifyKeyAlgo': unifyKeyAlgo,
                                                                       'unifyKeyFormat': unifyKeyFormat,
                                                                       'serial': serialNumber,
                                                                       'name': name,
                                                                       'secret': secret,
                                                                       'otp': otp,
                                                                       'otpLength': otpLength,
                                                                       'pin': pin,
                                                                       'pinOtpFormat': pinOtpFormat,
                                                                       'counter': counter,
                                                                       'challenge': challenge}))

    def addSoftwareToken(self, userId, userLogin, type, serialNumber, name, secret, otp, pin, pinOtpFormat):
        return self.webResource("tokens/software" + self.extension(), self.processFormData({'userId': userId,
                                                                       'userLogin': userLogin,
                                                                       'type': type,
                                                                       'serial': serialNumber,
                                                                       'name': name,
                                                                       'secret': secret,
                                                                       'otp': otp,
                                                                       'pin': pin,
                                                                 'pinOtpFormat': pinOtpFormat}))

    def addHardwareToken(self, userId, userLogin, type, serialNumber, name, secret,
                         otp, isExistedToken, pin, pinOtpFormat):
        return self.webResource("tokens/hardware" + self.extension(), self.processFormData({'userId': userId,
                                                                       'userLogin': userLogin,
                                                                       'type': type,
                                                                       'serial': serialNumber,
                                                                       'name': name,
                                                                       'secret': secret,
                                                                       'otp': otp,
                                                                       'existed': isExistedToken,
                                                                       'pin': pin,
                                                                 'pinOtpFormat': pinOtpFormat}))

    def editToken(self, id, name, enabled, apiSupport):
        return self.webResource("tokens/%s%s" % (id, self.extension()), self.processFormData({'name': name,
                                                                       'enabled': enabled,
                                                                       'apiSupport': apiSupport}), None, PUT_METHOD)

    def deleteToken(self, id):
        return self.webResource("tokens/%s%s" % (id, self.extension()), None, None, DELETE_METHOD)

    def unassignToken(self, tokenId):
        return self.webResource("tokens/%s/unassign%s" % (tokenId, self.extension()), {})





