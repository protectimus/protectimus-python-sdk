# -*- coding: utf-8 -*-

from protectimussdk.abstractserviceclient import AbstractServiceClient

class AuthServiceClient(AbstractServiceClient):
    def __init__(self, apiUrl, username, apiKey, responseFormat, version):
        super(AuthServiceClient, self).__init__(apiUrl, username, apiKey, responseFormat, version)

    def serviseName(self):
        return 'auth-service'

    def balance(self):
        return self.webResource("balance" + self.extension())

    def prepare(self, resourceId, resourceName, tokenId, userId, userLogin):
        return self.webResource("prepare" + self.extension(), self.processFormData({'resourceId': resourceId,
                                                               'resourceName': resourceName,
                                                               'tokenId': tokenId,
                                                               'userId': userId,
                                                               'userLogin': userLogin}))

    def authenticateToken(self, resourceId, resourceName, tokenId, otp, ip):
        return self.webResource("authenticate/token" + self.extension(), self.processFormData({
                                                               'resourceId': resourceId,
                                                               'resourceName': resourceName,
                                                               'tokenId': tokenId,
                                                               'otp': otp,
                                                               'ip': ip}))

    def authenticateUserPassword(self, resourceId, resourceName, userId, userLogin, password, ip):
        return self.webResource("authenticate/user-password" + self.extension(), self.processFormData({
                                                               'resourceId': resourceId,
                                                               'resourceName': resourceName,
                                                               'userId': userId,
                                                               'userLogin': userLogin,
                                                               'pwd': password,
                                                               'ip': ip}))

    def authenticateUserToken(self, resourceId, resourceName, userId, userLogin, otp, ip):
        return self.webResource("authenticate/user-token" + self.extension(), self.processFormData({
                                                               'resourceId': resourceId,
                                                               'resourceName': resourceName,
                                                               'userId': userId,
                                                               'userLogin': userLogin,
                                                               'otp': otp,
                                                               'ip': ip}))

    def authenticateUserPasswordToken(self, resourceId, resourceName, userId, userLogin, otp, password, ip):
        return self.webResource("authenticate/user-password-token" + self.extension(), self.processFormData({
                                                               'resourceId': resourceId,
                                                               'resourceName': resourceName,
                                                               'userId': userId,
                                                               'userLogin': userLogin,
                                                               'otp': otp,
                                                               'pwd': password,
                                                               'ip': ip}))
