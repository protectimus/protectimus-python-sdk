# -*- coding: utf-8 -*-

from protectimussdk.abstractserviceclient import AbstractServiceClient, PUT_METHOD, DELETE_METHOD

class UserServiceClient(AbstractServiceClient):
    def __init__(self, apiUrl, username, apiKey, responseFormat, version):
        super(UserServiceClient, self).__init__(apiUrl, username, apiKey, responseFormat, version)

    def serviseName(self):
        return 'user-service'

    def users(self, offset):
        return self.webResource("users" + self.extension(), None, {'start': offset})

    def user(self, userId):
        return self.webResource("users/%s%s" % (userId, self.extension()))

    def usersQuantity(self):
        return self.webResource("users/quantity%s" % self.extension())

    def addUser(self, login, email, phoneNumber, password, firstName, secondName, apiSupport):
        return self.webResource("users" + self.extension(), self.processFormData({'login': login,
                                                             'email': email,
                                                             'phoneNumber': phoneNumber,
                                                             'password': password,
                                                             'firstName': firstName,
                                                             'secondName': secondName,
                                                             'apiSupport': apiSupport}))

    def editUser(self, id, login, email, phoneNumber, password, firstName, secondName, apiSupport):
        return self.webResource("users/%s%s" % (id, self.extension()), self.processFormData({'login': login,
                                                             'email': email,
                                                             'phoneNumber': phoneNumber,
                                                             'password': password,
                                                             'firstName': firstName,
                                                             'secondName': secondName,
                                                             'apiSupport': apiSupport}), None, PUT_METHOD)

    def editUsersPassword(self, id, rawPassword, rawSalt, encodingType, encodingFormat):
        return self.webResource("users/%s/password%s" % (id, self.extension()), self.processFormData({'rawPassword': rawPassword,
                                                             'rawSalt': rawSalt,
                                                             'encodingType': encodingType,
                                                             'encodingFormat': encodingFormat}))

    def deleteUser(self, id):
        return self.webResource("users/%s%s" % (id, self.extension()), None, None, DELETE_METHOD)

    def userTokens(self, userId, offset):
        return self.webResource("users/%s/tokens%s" % (userId, self.extension()), None, {'start': offset})

    def userTokensQuantity(self, userId):
        return self.webResource("users/%s/tokens/quantity%s" % (userId, self.extension()))

    def assignUserToken(self, userId, tokenId):
        return self.webResource("users/%s/tokens/%s/assign%s" % (userId, tokenId, self.extension()),
                                self.processFormData({'userId': userId, 'tokenId': tokenId}))

    def unassignUserToken(self, userId, tokenId):
        return self.webResource("users/%s/tokens/%s/unassign%s" % (userId, tokenId, self.extension()),
                                self.processFormData({'userId': userId, 'tokenId': tokenId}))
