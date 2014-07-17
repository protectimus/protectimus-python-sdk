# -*- coding: utf-8 -*-

from protectimussdk.abstractserviceclient import AbstractServiceClient, PUT_METHOD, DELETE_METHOD

class ResourceServiceClient(AbstractServiceClient):
    def __init__(self, apiUrl, username, apiKey, responseFormat, version):
        super(ResourceServiceClient, self).__init__(apiUrl, username, apiKey, responseFormat, version)

    def serviseName(self):
        return 'resource-service'

    def resources(self, offset):
        return self.webResource("resources" + self.extension(), None, {'start': offset})

    def resource(self, resourceId):
        return self.webResource("resources/%s%s" % (resourceId, self.extension()))

    def resourcesQuantity(self):
        return self.webResource("resources/quantity%s" % self.extension())

    def addResource(self, resourceName, failedAttemptsBeforeLock):
        return self.webResource("resources" + self.extension(), self.processFormData({'resourceName': resourceName,
                                                                 'failedAttemptsBeforeLock': failedAttemptsBeforeLock}))

    def editResource(self, id, resourceName, failedAttemptsBeforeLock):
        return self.webResource("resources/%s%s" % (id, self.extension()),
                                self.processFormData({'resourceName': resourceName,
                                 'failedAttemptsBeforeLock': failedAttemptsBeforeLock}),
                                None, PUT_METHOD)

    def deleteResource(self, id):
        return self.webResource("resources/%s%s" % (id, self.extension()), None, None, DELETE_METHOD)

    def assignUserToResource(self, resourceId, resourceName, userId, userLogin):
        return self.webResource("assign/user" + self.extension(), self.processFormData({'resourceId': resourceId,
                                                                 'resourceName': resourceName,
                                                                 'userLogin': userLogin,
                                                                 'userId': userId}))

    def assignTokenToResource(self, resourceId, resourceName, tokenId):
        return self.webResource("assign/token" + self.extension(), self.processFormData({'resourceId': resourceId,
                                                                 'resourceName': resourceName,
                                                                 'tokenId': tokenId}))

    def assignUserAndTokenToResource(self, resourceId, resourceName, userId, userLogin, tokenId):
        return self.webResource("assign/user-token" + self.extension(), self.processFormData({'resourceId': resourceId,
                                                                         'resourceName': resourceName,
                                                                         'userLogin': userLogin,
                                                                         'userId': userId,
                                                                         'tokenId': tokenId}))

    def assignTokenWithUserToResource(self, resourceId, resourceName, tokenId):
        return self.webResource("assign/token-with-user" + self.extension(), self.processFormData({'resourceId': resourceId,
                                                                         'resourceName': resourceName,
                                                                         'tokenId': tokenId}))

    def unassignUserFromResource(self, resourceId, resourceName, userId, userLogin):
        return self.webResource("unassign/user" + self.extension(), self.processFormData({'resourceId': resourceId,
                                                                         'resourceName': resourceName,
                                                                         'userLogin': userLogin,
                                                                         'userId': userId}))

    def unassignTokenFromResource(self, resourceId, resourceName, tokenId):
        return self.webResource("unassign/token" + self.extension(), self.processFormData({'resourceId': resourceId,
                                                                         'resourceName': resourceName,
                                                                         'tokenId': tokenId}))

    def unassignUserAndTokenFromResource(self, resourceId, resourceName, userId, userLogin, tokenId):
        return self.webResource("unassign/user-token" + self.extension(), self.processFormData({'resourceId': resourceId,
                                                                         'resourceName': resourceName,
                                                                         'userLogin': userLogin,
                                                                         'userId': userId,
                                                                         'tokenId': tokenId}))

    def unassignTokenWithUserFromResource(self, resourceId, resourceName, tokenId):
        return self.webResource("unassign/token-with-user" + self.extension(), self.processFormData({'resourceId': resourceId,
                                                                         'resourceName': resourceName,
                                                                         'tokenId': tokenId}))

