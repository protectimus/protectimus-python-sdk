# -*- coding: utf-8 -*-

from protectimussdk.entity.resource import Resource
from protectimussdk.protectimusapi import ProtectimusAPI

if __name__ == "__main__":
    API_URL = ''
    USERNAME = ''
    APIKEY = ''
    p = ProtectimusAPI(API_URL, USERNAME, APIKEY, True, "v1")

    print p.balance()
    print p.prepareAuthentication(2, 6, None, None)
    #line = raw_input('Prompt ("stop" to quit): ')
    #line = None
    #print p.authenticateToken(4, 22, line, None)
    #print p.authenticateUserPassword(1, 1, 'user', 'pass', '123.1.1.2')
    #print p.authenticateUserToken(2, 3, 'user', 'pass', '123.1.1.2')
    #print p.authenticateUserPasswordToken(1, 1, 'user', 'pass', '123', '123.1.1.2')

    #for r in p.resources(0):
    #    print "R: %s" % (r)

    #print p.resource(4)
    #print p.resourcesQuantity()
    #print p.addResource('api resource', 3)
    #print p.editResource(4, 'api edit res', 12)

    r = Resource()
    r.id = 4
    r.name = "api new res"
    r.failedAttemptsBeforeLock = 4
    r.creatorId = 1
    r.creatorUsername = 'myblackbox.sergey@gmail.com'
    #print p.editResourceEntity(r)
    #print p.deleteResource(2)
    #print p.deleteResourceEntity(r)
    #p.assignUserToResource(1, 1)
    #p.assignTokenToResource(1, 1)
    #p.assignUserAndTokenToResource(1,1,1)
    #p.assignTokenWithUserToResource(1, 1)
    #p.unassignUserFromResource(1,1)
    #p.unassignUserAndTokenFromResource(1,1,1)
    #p.unassignTokenWithUserFromResource(1,1)

    #for t in p.tokens(0):
    #    print t
    #print p.token(1)
    #print p.tokensQuantity()
    from protectimussdk.enum.tokentype import MailTokenType, ProtectimusTokenType
    from protectimussdk.enum.pinotpformat import PinOtpFormatBefore
    #print p.addUnifyToken(None, None, "OATH_HOTP", "SHA256", "HEX", "unifytoken", "token name",
    #                "token secret", "123323", None, None, None, None, None)

    #print p.addSoftwareToken(1, 'user', MailTokenType(), 'nanama@anam.com', 'name', '123', '123',
    #                         '1233', PinOtpFormatBefore())
    #print p.addHardwareToken(1, 'user', ProtectimusTokenType(), 'nanama@anam.com', 'name', '123', '123',
    #                         False, '1233', PinOtpFormatBefore())
    #print p.editToken(1, 'ttt', True, True)
    #print p.deleteToken(5)
    #p.unassignToken(1)

    #for u in p.users(0):
    #    print u
    #print p.user(1)
    #print p.usersQuantity()
    #print p.addUser('newuser4', 'newuser4@mail.com', '(423)331-2672', 'pass', 'First name', None, None)
    #print p.editUser(5, 'newuser3', 'newuser3@mail.com', '(123)331-2672', 'pass', 'First name', None, True)
    #print p.deleteUser(7)
    #for t in p.userTokens(5, 0):
    #    print t
    #print p.userTokensQuantity(5)
    #print p.assignUserToken(5, 1)
    #p.unassignUserToken(5, 1)
