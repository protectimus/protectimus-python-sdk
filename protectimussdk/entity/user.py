# -*- coding: utf-8 -*-


class User(object):
    id = None
    login = None
    email = None
    phoneNumber = None
    firstName = None
    secondName = None
    apiSupport = False
    hasTokens = False
    creatorId = None
    creatorUsername = None

    def __str__(self):
        return self.__unicode__()

    def __unicode__(self):
        return (u'User[id=%s, login=%s, email=%s, phoneNumber=%s,'\
               + u' firstName=%s, secondName=%s, apiSupport=%s,'\
               + u' hasTokens=%s, creatorId=%s, creatorUsername=%s]') % (self.id, self.login, self.email,
        self.phoneNumber, self.firstName, self.secondName, self.apiSupport,
        self.hasTokens, self.creatorId, self.creatorUsername)
