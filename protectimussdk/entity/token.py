# -*- coding: utf-8 -*-


class Token(object):
    id = None
    name = None
    type = None
    serialNumber = None
    enabled = False
    apiSupport = False
    userId = None
    clientStaffId = None
    creatorId = None
    username = None
    clientStaffUsername = None
    creatorUsername = None

    def __str__(self):
        return self.__unicode__()

    def __unicode__(self):
        return (u'Token[id=%s, name=%s, type=%s, serialNumber=%s,'\
               + u' enabled=%s, apiSupport=%s, userId=%s,'\
               + u' clientStaffId=%s, creatorId=%s, username=%s,'\
               + u' clientStaffUsername=%s, creatorUsername=%s]') % (self.id, self.name, self.type,
        self.serialNumber, self.enabled, self.apiSupport, self.userId,
        self.clientStaffId, self.creatorId, self.username, self.clientStaffUsername, self.creatorUsername)
