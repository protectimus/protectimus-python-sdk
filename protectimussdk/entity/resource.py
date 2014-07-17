# -*- coding: utf-8 -*-

class Resource(object):
    id = None
    name = None
    failedAttemptsBeforeLock = 0
    geoFilterId = None
    geoFilterName = None
    geoFilterEnabled = False
    timeFilterId = None
    timeFilterName = None
    timeFilterEnabled = False
    creatorId = None
    creatorUsername = None

    def __str__(self):
        return self.__unicode__()

    def __unicode__(self):
        return (u'Resource[id=%s, name=%s, failedAttemptsBeforeLock=%s,'\
               + u' geoFilterId=%s, geoFilterName=%s, geoFilterEnabled=%s,'\
               + u' timeFilterId=%s, timeFilterName=%s, timeFilterEnabled=%s,'\
               + u' creatorId=%s, creatorUsername=%s]') % (self.id, self.name,
        self.failedAttemptsBeforeLock, self.geoFilterId, self.geoFilterName, self.geoFilterEnabled,
        self.timeFilterId, self.timeFilterName, self.timeFilterEnabled, self.creatorId, self.creatorUsername)