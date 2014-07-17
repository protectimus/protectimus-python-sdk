# -*- coding: utf-8 -*-

class Prepare(object):
    challenge = None
    tokenName = None
    tokenType = None

    def __str__(self):
        return self.__unicode__()

    def __unicode__(self):
        return (u'Prepare[challenge=%s, tokenName=%s, tokenType=%s]') % (self.challenge, self.tokenName,
        self.tokenType)