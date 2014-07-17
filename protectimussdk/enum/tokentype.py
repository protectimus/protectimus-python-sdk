# -*- coding: utf-8 -*-

SOFTWARE_TYPE = 0
HARDWARE_TYPE = 1

class TokenType(object):
    def tokenType(self):
        raise NotImplementedError("Please Implement this method")

    def tokenValue(self):
        raise NotImplementedError("Please Implement this method")

class GoogleAuthenticatorTokenType(TokenType):
    def tokenType(self):
        return SOFTWARE_TYPE

    def tokenValue(self):
        return 'GOOGLE_AUTHENTICATOR'

class ProtectimusTokenType(TokenType):
    def tokenType(self):
        return HARDWARE_TYPE

    def tokenValue(self):
        return 'PROTECTIMUS'

class SafenetEtokenPassTokenType(TokenType):
    def tokenType(self):
        return HARDWARE_TYPE

    def tokenValue(self):
        return 'SAFENET_ETOKEN_PASS'

class SmsTokenType(TokenType):
    def tokenType(self):
        return SOFTWARE_TYPE

    def tokenValue(self):
        return 'SMS'

class MailTokenType(TokenType):
    def tokenType(self):
        return SOFTWARE_TYPE

    def tokenValue(self):
        return 'MAIL'

class ProtectimusUltraTokenType(TokenType):
    def tokenType(self):
        return HARDWARE_TYPE

    def tokenValue(self):
        return 'PROTECTIMUS_ULTRA'

class ProtectimusSmartTokenType(TokenType):
    def tokenType(self):
        return SOFTWARE_TYPE

    def tokenValue(self):
        return 'PROTECTIMUS_SMART'

class YubicoOathModeTokenType(TokenType):
    def tokenType(self):
        return HARDWARE_TYPE

    def tokenValue(self):
        return 'YUBICO_OATH_MODE'

class UnifyOathModeTokenType(TokenType):
    def tokenType(self):
        return HARDWARE_TYPE

    def tokenValue(self):
        return 'UNIFY_OATH_TOKEN'

def getTokenTypeByName(name):
    if name == 'GOOGLE_AUTHENTICATOR': return GoogleAuthenticatorTokenType()
    if name == 'PROTECTIMUS': return ProtectimusTokenType()
    if name == 'SAFENET_ETOKEN_PASS': return SafenetEtokenPassTokenType()
    if name == 'SMS': return SmsTokenType()
    if name == 'MAIL': return MailTokenType()
    if name == 'PROTECTIMUS_ULTRA': return ProtectimusUltraTokenType()
    if name == 'PROTECTIMUS_SMART': return ProtectimusSmartTokenType()
    if name == 'YUBICO_OATH_MODE': return YubicoOathModeTokenType()
    if name == 'UNIFY_OATH_TOKEN': return UnifyOathModeTokenType()
    return None