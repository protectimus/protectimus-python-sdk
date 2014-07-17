# -*- coding: utf-8 -*-

class PinOtpFormat(object):
    def pinOtpFormatValue(self):
        raise NotImplementedError("Please Implement this method")

class PinOtpFormatBefore(PinOtpFormat):
    def pinOtpFormatValue(self):
        return 'PIN_BEFORE_OTP'

class PinOtpFormatAfter(PinOtpFormat):
    def pinOtpFormatValue(self):
        return 'PIN_AFTER_OTP'
