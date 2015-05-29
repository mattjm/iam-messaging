class SignatureVerifyException(Exception):
    pass

class SigningCertException(Exception):
    def __init__(self, url, status=0):
        self.url = url
        self.status = status

    def __str__(self):
        return ("Error fetching certificate from %s.  Status: %s" %
                (self.url, self.status))

class CryptKeyException(Exception):
    def __init__(self, keyid, msg):
        self.keyid = keyid
        self.msg = msg

    def __str__(self):
        return ("Crypt key error for key %s: %s" % (self.keyid, self.msg))

