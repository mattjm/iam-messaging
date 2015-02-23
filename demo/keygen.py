#
# IAM messaging tools (aes key generator)
#

import base64
import string
import os

key = os.urandom(16)
k64 = base64.encodestring(key)
print k64

