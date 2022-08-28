import hashlib
from Crypto.Cipher import AES


timeStamp = "31-07-2022 18:00:50"

master_key = hashlib.md5(timeStamp.encode('utf-8')).hexdigest()

key1 = master_key


# open file
with open('flag.txt.dbh','rb') as f:
    msg = f.read()

# brute force pins
for i in range(9999):
    
    # generate md5 hash from pin
    key2 = hashlib.md5(str(i).encode('utf-8')).hexdigest()
    
    # shuffel keys
    mykey = ''
    for i, char in enumerate(key1):
        if i % 2:
            mykey = mykey + char        
        else:
            mykey = mykey + key2[i]     
    try:
        newbytekey = bytes.fromhex(mykey)
        cipher = AES.new(newbytekey, AES.MODE_ECB)
        msgDe = cipher.decrypt(msg)
        msgDe = msgDe.decode("utf-8")
        if msgDe.startswith('DBH'):
            print("Flag: %s" % msgDe)
            print("Encryption Key: %s" % mykey)
            print("Pin: %s" % str(i))
    except:
        x = True
        





#master_key = b'abcdefghijklmnop'
#msg = b'AAAAAAAAAAAAAAAA'





