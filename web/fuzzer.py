import requests
import string
import urllib.parse


chars = string.ascii_letters + string.digits
#chars = chars + string.punctuation

print("using: " + chars)


loop = True
counter = 0
key = ''

while loop:
    for char in chars:
        #char = urllib.parse.quote(char)
        url = 'https://7729d9a333-rev-connector.dbhchallenge.net/index.php?ID=c56ac9e5a4faa7e8d694715ea6d1bff5&debug=true&key='+key+char
        x = requests.get(url)
        resp = 'Wrong char at position ' + str(counter)
        if x.text != resp:
            key = key + char
            print(key)
            counter += 1
            break
    
    if x.text[0:5] != 'Wrong':
        print(x.text)
        loop = False


print('key: ' + key)







    


