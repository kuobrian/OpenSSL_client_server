import requests
import ssl
import os
import cv2
from requests.packages.urllib3.exceptions import SubjectAltNameWarning
requests.packages.urllib3.disable_warnings(SubjectAltNameWarning)

def images_path():
    image_folder = "./data"
    f = []
    for (dirpath, dirnames, filenames) in os.walk(image_folder):
        f.extend(os.path.join(image_folder, fname) for fname in filenames)
        break
    return f


if __name__ == '__main__':
    CA_FILE = "data/ca/local_ca.crt"
    KEY_FILE = "data/client/local_client.key"
    CERT_FILE = "data/client/local_client.crt"  
    cert = (CERT_FILE, KEY_FILE)

    f = images_path()
    try:
        for i in range(len(f)):
            files = {'file': open(f[i], 'rb')}
            if f[i].find(".sh") == -1:
                ''' method 1 '''
                r = requests.post('https://localhost:5000/', files = files, cert=cert, verify=CA_FILE)
                
                ''' method 2 
                        ignore certificate can use verify=False
                '''
                # r = requests.post('https://localhost:5000/', files = files, verify=CA_FILE)
                print(r.text)
    except Exception as ex:
        print("Found Error in auth phase:%s" % str(ex))

