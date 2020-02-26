from flask import Flask
from flask import Flask, request
import ssl
from werkzeug.utils import secure_filename

app = Flask(__name__)


@app.route('/', methods=['GET', 'POST'])
def hello_world():
    file = request.files['file']
    filename = secure_filename(file.filename)
    print(filename)
    file.save("./test_local.jpg")
    return filename

if __name__ == '__main__':
    
    CA_FILE = "data/ca/local_ca.crt"
    KEY_FILE = "data/server/local_server.key"
    CERT_FILE = "data/server/local_server.crt"


    ''' method 1 '''
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    context.load_verify_locations(CA_FILE)
    context.verify_mode = ssl.CERT_REQUIRED
    app.run(debug=True, ssl_context=context)
    
    ''' method 2 '''
    # app.run(debug=True, ssl_context=(CERT_FILE, KEY_FILE))
    