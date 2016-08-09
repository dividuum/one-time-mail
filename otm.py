from gevent import monkey; monkey.patch_all()
import gevent_openssl; gevent_openssl.monkey_patch()

import re
import email
import json
import traceback
from imapclient import IMAPClient
from datetime import datetime, timedelta
from operator import itemgetter
import gevent
from gevent import Greenlet
from gevent.queue import Queue
from gevent.lock import Semaphore
from flask import Flask, render_template
from flask_sockets import Sockets
from bs4 import BeautifulSoup

app = Flask(__name__)
sockets = Sockets(app)
spawn = gevent.Greenlet.spawn

CONFIG = json.load(file("config.json"))

URL_REGEX = re.compile(r"(http|ftp|https)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?")

def remove_tags(garbage):
    return BeautifulSoup(garbage, "lxml").get_text()

class Authenticator(object):
    def __init__(self):
        self._lock = Semaphore()

    def verify(self, token):
        with self._lock:
            gevent.sleep(1)
            try:
                return self.verify_impl(token)
            except:
                traceback.print_exc()
                return False

    def verify_impl(self, token):
        return False

class AuthenticatorOTP(Authenticator):
    def __init__(self, state_file):
        Authenticator.__init__(self)
        self._state_file = state_file

    def verify_impl(self, token):
        with file(self._state_file) as inp:
            lines = [
                line.strip() for line in inp.readlines()
                if len(line.strip()) >= 8
            ]
        if not lines:
            return False # otps depleted
        if token != lines[0]:
            return False
        with file(self._state_file, "wb") as outp:
            outp.write("\n".join(lines[1:]))
        return True

class AuthenticatorYUBI(Authenticator):
    def __init__(self, client_id, secret_key, yubikey_id):
        Authenticator.__init__(self)
        try:
            import urllib3.contrib.pyopenssl
            urllib3.contrib.pyopenssl.inject_into_urllib3()
        except ImportError:
            pass
        from yubico_client import Yubico
        self._client = Yubico(client_id, secret_key)
        if len(yubikey_id) != 12:
            raise ValueError("invalid yubikey_id")
        self._yubikey_id = yubikey_id

    def verify_impl(self, token):
        if token[:12] != self._yubikey_id:
            return False
        return self._client.verify(token, timeout=5)

Authenticator = {
    "yubi": AuthenticatorYUBI,
    "otp": AuthenticatorOTP,
}[CONFIG['authenticator']['name']](**CONFIG['authenticator']['args'])

class Actor(gevent.Greenlet):
    def __init__(self, *args, **kwargs):
        self._inbox = Queue()
        self._running = True
        Greenlet.__init__(self)
        self.start()
        self._args = args
        self._kwargs = kwargs

    def quit(self):
        self.stop()

    def stop(self):
        self._running = False

    def _run(self):
        self.setup(*self._args, **self._kwargs)
        while self._running:
            event, args, kwargs = self._inbox.get()
            # print type(self).__name__, '<-', event, args
            try:
                getattr(self, event)(*args, **kwargs)
            except:
                traceback.print_exc()
                self.stop()

    def send(self, event, *args, **kwargs):
        self._inbox.put((event, args, kwargs))

class IMAP(Actor):
    def setup(self, client, hostname, username, password):
        print hostname, username, password
        self._imap  = IMAPClient(hostname, use_uid=True, ssl=True)
        # self._imap.debug = True
        self._imap.login(username, password)
        self._client = client
        self._folder = None

    def get_messages(self, folder):
        # XXX: error handling
        if folder != self._folder:
            self._imap.select_folder(folder, readonly=True)
            self._folder = folder
        threshold = (datetime.now() - timedelta(days=CONFIG['last_n_days'])).date()
        ids = self._imap.search(['NOT', 'DELETED', 'SINCE', threshold])
        messages = self._imap.fetch(ids, ['INTERNALDATE', 'FLAGS', 'RFC822.HEADER', 'RFC822'])

        def parse_message(raw):
            b = email.message_from_string(raw)
            body = "<no body>"

            if b.is_multipart():
                for part in b.walk():
                    ctype = part.get_content_type()
                    cdispo = str(part.get('Content-Disposition'))
                    if ctype == 'text/plain' and 'attachment' not in cdispo:
                        charset = part.get_content_charset() or 'utf-8'
                        body = part.get_payload(decode=True).decode(charset, errors='replace')
                        break
            else:
                charset = b.get_content_charset() or 'utf-8'
                body = b.get_payload(decode=True).decode(charset, errors='replace')

            body = remove_tags(body)

            replace_links = any(
                re.search(regex, body, re.M|re.S)
                for regex in CONFIG['mask_links']
            )

            if replace_links:
                body = URL_REGEX.sub("<link masked>", body)

            return {
                'from': b['from'],
                'to': b['to'],
                'date': b['date'],
                'subject': b['subject'],
                'body': body,
            }

        mails = []
        for id, message in messages.iteritems():
            parsed = parse_message(message['RFC822'])
            mails.append(parsed)

        self._client.send('mails', dict(
            folder = folder,
            mails = mails,
        ))

    def quit(self):
        self._imap.logout()

def external_api(fn):
    fn.external = True
    return fn

class Client(Actor):
    def setup(self, socket):
        self._socket = socket
        self._imap = None
        self._killer_task = None

    def send_to_client(self, event, **data):
        self._socket.send('send_client', json.dumps(dict(
            event = event,
            data = data,
        )))

    def send_error_and_close(self, message):
        self.send_to_client('error', message=message)
        gevent.sleep(0.5)
        self._socket.send('close')

    def mails(self, update):
        self.send_to_client('mails', **update) 

    def quit(self):
        if self._imap:
            self._imap.send('quit')
            self._killer_task.kill()
        self.stop()

    def killer_task(self):
        max_time = CONFIG['max_session_duration']
        gevent.sleep(max_time - 30)
        self.send_to_client('expire_warn')
        gevent.sleep(30)
        self.send_error_and_close('Session expired')

    @external_api
    def authenticate(self, token):
        if self._imap:
            self.send_error_and_close('already authenticated')
            return
        if not Authenticator.verify(token):
            self.send_error_and_close('invalid token')
            return
        self._imap = IMAP(self, 
            CONFIG['auth']['hostname'],
            CONFIG['auth']['username'],
            CONFIG['auth']['password'],
        )
        self._killer_task = spawn(self.killer_task)
        self.send_to_client('authenticated')
        self.send_to_client('folders', folders=sorted(
            CONFIG['folders'].iteritems(),
            key=itemgetter(1),
        ))

    @external_api
    def get_messages(self, folder):
        if not self._imap:
            self.send_error_and_close('not authenticated')
            return
        if folder not in CONFIG['folders']:
            self.send_error_and_close('invalid folder')
            return
        self._imap.send('get_messages', folder)

    def client_message(self, message):
        try:
            parsed = json.loads(message)
            event = parsed['event']
            data = parsed.get('data', {})
            fn = getattr(self, event)
            if not hasattr(fn, 'external'):
                raise NotImplementedError('not externally callable')
            fn(**data)
        except:
            traceback.print_exc()
            self.send_error_and_close('invalid message')

class Socket(Actor):
    def setup(self, ws):
        self._ws = ws

    def ping(self):
        self.send_client('')

    def close(self):
        self._ws.close()

    def send_client(self, message):
        self._ws.send(message)

@sockets.route('/ws')
def echo_socket(ws):
    socket = Socket(ws)
    client = Client(socket)

    def pinger():
        while 1:
            gevent.sleep(30)
            socket.send('ping')

    pinger_task = spawn(pinger)

    while not ws.closed:
        message = ws.receive()
        if not message:
            break
        client.send('client_message', message)

    pinger_task.kill()
    client.send('quit')
    socket.send('quit')
    print "done"

@app.route('/')
def index():
    return render_template("otm.jinja")

if __name__ == "__main__":
    from gevent import pywsgi
    from geventwebsocket.handler import WebSocketHandler
    server = pywsgi.WSGIServer(('127.0.0.1', 8080), app, handler_class=WebSocketHandler)
    server.serve_forever()
