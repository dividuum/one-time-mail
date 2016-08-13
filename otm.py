from gevent import monkey; monkey.patch_all()
import gevent_openssl; gevent_openssl.monkey_patch()

import re
import random
import string
import pytz
import email
import email.header
import json
import time
import traceback
import smtplib
from email.mime.text import MIMEText
from imapclient import IMAPClient
from datetime import datetime, timedelta
from operator import itemgetter
import gevent
from gevent import Greenlet
from gevent.queue import Queue
from gevent.lock import Semaphore
from flask import Flask, render_template, Response, request
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

class AuthenticatorDebugDoNotUse(Authenticator):
    def verify_impl(self, token):
        return True

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
    "debug-do-not-use": AuthenticatorDebugDoNotUse,
}[CONFIG['authenticator']['name']](**CONFIG['authenticator'].get('args', {}))

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
        self._imap  = IMAPClient(hostname, use_uid=True, ssl=True)
        # self._imap.debug = True
        self._imap.login(username, password)
        self._client = client
        self._folder = None

    def get_messages(self, folder, query):
        # XXX: error handling
        if folder != self._folder:
            self._imap.select_folder(folder, readonly=True)
            self._folder = folder
        ids = self._imap.search(query)
        messages = self._imap.fetch(ids, ['FLAGS', 'RFC822'])

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

            date = b['date']
            try:
                timestamp = email.utils.mktime_tz(email.utils.parsedate_tz(date))
                date = datetime.fromtimestamp(timestamp, pytz.utc).strftime("%c UTC")
            except:
                traceback.print_exc()
                timestamp = time.time()

            def dh(value):
                return unicode(email.header.make_header(email.header.decode_header(value)))

            return {
                'from': dh(b['from']),
                'to': dh(b['to']),
                'subject': dh(b['subject']),
                'msg_id': b['message-id'],
                'date': date,
                'body': body,
                'sort_key': timestamp,
                'unread': '\\Seen' not in message['FLAGS'],
            }

        mails = []
        for id, message in messages.iteritems():
            mails.append(parse_message(message['RFC822']))
        mails.sort(key=itemgetter('sort_key'), reverse=True)

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
        self.send_to_client('connected')

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
            self.send_error_and_close('Already authenticated')
            return
        if not Authenticator.verify(token):
            self.send_error_and_close('Invalid token')
            return
        self._imap = IMAP(self, 
            CONFIG['auth']['imap']['hostname'],
            CONFIG['auth']['imap']['username'],
            CONFIG['auth']['imap']['password'],
        )
        self._killer_task = spawn(self.killer_task)
        self.send_to_client('authenticated', expires=CONFIG['max_session_duration'])
        self.send_to_client('folders', folders=sorted(CONFIG['folders']))

    @external_api
    def get_messages(self, folder):
        if not self._imap:
            self.send_error_and_close('Not authenticated')
            return
        if folder not in CONFIG['folders']:
            self.send_error_and_close('Invalid folder')
            return
        folder_settings = CONFIG['folders'][folder]
        def parse(tok):
            if isinstance(tok, basestring):
                return tok
            elif isinstance(tok, (int, long)):
                return (datetime.now() - timedelta(days=tok)).date()
        query = [parse(tok) for tok in folder_settings['query']]
        self._imap.send('get_messages', folder_settings['folder'], query)

    @external_api
    def send_mail(self, to, subject, replyto, body):
        if not self._imap:
            self.send_error_and_close('Not authenticated')
            return
        server = smtplib.SMTP_SSL(
            CONFIG['auth']['smtp']['hostname'],
            CONFIG['auth']['smtp']['port'],
        )
        # server.set_debuglevel(1)
        # server.starttls()
        server.login(
            CONFIG['auth']['smtp']['username'],
            CONFIG['auth']['smtp']['password'],
        )
        msg = MIMEText(body, 'plain', 'utf-8')
        msg['Subject'] = subject
        msg['From'] = CONFIG['auth']['smtp']['from']
        msg['To'] = to
        msg['In-Reply-To'] = replyto
        server.sendmail(
            CONFIG['auth']['smtp']['from'],
            [to], msg.as_string()
        )
        server.quit()
        # XXX: This should also put a copy of the sent mail into the SENT folder?
        self.send_to_client('mail_sent')

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
            self.send_error_and_close('Invalid message')

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
def session_socket(ws):
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
    nonce = ''.join(random.sample(
        string.lowercase+string.digits, 16
    ))
    r = Response(render_template("otm.jinja",
        nonce=nonce
    ))
    r.headers['Content-Security-Policy'] = ';'.join((
        "default-src 'none'",
        "style-src 'nonce-%s'" % nonce,
        "script-src 'nonce-%s'" % nonce,
        "connect-src %s://%s/ws" % (
            "wss" if request.is_secure else "ws",
            request.host,
        ),
    ))
    r.headers['X-Frame-Options'] = 'DENY'
    return r

if __name__ == "__main__":
    from gevent import pywsgi
    from geventwebsocket.handler import WebSocketHandler
    from werkzeug.contrib.fixers import ProxyFix
    app = ProxyFix(app)
    server = pywsgi.WSGIServer(('127.0.0.1', 8080), app, handler_class=WebSocketHandler)
    server.serve_forever()
