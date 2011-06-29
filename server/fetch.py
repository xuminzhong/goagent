#!/usr/bin/env python
# coding=utf-8
# Based on GAppProxy by Du XiaoGang <dugang@188.com>
# Based on WallProxy 0.4.0 by hexieshe <www.ehust@gmail.com>

__version__ = 'beta'
__author__ =  'phus.lu@gmail.com'
__password__ = ''

import zlib, logging, time, re, struct, base64, binascii
from google.appengine.ext import webapp
from google.appengine.ext import db
from google.appengine.ext.webapp.util import run_wsgi_app
from google.appengine.api import urlfetch
from google.appengine.api import xmpp
from google.appengine.runtime import apiproxy_errors, DeadlineExceededError

def gae_encode_data(dic):
    return '&'.join('%s=%s' % (k, binascii.b2a_hex(str(v))) for k, v in dic.iteritems())

def gae_decode_data(qs):
    return dict((k, binascii.a2b_hex(v)) for k, v in (x.split('=') for x in qs.split('&')))

class MainHandler(webapp.RequestHandler):

    FRP_Headers = ('', 'x-google-cache-control', 'via')
    Fetch_Max = 3
    Fetch_MaxSize = 512*1000
    Deadline = (15, 30)

    def sendResponse(self, status_code, headers, content='', method='', url=''):
        self.response.headers['Content-Type'] = 'image/gif'  # fake header
        contentType = headers.get('content-type', '').lower()

        headers = gae_encode_data(headers)
        # Build send-data
        rdata = '%s%s%s' % (struct.pack('>3I', status_code, len(headers), len(content)), headers, content)
        if contentType.startswith(('text', 'application')):
            data = zlib.compress(rdata)
            data = '1'+data if len(rdata)>len(data) else '0'+rdata
        else:
            data = '0' + rdata
        if status_code > 500:
            logging.warning('Response: "%s %s" %d %d/%d/%d', method, url, status_code, len(content), len(rdata), len(data))
        else:
            logging.debug('Response: "%s %s" %d', method, url, status_code)
        return self.response.out.write(data)

    def sendXmppResponse(self, xmpp_message, status_code, headers, content='', method='', url=''):
        self.response.headers['Content-Type'] = 'application/octet-stream'
        contentType = headers.get('content-type', '').lower()

        headers = gae_encode_data(headers)
        rdata = '%s%s%s' % (struct.pack('>3I', status_code, len(headers), len(content)), headers, content)
        data = '2' + base64.b64encode(rdata)
        if status_code > 500:
            logging.warning('Response: "%s %s" %d %d/%d/%d', method, url, status_code, len(content), len(rdata), len(data))
        else:
            logging.debug('Response: "%s %s" %d', method, url, status_code)
        maxsize = 2000
        for i in xrange(0, len(data), maxsize):
            xmpp_message.reply(data[i:i+maxsize]+'\r\n')
        xmpp_message.reply('\r\n')

    def sendNotify(self, status_code, content, method='', url='', fullContent=False):
        if not fullContent and status_code!=555:
            content = '<h2>Fetch Server Info</h2><hr noshade="noshade"><p>Code: %d</p>' \
                      '<p>Message: %s</p>' % (status_code, content)
        headers = {'content-type':'text/html', 'content-length':len(content)}
        self.sendResponse(status_code, headers, content, method, url)

    def post(self):
        xmpp_mode = (self.request.path == '/_ah/xmpp/message/chat/')
        if xmpp_mode:
            xmpp_message = xmpp.Message(self.request.POST)
            request = gae_decode_data(xmpp_message.body.replace('&amp;', '&'))
            logging.debug('MainHandler post get xmpp request %s', request)
        else:
            xmpp_message = None
            request = gae_decode_data(zlib.decompress(self.request.body))
            #logging.debug('MainHandler post get fetch request %s', request)

        if __password__ and __password__ != request.get('password', ''):
            return self.sendNotify(403, 'Fobbidon -- wrong password. Please check your proxy.ini and fetch.py.')

        method = request.get('method', 'GET')
        fetch_method = getattr(urlfetch, method, '')
        if not fetch_method:
            return self.sendNotify(555, 'Invalid Method', method)

        url = request.get('url', '')
        if not url.startswith('http'):
            return self.sendNotify(555, 'Unsupported Scheme', method, url)

        payload = request.get('payload', '')
        deadline = MainHandler.Deadline[1 if payload else 0]

        fetch_range = 'bytes=0-%d' % (MainHandler.Fetch_MaxSize - 1)
        rangeFetch = False
        headers = {}
        for line in request.get('headers', '').splitlines():
            key, _, value = line.partition(':')
            if not value:
                continue
            key, value = key.strip().lower(), value.strip()
            #if key in MainHandler.FRS_Headers:
            #    continue
            if key == 'rangefetch':
                rangeFetch = True
                continue
            if key =='range' and not rangeFetch:
                m = re.search(r'(\d+)?-(\d+)?', value)
                if m is None:
                    continue
                start, end = m.group(1, 2)
                if not start and not end:
                    continue
                if not start and int(end) > MainHandler.Fetch_MaxSize:
                    end = '1023'
                elif not end or int(end)-int(start)+1 > MainHandler.Fetch_MaxSize:
                    end = str(MainHandler.Fetch_MaxSize - 1 + int(start))
                fetch_range = ('bytes=%s-%s' % (start, end))
            headers[key] = value
        headers['Connection'] = 'close'

        for i in range(MainHandler.Fetch_Max):
            try:
                response = urlfetch.fetch(url, payload, fetch_method, headers, False, False, deadline)
                #if method=='GET' and len(response.content)>0x1000000:
                #    raise urlfetch.ResponseTooLargeError(None)
                break
            except apiproxy_errors.OverQuotaError, e:
                time.sleep(4)
            except DeadlineExceededError:
                logging.error('DeadlineExceededError(deadline=%s, url=%r)', deadline, url)
                time.sleep(1)
                deadline = MainHandler.Deadline[1]
            except urlfetch.InvalidURLError, e:
                return self.sendNotify(555, 'Invalid URL: %s' % e, method, url)
            except urlfetch.ResponseTooLargeError, e:
                if method == 'GET':
                    deadline = MainHandler.Deadline[1]
                    if not rangeFetch:
                        headers['Range'] = fetch_range
                else:
                    return self.sendNotify(555, 'Response Too Large: %s' % e, method, url)
            except Exception, e:
                if i==0 and method=='GET':
                    deadline = MainHandler.Deadline[1]
                    if not rangeFetch:
                        headers['Range'] = fetch_range
        else:
            return self.sendNotify(555, 'Urlfetch error: %s' % e, method, url)

        for k in MainHandler.FRP_Headers:
            if k in response.headers:
                del response.headers[k]
        if 'set-cookie' in response.headers:
            scs = response.headers['set-cookie'].split(', ')
            cookies = []
            i = -1
            for sc in scs:
                if re.match(r'[^ =]+ ', sc):
                    try:
                        cookies[i] = '%s, %s' % (cookies[i], sc)
                    except IndexError:
                        pass
                else:
                    cookies.append(sc)
                    i += 1
            response.headers['set-cookie'] = '\r\nSet-Cookie: '.join(cookies)
        response.headers['connection'] = 'close'
        if xmpp_mode:
            return self.sendXmppResponse(xmpp_message, response.status_code, response.headers, response.content, method, url)
        else:
            return self.sendResponse(response.status_code, response.headers, response.content, method, url)

    def get(self):
        self.response.headers['Content-Type'] = 'text/html; charset=utf-8'
        self.response.out.write( \
'''
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
        <title>GoAgent %(version)s on GAE/已经在工作了</title>
    </head>
    <body>
        <table width="800" border="0" align="center">
            <tr><td align="center"><hr></td></tr>
            <tr><td align="center">
                <b><h1>GoAgent %(version)s on GAE/已经在工作了</h1></b>
            </td></tr>
            <tr><td align="center"><hr></td></tr>

            <tr><td align="center">
                GoAgent是一个开源的HTTP Proxy软件,使用Python编写,运行于Google App Engine平台上.
            </td></tr>
            <tr><td align="center"><hr></td></tr>

            <tr><td align="center">
                更多相关介绍,请参考<a href="http://code.google.com/p/goagent/">GoAgent项目主页</a>.
            </td></tr>
            <tr><td align="center"><hr></td></tr>

            <tr><td align="center">
                <img src="http://code.google.com/appengine/images/appengine-silver-120x30.gif" alt="Powered by Google App Engine" />
            </td></tr>
            <tr><td align="center"><hr></td></tr>
        </table>
    </body>
</html>
''' % dict(version=__version__))

def main():
    #application = webapp.WSGIApplication([('/_ah/xmpp/message/chat/', MainHandler),('/fetch.py', MainHandler)],debug=True)
    application = webapp.WSGIApplication([('/fetch.py', MainHandler)], debug=True)
    run_wsgi_app(application)

if __name__ == '__main__':
    main()