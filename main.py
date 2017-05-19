#!/usr/bin/env python

import webapp2
import urllib
import urllib2
from google.appengine.api import memcache
import json
import logging

PRIVACY_HTML = ('<!DOCTYPE html><html><head><title>acd_cli_oa privacy info</title></head>'
                'This app does not save any personal data. You may view <a href="./src">the source code</a> to check. '
                'However, Google\'s App Engine will retain a log of your IP address, request URL and browser string.'
                '</html>')

AMAZON_OA_LOGIN_URL = 'https://amazon.com/ap/oa'
AMAZON_OA_TOKEN_URL = 'https://api.amazon.com/auth/o2/token'
LOCAL_REDIRECT_URI = 'http://localhost'

CLIENT_ID = memcache.get('CLIENT_ID')
CLIENT_SECRET = memcache.get('CLIENT_SECRET')

if not CLIENT_ID or not CLIENT_SECRET:
    with open("client.json") as cd:
        cl_d = json.load(cd)

    CLIENT_ID = cl_d['CLIENT_ID']
    CLIENT_SECRET = cl_d['CLIENT_SECRET']
    memcache.set('CLIENT_ID', CLIENT_ID)
    memcache.set('CLIENT_SECRET', CLIENT_SECRET)

REFRESH_TOKEN_KEY = 'refresh_token'
REDIRECT_URI_KEY = 'redirect_uri'

OAUTH_ST1 = {'client_id': CLIENT_ID,
             'response_type': 'code',
             # the 'read' scope is outdated and should be replaced by
             # 'read_all' for newly created security profiles
             'scope': 'clouddrive:read clouddrive:write',
             REDIRECT_URI_KEY: None}

OAUTH_ST2 = {'grant_type': 'authorization_code',
             'code': None,
             'client_id': CLIENT_ID,
             'client_secret': CLIENT_SECRET,
             REDIRECT_URI_KEY: None}

OAUTH_REF = {'grant_type': REFRESH_TOKEN_KEY,
             'refresh_token': None,
             'client_id': CLIENT_ID,
             'client_secret': CLIENT_SECRET,
             REDIRECT_URI_KEY: None}


def pp(string):
    return json.dumps(json.loads(string), indent=4, sort_keys=True)

def ppo(obj):
    return json.dumps(obj, indent=4, sort_keys=True)


class OauthHandler(webapp2.RequestHandler):
    def get(self):
        try:
            error = self.request.GET['error']
            error_desc = self.request.GET['error_description']

            self.response.headers['Content-Type'] = 'text/plain'
            self.response.write('Error: %s\nDescription: %s\n' % (error, error_desc))
            return
        except KeyError:
            pass

        try:
            code = self.request.GET['code']
            scope = self.request.GET['scope']
        except KeyError:
            params = OAUTH_ST1
            params[REDIRECT_URI_KEY] = self.request.host_url
            oauth_step1_url = AMAZON_OA_LOGIN_URL + '?' + urllib.urlencode(OAUTH_ST1)
            return webapp2.redirect(oauth_step1_url)

        # user has returned after oauth
        if code and scope:
            params = OAUTH_ST2
            params['code'] = code
            params[REDIRECT_URI_KEY] = self.request.host_url

            resp = urllib.urlopen(AMAZON_OA_TOKEN_URL, urllib.urlencode(params))

            self.response.headers.add('Content-Disposition', 'attachment; filename="oauth_data"')
            self.response.write(pp(resp.read()))
            return

    def post(self):
        """Token refresh"""
        try:
            ref = self.request.POST[REFRESH_TOKEN_KEY]
        except KeyError:
            self.response.set_status(400)
            err_resp = {'error': 'refresh token not supplied', 'request': self.request.__str__()}
            self.response.write(json.dumps(err_resp, sort_keys=True))
            return

        params = OAUTH_REF
        params[REFRESH_TOKEN_KEY] = ref
        params[REDIRECT_URI_KEY] = self.request.host_url
        try:
            resp = urllib2.urlopen(AMAZON_OA_TOKEN_URL, urllib.urlencode(params), timeout=15)
        except urllib2.HTTPError as e:
            err_resp = {'error': str(e), 'request:': self.request.__str__()}
            self.response.set_status(502)
            self.response.write(ppo(err_resp))
            return

        code = resp.getcode()
        self.response.set_status(code)
        if code == 200:
            self.response.write(pp(resp.read()))
        else:
            err_resp = {}
            rt = resp.read()
            try:
                err_resp.update(json.loads(rt))
            except:
                err_resp = {'error': 'unknown error', 'response': str(rt)}
            err_resp['request'] = self.request.__str__()
            self.response.write(ppo(err_resp))


class PrivacyHandler(webapp2.RequestHandler):
    def get(self):
        self.response.write(PRIVACY_HTML)


class SourceHandler(webapp2.RequestHandler):
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        with open(__file__[:-1]) as f:
            self.response.write(f.read())


app = webapp2.WSGIApplication([
    ('/', OauthHandler),
    ('/privacy', PrivacyHandler),
    ('/src', SourceHandler)
], debug=True)
