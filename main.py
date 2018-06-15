#!/usr/bin/env python
# -*- coding: utf-8 -*-
import web
import json
from lib import mschap, mppe

urls = (
    '/', 'index'
)

app = web.application(urls, globals())

users = {"fengding": "fengding"}

class index:
    def _parse_mschap2_response(self, resp):
        ident = resp[0:2]
        flags = resp[2:4]
        peer_challenge = resp[4:36]
        reserved = resp[36:52]
        response = resp[52:]
        return (peer_challenge.decode("hex"), response.decode("hex"))

    def POST(self):
        data = json.loads(web.data())
        username = data["User-Name"]
        authenticator_challenge = data["MS-CHAP-Challenge"].decode("hex")
        chap2_response = data["MS-CHAP2-Response"]
        peer_challenge, nt_response = self._parse_mschap2_response(chap2_response)
        compute_nt_response = mschap.generate_nt_response_mschap2(authenticator_challenge, peer_challenge, username, users[username])
        authenticator_resp = mschap.generate_authenticator_response(users[username], compute_nt_response, peer_challenge, authenticator_challenge, username)
        msk = mppe.mppe_chap2_gen_keys(users[username], compute_nt_response)
        sendkey = msk[0].encode("hex")
        recvkey = msk[1].encode("hex")
        #web.header('Content-Type', 'application/json')
        #pyDict = {'User-Name': username,
        #          'MS-CHAP2-Success': authenticator_resp,
        #          'MS-MPPE-Recv-Key': sendkey,
        #          'MS-MPPE-Send-Key': recvkey}
        reply = "User-Name:=%s, MS-CHAP2-Success=\"%s\", MS-MPPE-Recv-Key=%s, MS-MPPE-Send-Key=%s" % (username, authenticator_resp, sendkey, recvkey)
        return reply

if __name__ == '__main__':
    app.run()
