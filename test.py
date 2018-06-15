#!/usr/bin/env python
# -*- coding: utf-8 -*-
import requests

username = "fengding"
mschap_challenge = "2696bacaf0815defdc858d405880b079"
mschap2_response = "0000ef15a4c5a4b9420dcb64ca7f0b5a579100000000000000008c2507c7c31ef0682b00be797173f2a2a8b4345a46eb7d0f"

server = "http://127.0.0.1:8080"

data = {"User-Name": username,
        "MS-CHAP-Challenge": mschap_challenge,
        "MS-CHAP2-Response": mschap2_response}

r = requests.post(server, json=data)
print r.text
