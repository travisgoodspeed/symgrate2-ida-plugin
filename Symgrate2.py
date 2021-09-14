
# This is a Python2 version of the Symgrate library - woohoo!
# (because I don't have a Python3 IDA version to test with) -- evm
import httplib
import urllib
import json


"""A Python2 library for the Symgrate web API."""

global SEARCHLEN
SEARCHLEN=18
LEN=SEARCHLEN


def jprint(j):
    """Prints the results from JSON."""
    # Parse the JSON.
    x=json.loads(j)

    #Print each name and record.
    for f in x:
        print(f, x[f]["Name"])

def queryfn(raw):
    """Queries the server for the first bytes of ASCII armored machine language."""
    data=Symgrate2.queryjfns("raw=%s"%raw)
    j=json.loads(data)
    for f in j:
        return j[f]["Name"]
    return None

def queryjfns(q):
    """Queries the server for the first bytes of ASCII armored machine language."""
    conn = httplib.HTTPConnection("symgrate.com",80)
    headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"}
    params=q
    try:
        params = urllib.urlencode(q)
    except TypeError:
        pass;

    #print(q+"\n")
    # FIXME, we should be taking bytes as raw instead of a string.
    conn.request("POST", "/jfns", params, headers)
    
    r1 = conn.getresponse()
    #print r1.status, r1.reason
    # 200 OK ?
    toret=None
    if r1.status==200:
        data = r1.read()
        if len(data)>2:
            toret=data.decode("utf-8")

    # TODO: This would go a little faster if we reused the socket.
    conn.close()
    return toret

