#Quick symgrate.com client script for Thumb2 symbol recovery.
#@author Travis Goodspeed & evm
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 


## This is an IDA 6.x script that queries the Symgrate2
## database, in order to recognize standard functions from a variety
## of embedded ARM development kits.

import httplib;
import idc

#Must match the server.
LEN=18

def queryfns(conn, q):
    """Queries the server for a dozen or more functions."""
    conn.request("GET", "/fns?"+q) 
    r1 = conn.getresponse()
    # print r1.status, r1.reason
    # 200 OK ?
    toret=None;
    if r1.status==200:
        data = r1.read();
        if len(data)>2:
            print data.strip();

    return toret;

#fncount=currentProgram.getFunctionManager().getFunctionCount();
#monitor.initialize(fncount);

# Iterate over all the functions, querying from the database and printing them.
fnhandled=0;

conn = httplib.HTTPConnection("symgrate.com",80)

qstr="";

start=0
end=0
start=idc.SegByBase(idc.SegByName(".text"))
if (start != idc.BADADDR):
    end = idc.SegEnd(start)
else:
    start = idc.NextFunction(0)
    end = idc.BADADDR

f=start

while (f != idc.BADADDR) and (f <= end):
    iname=idc.GetFunctionName(f);
    adr=f
    adrstr="%x"%f;
    res=None;

    B=bytearray(idc.GetManyBytes(adr, LEN));
    bstr="";
    for b in B: bstr+="%02x"%(0x00FF&b)

    # We query the server in batches of 64 functions to reduce HTTP overhead.
    qstr+="%s=%s&"%(adrstr,bstr)
    f = idc.NextFunction(f)

    if fnhandled&0x3F==0 or f is None:
        res=queryfns(conn,qstr);
        #monitor.setProgress(fnhandled);
        qstr="";
    
    fnhandled+=1;

conn.close();


#Queries an example sprintf for testing.
#queryfn("0eb440f2000370b59db021acc0f20003064602a954f8042b4ff402751868cff6ff7502962346019406966ff0004405950794");

