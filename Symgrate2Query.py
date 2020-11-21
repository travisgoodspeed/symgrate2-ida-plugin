#Quick symgrate.com client script for Thumb2 symbol recovery.
#@author Travis Goodspeed & evm
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 


## This is an IDA script that queries the Symgrate2
## database, in order to recognize standard functions from a variety
## of embedded ARM development kits.

import httplib;
import idc
import ida_idaapi
import ida_segment

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

#conn = httplib.HTTPConnection("localhost",80)
conn = httplib.HTTPConnection("symgrate.com",80)

qstr="";

start=0
end=0
t = ida_segment.get_segm_by_name(".text")
if (t and t.start_ea != ida_idaapi.BADADDR):
    start = t.start_ea
    end = t.end_ea
else:
    start = idc.get_next_func(0)
    end = ida_idaapi.BADADDR

f=start

while (f != ida_idaapi.BADADDR) and (f <= end):
    iname=idc.get_func_name(f);
    adr=f
    adrstr="%x"%f;
    res=None;

    B=bytearray(ida_bytes.get_bytes(adr, LEN));
    bstr="";
    for b in B: bstr+="%02x"%(0x00FF&b)

    # We query the server in batches of 64 functions to reduce HTTP overhead.
    qstr+="%s=%s&"%(adrstr,bstr)
    f = idc.get_next_func(f)

    if fnhandled&0x3F==0 or f is None:
        res=queryfns(conn,qstr);
        #monitor.setProgress(fnhandled);
        qstr="";
    
    fnhandled+=1;

conn.close();


#Queries an example sprintf for testing.
#queryfn("0eb440f2000370b59db021acc0f20003064602a954f8042b4ff402751868cff6ff7502962346019406966ff0004405950794");

