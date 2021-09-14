#Quick symgrate.com client script for Thumb2 symbol recovery.
#@author Travis Goodspeed & evm
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 


## This is an IDA script that queries the Symgrate2
## database, in order to recognize standard functions from a variety
## of embedded ARM development kits.

import idc
import ida_idaapi
import ida_segment

import Symgrate2

def ida_renamefunctions(j):
    x=json.loads(j)
    for f in x:
        fnameu=x[f]["Name"]
        fname=fnameu.encode('utf-8')
        print("renaming %s to %s" % (f,fname))
        fadr=int(f,16)
        ida_name.set_name(fadr,fname)
       

def ida_functionprefix(fun):
    """Returns the first eighteen bytes of a function as ASCII."""
    B=bytearray(ida_bytes.get_bytes(fun, Symgrate2.SEARCHLEN));
    bstr="";
    for b in B: bstr+="%02x"%(0x00FF&b)
    return bstr;

# Iterate over all the functions, querying from the database and printing them.
fnhandled=0;

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
    iname=idc.get_func_name(f)
    adr=f
    adrstr="%x"%f
    res=None

    bstr = ida_functionprefix(f)
    # We query the server in batches of 64 functions to reduce HTTP overhead.
    qstr+="%s=%s&"%(adrstr,bstr)
    f = idc.get_next_func(f)

    if fnhandled&0x3F==0 or f is None:
        res=Symgrate2.queryjfns(qstr)
        qstr=""
        if res!=None:
            Symgrate2.jprint(res)
            #optionally rename functions to the values found in the query
            #ida_renamefunctions(res)
    
    fnhandled+=1

res=Symgrate2.queryjfns(qstr)
if res!=None: 
    Symgrate2.jprint(res)
    #optionally rename functions
    #ida_renamefunctions(res)

