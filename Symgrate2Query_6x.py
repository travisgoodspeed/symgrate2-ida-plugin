#Quick symgrate.com client script for Thumb2 symbol recovery.
#@author Travis Goodspeed & evm
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 


## This is an IDA 6.x script that queries the Symgrate2
## database, in order to recognize standard functions from a variety
## of embedded ARM development kits.

import Symgrate2 
import idc

def ida_renamefunctions(j):
    x=json.loads(j)
    for f in x:
        fnameu=x[f]["Name"]
        fname=fnameu.encode('utf-8')
        print("renaming %s to %s" % (f,fname))
        fadr=int(f,16)
        idc.MakeName(fadr,fname)
       

def ida_functionprefix(fun):
    """Returns the first eighteen bytes of a function as ASCII."""
    B=bytearray(idc.GetManyBytes(adr, Symgrate2.SEARCHLEN));
    bstr="";
    for b in B: bstr+="%02x"%(0x00FF&b)
    return bstr

# Iterate over all the functions, querying from the database and printing them.
fnhandled=0;

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

    bstr = ida_functionprefix(f)
    # We query the server in batches of 64 functions to reduce HTTP overhead.
    qstr+="%s=%s&"%(adrstr,bstr)
    f = idc.NextFunction(f)

    if fnhandled&0x3F==0 or f is None:
        res=Symgrate2.queryjfns(qstr);
        qstr="";
        if res!=None:
            Symgrate2.jprint(res)
            #optionally rename functions to the values found in the query
            ida_renamefunctions(res)
    
    fnhandled+=1;

res=Symgrate2.queryjfns(qstr)
if res!=None: 
    Symgrate2.jprint(res)
    #optionally rename functions
    ida_renamefunctions(res)


#Queries an example sprintf for testing.
#queryfn("0eb440f2000370b59db021acc0f20003064602a954f8042b4ff402751868cff6ff7502962346019406966ff0004405950794");

