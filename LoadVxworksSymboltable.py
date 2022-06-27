#TODO write a description for this script
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 


#TODO Add User Code Here

#from ghidra.util.task import ConsoleTaskMonitor
#from ghidra.program.model.listing import *

def p32(d):
    data = str(d)
    tmp = []
    for i in data:
        tmp.append(i)
    ''.join(tmp)
    result = tmp[6:8]
    result += tmp[4:6]
    result += tmp[2:4]
    result += tmp[:2]
    return ''.join(result)

getfn = lambda addr: getFunctionContaining(toAddr(addr)) # get function name from addr
getdta = lambda addr: str(getDataAt(toAddr(addr)).getValue().decode()) # get data string from addr in ds
setstr = lambda addr: createAsciiString(toAddr(addr))
setlabel = lambda x,y: createLabel(toAddr(x), y, True)

with open("/home/kali/Documents/projects/mercusys/_ac12v2-up_2020-09-03_10.35.35.bin.extracted/symtable.dump") as f:
    for l in f.readlines():
        if l == "\n":
            continue
           
        symdata = l.strip("\n")
        symfunc_addr = p32(symdata[8:])
        symstr_addr = p32(symdata[:8])

        try:
            symstr = getdta(symstr_addr)
            setlabel(symfunc_addr, symstr)
        except:
            setstr(symstr_addr)
            setlabel(symfunc_addr, symstr)

        print("Creating function \"{}\" at {}..".format(symstr, symfunc_addr))
        
       
   
test = 0x803ba7a0
err = 0x803ba7b8

