#! /usr/bin/python

import sys

if len(sys.argv) != 3:
    print "Usage: %s <functional simualtor output> <verilog simulator output>" % sys.argv[0]
    sys.exit(0)

f = open(sys.argv[1])
foutput = f.readlines()
f.close()

f = open(sys.argv[2])
voutput = f.readlines()
f.close()

fparse = filter(lambda x: x.find('>>>') != -1, foutput)
vparse = filter(lambda x: x.find('>>>') != -1, voutput)

fparse = map(lambda x: x.split('\n')[0], fparse)
vparse = map(lambda x: x.split('\n')[0], vparse)

fparse.append('>>>pc=end')
vparse.append('>>>pc=end')

fstory = []
pc = ''
regs = []

for line in fparse:
    rline = line.split('>>>')[1]
    parse = rline.split('=')
    cmd = parse[0]
    value = parse[1]
    if   cmd == 'pc':
        if pc != '':
            regs.sort()
            fstory.append([pc, inst, psr, wim, y, regs])
        pc = value
        regs = []
    elif cmd == 'inst': inst = value
    elif cmd == 'psr': psr = value
    elif cmd == 'wim': wim = value
    elif cmd == 'y': y = value
    else: regs.append([int(cmd), value])

vstory = []
pc = ''
regs = []

for line in vparse:
    rline = line.split('>>>')[1]
    parse = rline.split('=')
    cmd = parse[0]
    value = parse[1]
    if   cmd == 'pc':
        if pc != '':
            regs.sort()
            vstory.append([pc, inst, psr, wim, y, regs])
        pc = value
        regs = []
    elif cmd == 'inst': inst = value
    elif cmd == 'psr': psr = value
    elif cmd == 'wim': wim = value
    elif cmd == 'y': y = value
    else: regs.append([int(cmd), value])

nwindows = 3
fwindow = []
vwindow = []
for i in range(8+16*nwindows):
    fwindow.append('0x00000000')
    vwindow.append('0x00000000')

fcycle = 0
vcycle = 0

while 1:
    fline = fstory[fcycle]
    vline = vstory[vcycle]

    fpc = fline[0]
    finst = fline[1]
    fpsr = fline[2]
    fwim = fline[3]
    fy = fline[4]
    fregs = fline[5]

    vpc = vline[0]
    vinst = vline[1]
    vpsr = vline[2]
    vwim = vline[3]
    vy = vline[4]
    vregs = vline[5]

    for reg in fregs:
        fwindow[reg[0]] = reg[1]

    for reg in vregs:
        vwindow[reg[0]] = reg[1]
    print "-----"
    print "       fcycl=%10d, vcycl=%10d" % (fcycle, vcycle)
    print "[%s] fpc  =%s, vpc  =%s" % (fpc==vpc and 'SAME' or 'DIFF', fpc, vpc)
    print "[%s] finst=%s, vinst=%s" % (finst==vinst and 'SAME' or 'DIFF', finst, vinst)
    print "[%s] fpsr =%s, vpsr =%s" % (fpsr==vpsr and 'SAME' or 'DIFF', fpsr, vpsr)
    print "[%s] fwim =%s, vwim =%s" % (fwim==vwim and 'SAME' or 'DIFF', fwim, vwim)
    print "[%s] fy   =%s, vy   =%s" % (fy==vy and 'SAME' or 'DIFF', fy, vy)
    print "[%s] freg            , vreg    " % (fwindow==vwindow and 'SAME' or 'DIFF')

    for i in range(8+16*nwindows):
        print "  (%2d)       %s        %s" % (i, fwindow[i], vwindow[i])

    fcycle = fcycle + 1
    vcycle = vcycle + 1

    if fcycle >= len(fstory) or vcycle >= len(vstory): break
