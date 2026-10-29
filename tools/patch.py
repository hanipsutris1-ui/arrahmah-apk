import struct,zlib,hashlib,re,sys
O='/tmp/apkwork/orig/'; B='/tmp/apkwork/build/'
# ---------- MANIFEST ----------
m=bytearray(open(O+'AndroidManifest.xml','rb').read())
sp=8; t,h2,sz,cnt,sc,flags,sstart,ststart=struct.unpack('<HHIIIIII',m[sp:sp+28])
assert flags&0x100==0 and sc==0
offs=struct.unpack('<%dI'%cnt,m[sp+28:sp+28+4*cnt]); base=sp+sstart
def get(i):
    p=base+offs[i]; l=struct.unpack('<H',m[p:p+2])[0]; return p,l,m[p+2:p+2+2*l].decode('utf16')
def setstr(old,new):
    for i in range(cnt):
        p,l,s=get(i)
        if s==old:
            assert len(new)==l,(old,new)
            m[p+2:p+2+2*l]=new.encode('utf-16-le'); print('manifest:',old,'->',new); return i
    raise SystemExit('tidak ada '+old)
setstr('Arrahmah','ArRahmah'); setstr('2.0','2.2')
# versionCode 14 -> 15 : cari atribut int bernama 'versionCode'
names=[get(i)[2] for i in range(cnt)]; vc=names.index('versionCode')
pos=8+sz  # setelah string pool
found=False
while pos<len(m):
    ct,chs,csz=struct.unpack('<HHI',m[pos:pos+8])
    if ct==0x0102:  # start element
        ns,line,cm,nsi,nm,aoff,asz,acnt=struct.unpack('<IIIIIHHH',m[pos+8:pos+8+26]) if False else (None,)*8
        ac=struct.unpack('<H',m[pos+28:pos+30])[0]; ab=pos+16+ struct.unpack('<H',m[pos+24:pos+26])[0]
        for a in range(ac):
            q=ab+a*20; ans,an,araw,dsz,res0,dt,dat=struct.unpack('<IIIHBBI',m[q:q+20])
            if an==vc and dt==0x10:
                print('versionCode',dat,'->',dat+2); m[q+16:q+20]=struct.pack('<I',dat+2); found=True
            if names[an] in('minSdkVersion','targetSdkVersion') : print(names[an],dat)
    pos+=csz
assert found
open(B+'AndroidManifest.xml','wb').write(m)
# ---------- DEX ----------
d=bytearray(open(O+'classes.dex','rb').read())
sids,soff=struct.unpack('<II',d[56:64])
def uleb(p):
    r=s=n=0
    while True:
        b=d[p+n]; r|=(b&0x7f)<<s; n+=1
        if not b&0x80: return r,n
        s+=7
def strings():
    out=[]
    for i in range(sids):
        off=struct.unpack('<I',d[soff+4*i:soff+4*i+4])[0]; l,n=uleb(off); e=d.index(b'\0',off+n); out.append((off,l,n,bytes(d[off+n:e]).decode('utf8','surrogateescape')))
    return out
S=strings()
RENAME={'/NotaDaging':'/arrahmah','Download/NotaDaging':'Download/arrahmah','Pictures/NotaDaging':'Pictures/arrahmah',
 'Gambar nota tersimpan di Pictures/NotaDaging.':'Gambar nota tersimpan di Pictures/arrahmah.','Gambar tersimpan di Pictures/NotaDaging':'Gambar tersimpan di Pictures/arrahmah'}
done=0
for off,l,n,s in S:
    if s in RENAME:
        new=RENAME[s]; assert len(new)<128 and len(s)<128 and len(new.encode())==len(new)
        slot=n+len(s)+1; dl=len(s)-len(new); assert dl>=0
        ul=n+dl  # uleb diisi non-kanonik agar slot tetap sama
        u=bytearray([ (len(new)&0x7f)|0x80 ]+[0x80]*(ul-2)+[0x00]); assert len(u)==ul
        item=bytes(u)+new.encode()+b'\0'; assert len(item)==slot,(len(item),slot)
        d[off:off+slot]=item; done+=1; print('dex:',repr(s),'->',repr(new))
assert done==len(RENAME),done
S2=strings(); K=[x[3].encode('utf-8','surrogateescape') for x in S2]
bad=[i for i in range(len(K)-1) if K[i]>=K[i+1]]
orig=[i for i in range(len(S)-1) if S[i][3].encode('utf-8','surrogateescape')>=S[i+1][3].encode('utf-8','surrogateescape')]
assert bad==orig,('urutan string berubah',bad,orig)
assert [x[3] for x in S2].count('Download/arrahmah')==1
print('urutan string dex tetap terurut; jumlah',len(S2))
d[12:32]=b'\0'*20
d[8:12]=b'\0\0\0\0'
sha=hashlib.sha1(bytes(d[32:])).digest(); d[12:32]=sha
d[8:12]=struct.pack('<I',zlib.adler32(bytes(d[12:]))&0xffffffff)
open(B+'classes.dex','wb').write(d); print('dex ok',len(d))
