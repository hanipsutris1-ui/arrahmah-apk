import struct,zipfile,hashlib,sys,zlib
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes,serialization
from cryptography import x509
p=sys.argv[1]; b=open(p,'rb').read()
z=zipfile.ZipFile(p); print('zip test:',z.testzip() or 'OK'); 
for i in z.infolist():
    print(' ',i.filename,i.file_size,'stored' if i.compress_type==0 else 'deflate','offset-data',(i.header_offset+30+len(i.filename.encode())+struct.unpack('<H',b[i.header_offset+28:i.header_offset+30])[0])%4)
e=b.rfind(b'PK\x05\x06'); cdsize,cdoff=struct.unpack('<II',b[e+12:e+20])
assert b[cdoff-16:cdoff]==b'APK Sig Block 42'
bs=struct.unpack('<Q',b[cdoff-24:cdoff-16])[0]; bstart=cdoff-bs-8
assert struct.unpack('<Q',b[bstart:bstart+8])[0]==bs; print('blok tanda tangan di',bstart,'ukuran',bs)
q=bstart+8; pairs={}
while q<cdoff-24:
    l,i=struct.unpack('<QI',b[q:q+12]); pairs[i]=b[q+12:q+8+l]; q+=8+l
v=pairs[0x7109871a]
def rd(buf,o=0):
    l=struct.unpack('<I',buf[o:o+4])[0]; return buf[o+4:o+4+l],o+4+l
signers,_=rd(v); signer,_=rd(signers); signed,o=rd(signer); sigs,o=rd(signer,o); pub,o=rd(signer,o)
sig_rec,_=rd(sigs); algo=struct.unpack('<I',sig_rec[:4])[0]; sig,_=rd(sig_rec,4)
print('algo',hex(algo))
pk=serialization.load_der_public_key(pub); pk.verify(sig,signed,padding.PKCS1v15(),hashes.SHA256()); print('tanda tangan RSA: VALID')
digs,o=rd(signed); certs,o=rd(signed,o)
rec,_=rd(digs); dalgo=struct.unpack('<I',rec[:4])[0]; dig,_=rd(rec,4)
c1,_=rd(certs); cert=x509.load_der_x509_certificate(c1); print('subjek:',cert.subject.rfc4514_string(),'| berlaku sampai',cert.not_valid_after_utc.date())
assert cert.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)==pub
# hitung ulang digest isi
sec1=b[:bstart]; sec2=b[cdoff:cdoff+cdsize]; eo=bytearray(b[cdoff+cdsize:]); eo[16:20]=struct.pack('<I',bstart)
CH=1<<20; ds=[]
for sec in (sec1,sec2,bytes(eo)):
    for i in range(0,max(len(sec),1),CH):
        c=sec[i:i+CH]; ds.append(hashlib.sha256(b'\xa5'+struct.pack('<I',len(c))+c).digest())
top=hashlib.sha256(b'\x5a'+struct.pack('<I',len(ds))+b''.join(ds)).digest()
print('digest isi cocok:',top==dig)
# dex
d=z.read('classes.dex'); print('dex checksum ok:',struct.unpack('<I',d[8:12])[0]==zlib.adler32(d[12:])&0xffffffff,'| sha1 ok:',d[12:32]==hashlib.sha1(d[32:]).digest())
