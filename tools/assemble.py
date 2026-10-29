import struct,zlib,hashlib,io,os,sys
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives import hashes,serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
O='/tmp/apkwork/orig/'; B='/tmp/apkwork/build/'
# ---- isi aplikasi ----
h=open('/mnt/user-data/outputs/nota-ar-rahmah.html',encoding='utf8').read()
for a,b in [('"backup-nota-daging-"','"backup-arrahmah-"'),('"backup-nota-gabung-"','"backup-arrahmah-"'),('title:"Backup Nota Daging"','title:"Backup ArRahmah"'),('bukan backup Nota Daging yang valid','bukan backup ArRahmah yang valid')]:
    assert h.count(a)>=1,a; h=h.replace(a,b)
html=h.encode('utf8')
entries=[ # (nama, data, simpan-tanpa-kompres, rata)
 ('AndroidManifest.xml',open(B+'AndroidManifest.xml','rb').read(),False),
 ('classes.dex',open(B+'classes.dex','rb').read(),False),
 ('resources.arsc',open(O+'resources.arsc','rb').read(),True),
 ('res/drawable/ic_launcher.png',open(O+'res/drawable/ic_launcher.png','rb').read(),True),
 ('assets/index.html',html,False)]
# ---- tulis zip (rata 4 byte untuk entri tanpa kompres) ----
out=io.BytesIO(); cds=[]
dt=(0<<11)|(0<<5)|0; dd=((2026-1980)<<9)|(10<<5)|26
for name,data,stored in entries:
    nb=name.encode(); crc=zlib.crc32(data)&0xffffffff
    if stored: comp=data; method=0
    else:
        c=zlib.compressobj(9,zlib.DEFLATED,-15); comp=c.compress(data)+c.flush(); method=8
    off=out.tell(); extra=b''
    if stored:
        pad=(-(off+30+len(nb)))%4; extra=b'\0'*pad
    out.write(struct.pack('<IHHHHHIIIHH',0x04034b50,20,0x0800,method,dt,dd,crc,len(comp),len(data),len(nb),len(extra))+nb+extra+comp)
    cds.append((nb,method,crc,len(comp),len(data),off,len(extra)))
cdoff=out.tell()
for nb,method,crc,cs,us,off,el in cds:
    out.write(struct.pack('<IHHHHHHIIIHHHHHII',0x02014b50,20,20,0x0800,method,dt,dd,crc,cs,us,len(nb),0,0,0,0,0,off)+nb)
cdsize=out.tell()-cdoff
out.write(struct.pack('<IHHHHIIH',0x06054b50,0,0,len(cds),len(cds),cdsize,cdoff,0))
z=out.getvalue()
# ---- kunci baru (disimpan agar pembaruan berikutnya bisa ditandatangani sama) ----
KP='/tmp/apkwork/arrahmah-key.pem'; CP='/tmp/apkwork/arrahmah-cert.pem'
if os.path.exists(KP):
    key=serialization.load_pem_private_key(open(KP,'rb').read(),None); cert=x509.load_pem_x509_certificate(open(CP,'rb').read())
else:
    key=rsa.generate_private_key(65537,2048)
    n=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'ArRahmah'),x509.NameAttribute(NameOID.ORGANIZATION_NAME,'Ar Rahmah')])
    now=datetime.datetime(2026,10,26)
    cert=(x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now+datetime.timedelta(days=36500)).sign(key,hashes.SHA256()))
    open(KP,'wb').write(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())); open(CP,'wb').write(cert.public_bytes(serialization.Encoding.PEM))
certder=cert.public_bytes(serialization.Encoding.DER); pub=key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
# ---- APK Signature Scheme v2 ----
sec1=z[:cdoff]; sec2=z[cdoff:cdoff+cdsize]; sec3=z[cdoff+cdsize:]  # EOCD: cd offset = awal blok tanda tangan = cdoff (sudah benar)
CH=1<<20
def chunks(b): return [b[i:i+CH] for i in range(0,len(b),CH)] or [b'']
digs=[]
for sec in (sec1,sec2,sec3):
    for c in chunks(sec): digs.append(hashlib.sha256(b'\xa5'+struct.pack('<I',len(c))+c).digest())
top=hashlib.sha256(b'\x5a'+struct.pack('<I',len(digs))+b''.join(digs)).digest()
lp=lambda b:struct.pack('<I',len(b))+b
ALGO=0x0103
digests=lp(struct.pack('<I',ALGO)+lp(top)); 
signed=lp(digests)+lp(lp(certder))+lp(b'')
sig=key.sign(signed,padding.PKCS1v15(),hashes.SHA256())
signer=lp(signed)+lp(lp(struct.pack('<I',ALGO)+lp(sig)))+lp(pub)
val=lp(lp(signer)); pair=struct.pack('<QI',4+len(val),0x7109871a)+val
blk=struct.pack('<Q',len(pair)+24)+pair+struct.pack('<Q',len(pair)+24)+b'APK Sig Block 42'
eocd=bytearray(sec3); eocd[16:20]=struct.pack('<I',cdoff+len(blk))
final=sec1+blk+sec2+bytes(eocd)
open('/tmp/apkwork/ArRahmah.apk','wb').write(final)
print('APK',len(final),'bytes; sidik jari sertifikat SHA-256:',hashlib.sha256(certder).hexdigest())
