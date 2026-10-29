# ArRahmah

Aplikasi nota jual-beli kambing dan daging untuk Android (WebView membungkus satu berkas HTML, data tersimpan lokal).

- Versi terbaru: **2.2** (versionCode 11), minSdk 24
- Mode Penjualan (terang) dan Pembelian (gelap), tab bar ala myBCA
- Backup ke Google Drive, kirim nota sebagai gambar ke WhatsApp

## Isi repo
- `web/index.html` aplikasi (sumber `assets/index.html` di APK)
- `tools/` skrip tambal manifest/dex, rakit zip, dan tanda tangan APK v2
- `releases/` APK siap pasang

## Build ulang
Butuh Python 3 dengan paket `cryptography` dan hasil ekstrak APK dasar di `orig/`.
```
python3 -I tools/patch.py && python3 -I tools/assemble.py && python3 -I tools/verify.py ArRahmah.apk
```

## Kunci tanda tangan
Kunci (`arrahmah-key.pem`) **tidak disimpan di repo ini** (lihat `.gitignore`). Simpan di tempat aman.
Tanpa kunci yang sama, versi baru tidak bisa dipasang menimpa versi lama.
Sidik jari sertifikat SHA-256: `a94a4743dc256c7042f3a7ab04395fce754b215604ab188f898c877732018064`
