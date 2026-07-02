# Live Demo PASETO

Demo lokal untuk presentasi JWT vs token secure.

## Jalankan

```bash
npm start
```

Lalu buka:

- Presenter: http://localhost:8080/presenter.html
- Audience: http://localhost:8080/audience.html

## Alur test cepat

1. Buka audience, isi nama.
2. Tekan `Demo JWT rentan`.
3. Tekan `Forge JWT ADMIN`, lalu `Akses brankas rahasia`.
4. Presenter akan menampilkan notifikasi `SISTEM DIRETAS`.
5. Tekan `Demo PASETO secure`.
6. Tekan `Rusak 1 karakter`, lalu `Akses brankas rahasia`.
7. Request akan diblokir.

Catatan: implementasi secure lokal ini memakai AEAD `AES-256-GCM` dengan prefix `v4.local` agar bisa berjalan tanpa dependency eksternal. Untuk produksi atau demo Spring Boot final, ganti dengan library PASETO resmi.
