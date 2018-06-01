# Crypto Reference

## Cryptol

[Cryptol](https://cryptol.net/) adalah sebuah DSL (Domain-Specific Language) yang khusus digunakan untuk keperluan eksperimen terhadap algoritma kriptografi serta analisisnya. Cryptol merupakan bahasa deklaratif dengan pendekatan yang mirip dengna notasi matematis sehingga membuat pembuatan algoritma kriptografi menjadi lebih ekspresif tanpa perlu melibatkan detail yang tidak diperlukan (seperti penanganan buffer, perkalian bilangan yang efisien, dsb).

Umumnya, spesifikasi algoritma yang dituangkan di paper maupun jurnal memiliki satu keterbatasan yaitu notasi matematik bukan merupakan executable sehingga tidak dapat diverifikasi saat runtime. Cryptol menjembatani hal ini sehingga spesifikasi algoritma dalam notasi matematik dapat diterjemahkan dengan cepat dan diobservasi hasilnya.

Cryptol telah digunakan di beberapa perusahan dan pemerintah. Sebelum akhirnya dilepas sebagai proyek open source, Cryptol awalnya didesain untuk badan pemerintah seperti NSA untuk berbagai keperluan yang berhubungan dengan kriptografi.