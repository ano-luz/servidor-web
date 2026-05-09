Para começar precisamos implementar o protocolo TLS 1.3 definido na RFC 8446 "The Transport Layer Security (TLS) Protocol Version 1.3".

Porém antes de começar a estruturar a lógica do tls 1.3 precisamos ter em mãos alguns dos algoritmos exigidos por esse protocolo.

São eles :

. AES-128 GCM

. SHA256

. Assinatura RSA-PSS-RSAE_SHA256

. Troca de chave secp256r1
