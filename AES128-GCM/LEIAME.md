O arquivo "AES128.c" contém o código da cifra AES-128.

O arquivo "testeAes.c" contém um pequeno código para testar o algoritmo AES do arquivo "AES128.c". É preciso compilar os dois arquivos juntos.

exemplo de linha de comando :

gcc AES128.c testeAes.c -o executavel

O AES sozinho não gera dados criptografados apenas dados chamados "cifrados". É preciso usar um modo junto com o AES para gerar dados criptografados.

O arquivo "algoritmoGCM.c" contém o código do modo GCM que usa o AES no arquivo "AES128.c".

O arquivo "testeAes128Gcm.c" tem um código para testar o GCM. É preciso compilar os 3 arquivos juntos.

Exemplo de linha de comando :

gcc AES128.c algoritmoGCM.c testeAes128Gcm.c -o executavel
