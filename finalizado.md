Desafios já finalizados

ALGORITMOS EXIGIDOS PELO PROTOCOLO TLS 1.3 ---------------------------------------------------------------------------------------------------


AES 128 GCM  //////////////////////////////////////////////////////////////////////////////////////

A pasta "AES128-GCM" contém o arquivo "AES128.c" que é o código para executar a cifra AES com chave de 128 bits.

O arquivo "algoritmoGCM.c" contém o código do modo GCM para o AES.

A criptografia simetrica AES128 GCM é realizada chamando a função "criptografiaGCM()" no arquivo "algoritmoGCM.c".


O arquivo "testeAes.c" contém um pequeno código para testar o algoritmo AES128.

É necessario compilar os arquivos com o gcc no Linux.

exemplo de linha de comando :

gcc AES128.c testeAes.c -o executavel


O arquivo "testeAes128Gcm.c" contém um pequeno código para testar o algoritmo GCM para criptografar dados.

O algoritmo GCM usa o arquivo "AES128.c"

É necessario compilar os arquivos com o gcc no Linux.

exemplo de linha de comando :

gcc AES128.c algoritmoGCM.c testeAes128Gcm.c -o executavel

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

----------------------------------------------------------------------------------------------------------------------------------------------------------------
