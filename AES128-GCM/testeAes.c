
#include <stdio.h>










int keyExpansion(unsigned int k1, unsigned int k2, unsigned int k3, unsigned int k4);  // função do arquivo AES128.c

int chiper();  // função do arquivo AES128.c




extern unsigned char dados[16];  // array do arquivo AES128.c










int main() {


// definindo a chave de 128 bits udada na cifra AES

// k1 tem os 32 bits mais significativos da chave, k2 tem os 32 bits seguintes, e assim por diante.


unsigned int k1 = 0x2b7e1516;
unsigned int k2 = 0x28aed2a6;
unsigned int k3 = 0xabf71588;
unsigned int k4 = 0x09cf4f3c;


keyExpansion(k1, k2, k3, k4);    // gerando a expansão de chave




// definindo os 128 bits a serem cifrados, o indice 0 tem os bits mais significativos



dados[0] = 0x32;
dados[1] = 0x43;
dados[2] = 0xf6;
dados[3] = 0xa8;
dados[4] = 0x88;
dados[5] = 0x5a;
dados[6] = 0x30;
dados[7] = 0x8d;
dados[8] = 0x31;
dados[9] = 0x31;
dados[10] = 0x98;
dados[11] = 0xa2;
dados[12] = 0xe0;
dados[13] = 0x37;
dados[14] = 0x07;
dados[15] = 0x34;


chiper();


printf("%x %x %x %x %s", dados[0], dados[4], dados[8], dados[12], "\n");

printf("%x %x %x %x %s", dados[1], dados[5], dados[9], dados[13], "\n");

printf("%x %x %x %x %s", dados[2], dados[6], dados[10], dados[14], "\n");

printf("%x %x %x %x %s", dados[3], dados[7], dados[11], dados[15], "\n");



return 0;

}