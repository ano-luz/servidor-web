
#include <stdio.h>



// Teste do algoritmo GCM que usa o algoritmo AES128









int criptografiaGCM(int tipo);  // tipo = 1 -> criptografia     tipo = 0 -> descriptografia

int keyExpansion(unsigned int k1, unsigned int k2, unsigned int k3, unsigned int k4);







extern unsigned char IV[12];

extern unsigned char P[65536];  // Armazena o Plaintext (os dados puro)

extern unsigned char C[65536];  // Armazena o ciphertext (os dados criptografados)

extern unsigned char A[65536];  // Armazena os dados adicionais, que serão apenas autenticados e não criptografados

extern unsigned int lenP;  // em bytes é o tamanho de P ou o tamanho de C

extern unsigned int lenA;  // em bytes é o tamanho de A

extern unsigned char T[16];  // Armazena a Tag de autenticação








int main() {

unsigned int k1 = 0xFEFFE992;
unsigned int k2 = 0x8665731C;
unsigned int k3 = 0x6D6A8F94;
unsigned int k4 = 0x67308308;

keyExpansion(k1, k2, k3, k4);

IV[0] = 0xCA;
IV[1] = 0xFE;
IV[2] = 0xBA;
IV[3] = 0xBE;
IV[4] = 0xFA;
IV[5] = 0xCE;
IV[6] = 0xDB;
IV[7] = 0xAD;
IV[8] = 0xDE;
IV[9] = 0xCA;
IV[10] = 0xF8;
IV[11] = 0x88;


P[0] = 0xD9;
P[1] = 0x31;
P[2] = 0x32;
P[3] = 0x25;
P[4] = 0xF8;
P[5] = 0x84;
P[6] = 0x06;
P[7] = 0xE5;
P[8] = 0xA5;
P[9] = 0x59;
P[10] = 0x09;
P[11] = 0xC5;
P[12] = 0xAF;
P[13] = 0xF5;
P[14] = 0x26;
P[15] = 0x9A;
P[16] = 0x86;
P[17] = 0xA7;
P[18] = 0xA9;
P[19] = 0x53;
P[20] = 0x15;
P[21] = 0x34;
P[22] = 0xF7;
P[23] = 0xDA;
P[24] = 0x2E;
P[25] = 0x4C;
P[26] = 0x30;
P[27] = 0x3D;
P[28] = 0x8A;
P[29] = 0x31;
P[30] = 0x8A;
P[31] = 0x72;
P[32] = 0x1C;
P[33] = 0x3C;
P[34] = 0x0C;
P[35] = 0x95;
P[36] = 0x95;
P[37] = 0x68;
P[38] = 0x09;
P[39] = 0x53;
P[40] = 0x2F;
P[41] = 0xCF;
P[42] = 0x0E;
P[43] = 0x24;
P[44] = 0x49;
P[45] = 0xA6;
P[46] = 0xB5;
P[47] = 0x25;
P[48] = 0xB1;
P[49] = 0x6A;
P[50] = 0xED;
P[51] = 0xF5;
P[52] = 0xAA;
P[53] = 0x0D;
P[54] = 0xE6;
P[55] = 0x57;
P[56] = 0xBA;
P[57] = 0x63;
P[58] = 0x7B;
P[59] = 0x39;
P[60] = 0x1A;
P[61] = 0xAF;
P[62] = 0xD2;
P[63] = 0x55;





A[0] = 0x3A;
A[1] = 0xD7;
A[2] = 0x7B;
A[3] = 0xB4;
A[4] = 0x0D;
A[5] = 0x7A;
A[6] = 0x36;
A[7] = 0x60;
A[8] = 0xA8;
A[9] = 0x9E;
A[10] = 0xCA;
A[11] = 0xF3;
A[12] = 0x24;
A[13] = 0x66;
A[14] = 0xEF;
A[15] = 0x97;
A[16] = 0xF5;
A[17] = 0xD3;
A[18] = 0xD5;
A[19] = 0x85;
A[20] = 0x03;
A[21] = 0xB9;
A[22] = 0x69;
A[23] = 0x9D;
A[24] = 0xE7;
A[25] = 0x85;
A[26] = 0x89;
A[27] = 0x5A;
A[28] = 0x96;
A[29] = 0xFD;
A[30] = 0xBA;
A[31] = 0xAF;
A[32] = 0x43;
A[33] = 0xB1;
A[34] = 0xCD;
A[35] = 0x7F;
A[36] = 0x59;
A[37] = 0x8E;
A[38] = 0xCE;
A[39] = 0x23;
A[40] = 0x88;
A[41] = 0x1B;
A[42] = 0x00;
A[43] = 0xE3;
A[44] = 0xED;
A[45] = 0x03;
A[46] = 0x06;
A[47] = 0x88;
A[48] = 0x7B;
A[49] = 0x0C;
A[50] = 0x78;
A[51] = 0x5E;
A[52] = 0x27;
A[53] = 0xE8;
A[54] = 0xAD;
A[55] = 0x3F;
A[56] = 0x82;
A[57] = 0x23;
A[58] = 0x20;
A[59] = 0x71;
A[60] = 0x04;
A[61] = 0x72;
A[62] = 0x5D;
A[63] = 0xD4;


lenP = 64;

lenA = 0;

criptografiaGCM(0);


printf("%x %x %x %x %s", T[0], T[4], T[8], T[12], "\n");

printf("%x %x %x %x %s", T[1], T[5], T[9], T[13], "\n");

printf("%x %x %x %x %s", T[2], T[6], T[10], T[14], "\n");

printf("%x %x %x %x %s", T[3], T[7], T[11], T[15], "\n Tag \n\n");


int ind;

for (ind = 0; ind < 16; ind++) { printf("%x %x %x %x %s", C[ind*4], C[ind*4+1], C[ind*4+2], C[ind*4+3], "\n"); }

printf("%s", "\n ciphertext \n");


} // main
