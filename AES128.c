// Algoritmo AES-128




// Esse algoritmo segue o documento "FIPS 197 Advanced Encryption Standard (AES)"



// O algoritmo AES serve para cifrar blocos de 128 bits. O bloco de 128 bits cifrado é então usado por outro algoritmo como o GCM para gerar a criptografia final.


// dados -> cifra AES -> algoritmo GCM -> dados criptografados



// O algoritmo AES recebe como entrada um bloco de dados de 128 bits e uma chave de 128, 192 ou 256 bits,

// O AES então gera uma expansão da chave. Usando essa expansão ele fornece na saída um bloco de 128 bits que são os dados de entrada cifrados.




// primeiro gerar uma expansão da chave com a função keyExpansion().

// Depois cifrar um bloco de 128 bits chamando a função chiper(). 



// Antes de chamar chiper() pela 1 vez, keyExpansion() deve ser chamada para expandir a chave (keySchedule).

// Antes de chamar keyExpansion() o array "keySchedule[44]" deve ter os 4 primeiros elementos preenchidos com o valor da chave (chave de 128 bits).
 

// Após ser gerado a expansão da chave, chiper() pode ser chamada, porém antes deve-se definir os 128 bits a serem cifrados na variável "unsigned char dados[16]"

// após o fim da execução de chiper() "unsigned char dados[16]" contém a cifra de 128 bits.








int keyExpansion(unsigned int k1, unsigned int k2, unsigned int k3, unsigned int k4);

int chiper();

static int invChiper();

static int addRoundKey(unsigned char round);

static int subBytes();

static int invSubBytes();

static int shiftRows();

static int invShiftRows();

static int mixColumns();

static int invMixColumns();

static unsigned char xTimes(unsigned char byte);

static unsigned char multiGF228(unsigned char byte, unsigned char num);










unsigned char dados[16];

static unsigned char dadosMixColumns[16];

static unsigned int keySchedule[44];  // as 4 primeiras words de keySchedule devem receber as 4 words da chave (key)

unsigned char *byteKeySchedule = (unsigned char *)&keySchedule;



static const unsigned char matrizSbox[16][16] = {

{0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},

{0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},

{0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},

{0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},

{0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},

{0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},

{0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},

{0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},

{0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},

{0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},

{0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},

{0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},

{0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},

{0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},

{0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},

{0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}

};






static const unsigned char matrizInvSbox[16][16] = {

{0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},

{0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},

{0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},

{0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},

{0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},

{0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},

{0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},

{0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},

{0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},

{0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},

{0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},

{0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},

{0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},

{0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},

{0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},

{0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}

};







static const unsigned int Rcon[11] = { 0, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000 };



















int keyExpansion(unsigned int k1, unsigned int k2, unsigned int k3, unsigned int k4) {


keySchedule[0] = k1;

keySchedule[1] = k2;

keySchedule[2] = k3;

keySchedule[3] = k4;

unsigned char Nr = 10;

unsigned char Nk = 4;

unsigned char i = Nk;

unsigned int temp;

unsigned char *bytetemp = (unsigned char *)&temp;

unsigned char linha, coluna, auxiliar;


while( i <= (4*Nr+3) ) {

temp = keySchedule[i-1];


if ( (i % Nk) == 0 ) { // se i mod Nk == 0

// RotWord

auxiliar = bytetemp[3];

temp = temp << 8;

bytetemp[0] = auxiliar;

// RotWord


// SubWord

unsigned char ind;

for (ind = 0; ind < 4; ind++) {

linha = bytetemp[ind] & 0xF0;

linha = linha >> 4;

coluna = bytetemp[ind] & 0x0F;

bytetemp[ind] = matrizSbox[linha][coluna];

} // for

// SubWord


temp = temp ^ Rcon[i/Nk];

} // se i mod Nk == 0


keySchedule[i] = keySchedule[i - Nk] ^ temp;


i++;

} // while

return 1;

} // keyExpansion()










int chiper() {

addRoundKey(0);

unsigned char round;


for (round = 1; round < 10; round++) {

subBytes();

shiftRows();

mixColumns();

addRoundKey(round);

} // for


subBytes();

shiftRows();

addRoundKey(round);

return 0;

// resultado em dados[16]

} // chipher










static int invChiper() {

addRoundKey(10);

unsigned char round;


for (round = 9; round > 0; round--) {

invShiftRows();

invSubBytes();

addRoundKey(round);

invMixColumns();

} // for

invShiftRows();

invSubBytes();

addRoundKey(0);

return 0;

} // invChipher










static int addRoundKey(unsigned char round) {

unsigned char indiceKeySchedule = round * 4;

unsigned char byteRoundKey = indiceKeySchedule * 4;

unsigned char lop = 0;


while(lop < 16) {

dados[lop] = dados[lop] ^ byteKeySchedule[byteRoundKey + 3];

dados[lop + 1] = dados[lop + 1] ^ byteKeySchedule[byteRoundKey + 2];

dados[lop + 2] = dados[lop + 2] ^ byteKeySchedule[byteRoundKey + 1];

dados[lop + 3] = dados[lop + 3] ^ byteKeySchedule[byteRoundKey];

lop = lop + 4;

byteRoundKey = byteRoundKey + 4;

} // while


return 1;

} // addRoundKey





static int subBytes() {

unsigned char indi, linha, coluna;

for (indi = 0; indi < 16; indi++) {

linha = dados[indi] & 0xF0;

linha = linha >> 4;

coluna = dados[indi] & 0x0F;

dados[indi] = matrizSbox[linha][coluna];

} // for

return 1;

} // subBytes





static int invSubBytes() {

unsigned char indi, linha, coluna;

for (indi = 0; indi < 16; indi++) {

linha = dados[indi] & 0xF0;

linha = linha >> 4;

coluna = dados[indi] & 0x0F;

dados[indi] = matrizInvSbox[linha][coluna];

} // for

return 1;

} // invSubBytes





static int shiftRows() {

unsigned char aux, aux2;

aux = dados[1];

dados[1] = dados[5]; dados[5] = dados[9]; dados[9] = dados[13]; dados[13] = aux;


aux = dados[2]; aux2 = dados[6];

dados[2] = dados[10]; dados[6] = dados[14]; dados[10] = aux; dados[14] = aux2;


aux = dados[15];

dados[15] = dados[11]; dados[11] = dados[7]; dados[7] = dados[3]; dados[3] = aux;

return 1;

} // shiftRows





static int invShiftRows() {

unsigned char aux, aux2;

aux = dados[1];

dados[1] = dados[13]; dados[13] = dados[9]; dados[9] = dados[5]; dados[5] = aux;


aux = dados[2]; aux2 = dados[6];

dados[2] = dados[10]; dados[6] = dados[14]; dados[10] = aux; dados[14] = aux2;


aux = dados[3];

dados[3] = dados[7]; dados[7] = dados[11]; dados[11] = dados[15]; dados[15] = aux;

return 1;

} // invShiftRows





static int mixColumns() {

unsigned char coluna, vezes2, vezes3;


for (coluna = 0; coluna < 4; coluna++) {


vezes2 = xTimes(dados[coluna*4+0]);

vezes3 = xTimes(dados[coluna*4+1]);

vezes3 = vezes3 ^ dados[coluna*4+1];

dadosMixColumns[coluna*4+0] = vezes2 ^ vezes3 ^ dados[coluna*4+2] ^ dados[coluna*4+3];


vezes2 = xTimes(dados[coluna*4+1]);

vezes3 = xTimes(dados[coluna*4+2]);

vezes3 = vezes3 ^ dados[coluna*4+2];

dadosMixColumns[coluna*4+1] = dados[coluna*4+0] ^ vezes2 ^ vezes3 ^ dados[coluna*4+3];


vezes2 = xTimes(dados[coluna*4+2]);

vezes3 = xTimes(dados[coluna*4+3]);

vezes3 = vezes3 ^ dados[coluna*4+3];

dadosMixColumns[coluna*4+2] = dados[coluna*4+0] ^ dados[coluna*4+1] ^ vezes2 ^ vezes3;


vezes2 = xTimes(dados[coluna*4+3]);

vezes3 = xTimes(dados[coluna*4+0]);

vezes3 = vezes3 ^ dados[coluna*4+0];

dadosMixColumns[coluna*4+3] = vezes3 ^ dados[coluna*4+1] ^ dados[coluna*4+2] ^ vezes2;


} // for


for (coluna = 0; coluna < 16; coluna++) { dados[coluna] = dadosMixColumns[coluna]; }

return 1;

} // mixColumns





static int invMixColumns() {

unsigned char coluna, vezes9, vezes11, vezes13, vezes14;


for (coluna = 0; coluna < 4; coluna++) {


vezes14 = multiGF228(dados[coluna*4+0], 14);

vezes9 = multiGF228(dados[coluna*4+3], 9);

vezes11 = multiGF228(dados[coluna*4+1], 11);

vezes13 = multiGF228(dados[coluna*4+2], 13);

dadosMixColumns[coluna*4+0] = vezes14 ^ vezes11 ^ vezes13 ^ vezes9;



vezes14 = multiGF228(dados[coluna*4+1], 14);

vezes9 = multiGF228(dados[coluna*4+0], 9);

vezes11 = multiGF228(dados[coluna*4+2], 11);

vezes13 = multiGF228(dados[coluna*4+3], 13);

dadosMixColumns[coluna*4+1] = vezes9 ^ vezes14 ^ vezes11 ^ vezes13;



vezes14 = multiGF228(dados[coluna*4+2], 14);

vezes9 = multiGF228(dados[coluna*4+1], 9);

vezes11 = multiGF228(dados[coluna*4+3], 11);

vezes13 = multiGF228(dados[coluna*4+0], 13);

dadosMixColumns[coluna*4+2] = vezes13 ^ vezes9 ^ vezes14 ^ vezes11;



vezes14 = multiGF228(dados[coluna*4+3], 14);

vezes9 = multiGF228(dados[coluna*4+2], 9);

vezes11 = multiGF228(dados[coluna*4+0], 11);

vezes13 = multiGF228(dados[coluna*4+1], 13);

dadosMixColumns[coluna*4+3] = vezes11 ^ vezes13 ^ vezes9 ^ vezes14;


} // for


for (coluna = 0; coluna < 16; coluna++) { dados[coluna] = dadosMixColumns[coluna]; }

return 1;

} // invMixColumns





static unsigned char multiGF228(unsigned char byte, unsigned char num) {

unsigned char vezes2, vezes4, vezes8, resul;

vezes2 = xTimes(byte);

vezes4 = xTimes(vezes2);

vezes8 = xTimes(vezes4);

if (num == 14) { resul = vezes8 ^ vezes4 ^ vezes2; }

else if (num ==  9) { resul = vezes8 ^ byte; }

else if (num == 11) { resul = vezes8 ^ vezes2 ^ byte; }

else if (num == 13) { resul = vezes8 ^ vezes4 ^ byte; }

return resul;

} // multiGF228





static unsigned char xTimes(unsigned char byte) {

if (byte & 0x80) { byte = byte << 1; byte = byte ^ 0x1B; }

else { byte = byte << 1; }

return byte;

} // xTimes
