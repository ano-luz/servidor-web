// Algoritmo GCM


// Esse algoritmo segua o documento "NIST Special Publication 800-38D" 


// O GCM é um complemento do AES para gerar dados criptografados


// A função criptografiaGCM(), no modo criptografia, Recebe 3 inputs :

// . Um Plaintext denotado P. Os dados a serem criptografados.

// . Dados adicionais autenticados (opcional), denotado A. Esses dados não são criptografados mas apenas autenticados.

// . Vetor de inicialização, denotado IV e chamado de nonce.


// Fornece na saída :

// . Um Ciphertext, denotado C. Os dados criptografados.

// . Uma tag de autenticação, denotada T.




// A função criptografiaGCM(), no modo descriptografia, Recebe 4 inputs : nonce, A, T e C. 

// A saída fornece o Plaintext P que corresponde ao Ciphertext C ou um erro denotado FAIL.




// Antes de chamar a função criptografiaGCM(), deve-se definir os valores de P ou C, A, IV, lenA e lenP









int chiper();  // função do arquivo AES128.c






int criptografiaGCM(int tipo);  // tipo = 1 -> criptografia     tipo = 0 -> descriptografia

static int INK32(unsigned char *bitStringX);

static int mult2blocos(unsigned char *X, unsigned char *Y, unsigned char *resul);

static int GHASHH(unsigned char *X, unsigned int m);

static int GCTRk(unsigned char *ICB, unsigned char *X, unsigned char *Y, unsigned int tamanho);










extern unsigned char dados[16];  // array do arquivo AES128.c






static unsigned char Yhash[16];

static unsigned char H[16];

unsigned char IV[12];  // Armazena um nonce de 96 bits

static unsigned char J0[16];

static unsigned char J0INC[16];

static unsigned char CBdeGCTRk[16];

unsigned char P[65536];  // Armazena o Plaintext (os dados puro)

unsigned char C[65536];  // Armazena o ciphertext (os dados criptografados)

unsigned char A[65536];  // Armazena os dados adicionais, que serão apenas autenticados e não criptografados

unsigned int lenP;  // em bytes é o tamanho de P ou o tamanho de C

unsigned int lenA;  // em bytes é o tamanho de A

static unsigned char S[131072];

unsigned char T[16];  // Armazena a Tag de autenticação

















int criptografiaGCM(int tipo) {

// Antes de chamar essa função deve-se definir os valores de P ou C, A, IV, lenA e lenP


unsigned int u, v, is, ic, ind, tamS, G;


for (ind = 0; ind < 16; ind++) { dados[ind] = 0; }

chiper();

for (ind = 0; ind < 16; ind++) { H[ind] = dados[ind]; }


for (ind = 0; ind < 12; ind++) { J0[ind] = IV[ind]; }   // para nonce de 96 bits

J0[12] = 0; J0[13] = 0; J0[14] = 0; J0[15] = 1;


for (ind = 0; ind < 16; ind++) { J0INC[ind] = J0[ind]; }

INK32(J0INC);



if (lenP > 0) {

if (tipo == 1) { GCTRk(J0INC, P, C, lenP); }    // resultado em C que é o chipertext

else { GCTRk(J0INC, C, P, lenP); }    // resultado em P que é o plaintext

} // lenP > 0



G = lenP/16;              // lenP e lenA estão em bytes (multiplo de 8 bits) com isso u e v abaixo sempre será multiplo de 8.

if (lenP % 16) {G++;}

u = 128*G - (lenP*8);

G = lenA/16;

if (lenA % 16) {G++;}

v = 128*G - (lenA*8);

for (is = 0; is < lenA; is++) { S[is] = A[is]; }

// considerando que len(A) e len(P) são multiplos de 8 bits

u = u/8;

v = v/8;         // u e v estão em bytes agora


for (ind = 0; ind < v; ind++) { S[is] = 0; is++; }


ic = 0;

for (ind = 0; ind < lenP; ind++) { S[is] = C[ic]; is++; ic++; }


for (ind = 0; ind < u; ind++) { S[is] = 0; is++; }

unsigned int lenAx = lenA*8;

unsigned int lenPx = lenP*8;


S[is] = 0; S[is+1] = 0; S[is+2] = 0; S[is+3] = 0;

S[is+4] = (unsigned char)(lenAx >> 24); S[is+5] = (unsigned char)(lenAx >> 16); S[is+6] = (unsigned char)(lenAx >> 8); S[is+7] = (unsigned char)lenAx;

S[is+8] = 0; S[is+9] = 0; S[is+10] = 0; S[is+11] = 0;

S[is+12] = (unsigned char)(lenPx >> 24); S[is+13] = (unsigned char)(lenPx >> 16); S[is+14] = (unsigned char)(lenPx >> 8); S[is+15] = (unsigned char)lenPx; 


tamS = (lenA + v + lenP + u + 16) / 16;

GHASHH(S, tamS);    // resultado em Yhash


GCTRk(J0, Yhash, T, 16);   // resultado em T que é a tag


return 1;

} // criptografiaGCM()











int GCTRk(unsigned char *ICB, unsigned char *X, unsigned char *Y, unsigned int tamanho) { // tamanho deve receber a quantidade de bytes de X

unsigned int n = tamanho/16;

if (tamanho % 16) {n++;}


unsigned char ind;

for (ind = 0; ind < 16; ind++) { CBdeGCTRk[ind] = ICB[ind]; }


unsigned int i = 0;

for (i = 0; i < (n-1); i++) {


for (ind = 0; ind < 16; ind++) { dados[ind] = CBdeGCTRk[ind]; }

chiper();

for (ind = 0; ind < 16; ind++) { Y[ind+(i*16)] = X[ind+(i*16)] ^ dados[ind]; }

INK32(CBdeGCTRk);


} // for


for (ind = 0; ind < 16; ind++) { dados[ind] = CBdeGCTRk[ind]; }

chiper();


unsigned char indFinal = tamanho % 16;

if (indFinal == 0) {indFinal = 16;}


for (ind = 0; ind < indFinal; ind++) { Y[ind+(i*16)] = X[ind+(i*16)] ^ dados[ind]; }


return 1;

} // GCTRk()













int INK32(unsigned char *bitStringX) {  // O uso de INK32 no GCM sempre terá como entrada um bit string X de 128 bits

if (bitStringX[15] < 0xFF) { bitStringX[15]++; }

else if (bitStringX[14] < 0xFF) { bitStringX[14]++; bitStringX[15] = 0; }

else if (bitStringX[13] < 0xFF) { bitStringX[13]++; bitStringX[14] = 0; bitStringX[15] = 0; }

else if (bitStringX[12] < 0xFF) { bitStringX[12]++; bitStringX[13] = 0; bitStringX[14] = 0; bitStringX[15] = 0; }

else { bitStringX[12] = 0; bitStringX[13] = 0; bitStringX[14] = 0; bitStringX[15] = 0; }

return 1;

} // INK32()





int GHASHH(unsigned char *X, unsigned int m) {  // o bit string X deve ser multiplo de 128 bits (multiplo de 16 bytes) m é o valor do multiplo de 16 bytes

unsigned char ind;

unsigned int i;

for (ind = 0; ind < 16; ind++) { Yhash[ind] = 0; }


for (i = 0; i < m; i++) {

for (ind = 0; ind < 16; ind++) { Yhash[ind] = Yhash[ind] ^ X[ind+(16*i)]; }

mult2blocos(Yhash, H, Yhash);

} // for

return 1;

} // GHASHH()





int mult2blocos(unsigned char *X, unsigned char *Y, unsigned char *resul) {

unsigned long long int Z0[2] = {0, 0};

unsigned long long int R[2] = {0xE100000000000000, 0};

unsigned long long int V0[2];

unsigned char *byteV0 = (unsigned char *)V0;

unsigned char *byteZ0 = (unsigned char *)Z0;


// V0 = Y

byteV0[0] = Y[7]; byteV0[1] = Y[6]; byteV0[2] = Y[5]; byteV0[3] = Y[4]; byteV0[4] = Y[3]; byteV0[5] = Y[2]; byteV0[6] = Y[1]; byteV0[7] = Y[0];

byteV0[8] = Y[15]; byteV0[9] = Y[14]; byteV0[10] = Y[13]; byteV0[11] = Y[12]; byteV0[12] = Y[11]; byteV0[13] = Y[10]; byteV0[14] = Y[9]; byteV0[15] = Y[8];

//

unsigned char BIT = 0x80;

unsigned char i;

unsigned char tst;


for (i = 0; i < 16; i++) {


for (BIT = 0x80; BIT > 0; BIT = BIT >> 1) {


if (X[i] & BIT) { Z0[0] = Z0[0] ^ V0[0]; Z0[1] = Z0[1] ^ V0[1]; }

tst = 0;

if (V0[1] & 0x01) { tst = 1; }

/////

if (V0[0] & 0x01) { V0[0] = V0[0] >> 1; V0[1] = V0[1] >> 1; V0[1] = V0[1] | 0x8000000000000000; }

else { V0[0] = V0[0] >> 1; V0[1] = V0[1] >> 1; }

////  deslocando V0 >> 1

if (tst) { V0[0] = V0[0] ^ R[0]; V0[1] = V0[1] ^ R[1]; }


} // for BIT > 0


} // for i < 16


resul[0] = byteZ0[7]; resul[1] = byteZ0[6]; resul[2] = byteZ0[5]; resul[3] = byteZ0[4]; resul[4] = byteZ0[3]; resul[5] = byteZ0[2]; resul[6] = byteZ0[1]; resul[7] = byteZ0[0];

resul[8] = byteZ0[15]; resul[9] = byteZ0[14]; resul[10] = byteZ0[13]; resul[11] = byteZ0[12]; resul[12] = byteZ0[11]; resul[13] = byteZ0[10]; resul[14] = byteZ0[9]; resul[15] = byteZ0[8];



return 1;   // O bloco Z0 é o resultado da multiplicação dos blocos X e Y

} // mult2blocos()


