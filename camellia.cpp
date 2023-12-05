#include <iostream>
#include <string>
#include <algorithm>
#include <fstream>
#include <iomanip>

#include "camellia.h"
#include "ttt.h"

using namespace std;

#define MASK8 0xFF
#define MASK32 0xFFFFFFFF

uint64_t F(uint64_t, uint64_t);

struct key_init{
	int len_key;
	int len_bit;
	string key;
};

SubKey keyScheduling(key_init ki){
// KL 128 bit number is split into 64bit KL1 (high bits) and 64bit KL2 (low bits)
// KR 128 bit number is split into KR1 (high bits) and KR2 (low bits), but only used for 192- and 256-bit keys
// Same with KA and KB
	uint64_t KL1, KL2, KR1, KR2;
	uint64_t KA1, KA2, KB1, KB2;
	uint64_t D1, D2;
	SubKey sk;
	
	switch (ki.len_key){
		case 16:
			{
				sk = init_SubKey(18, 4);
				KL1 = keyToUint64(ki.key, 0);
				KL2 = keyToUint64(ki.key, 8);
				KR1 = KR2 = 0;
				break;
			}
			
		case 24:
			{
				sk = init_SubKey(24, 6);
				KL1 = keyToUint64(ki.key, 0);
				KL2 = keyToUint64(ki.key, 8);
				KR1 = keyToUint64(ki.key, 16);
				KR2 = ~KR1;
				break;
			}

		case 32:
			{
				sk = init_SubKey(24, 6);
				KL1 = keyToUint64(ki.key, 0);
                        	KL2 = keyToUint64(ki.key, 8);
                        	KR1 = keyToUint64(ki.key, 16);
				KR2 = keyToUint64(ki.key, 24);
				break;
			}

		default:
			break;
	}

	D1 = KL1 ^ KR1;
	D2 = KL2 ^ KR2;
	D2 = D2 ^ F(D1, Sigma[0]);
	D1 = D1 ^ F(D2, Sigma[1]);
	D1 = D1 ^ KL1;
	D2 = D2 ^ KL2;
	D2 = D2 ^ F(D1, Sigma[2]);
	D1 = D1 ^ F(D2, Sigma[3]);
	KA1 = D1;
	KA2 = D2;

	if (ki.len_key > 16){
		D1 = (KA1 ^ KR1);
		D2 = (KA2 ^ KR2);
		D2 = D2 ^ F(D1, Sigma[4]);
		D1 = D1 ^ F(D2, Sigma[5]);
		KB1 = D1;
		KB2 = D2;
	}

	if (ki.len_key == 16){
		sk.kw[0] = KL1; //kw1 = (KL <<<   0) >> 64
		sk.kw[1] = KL2; //kw2 = (KL <<<   0) & MASK64
		sk.k[0] = KA1; //k1  = (KA <<<   0) >> 64
		sk.k[1] = KA2; //k2  = (KA <<<   0) & MASK64
		Roll128(KL1, KL2, 15); //rotate 128bit left 15  KL
		sk.k[2] = KL1;
		sk.k[3] = KL2; 
		Roll128(KA1, KA2, 15); //rotate 128bit left 15  KA
		sk.k[4] = KA1;
		sk.k[5] = KA2;
		Roll128(KA1, KA2, 15); //rotate another 15 left (30 total) KA
		sk.ke[0] = KA1;
		sk.ke[1] = KA2;
		Roll128(KL1, KL2, 30); //rotate another 30 left (45 total) KL
		sk.k[6] = KL1;
		sk.k[7] = KL2;
		Roll128(KA1, KA2, 15); //rotate another 15 left (45 total) KA
		sk.k[8] = KA1;
		Roll128(KL1, KL2, 15); //rotate another 15 left (60 total) KL
		sk.k[9] = KL2;
		Roll128(KA1, KA2, 15); //rotate another 15 left (60 total) KA
		sk.k[10] = KA1;
		sk.k[11] = KA2;
		Roll128(KL1, KL2, 17); //rotate another 17 left (77 total) KL
		sk.ke[2] = KL1;
		sk.ke[3] = KL2;
		Roll128(KL1, KL2, 17); //rotate another 17 left (94 total) KL
		sk.k[12] = KL1;
		sk.k[13] = KL2;
		Roll128(KA1, KA2, 34); //rotate another 34 left (94 total) KA
		sk.k[14] = KA1;
		sk.k[15] = KA2;
		Roll128(KL1, KL2, 17); //rotate another 17 left (111 total) KL
		sk.k[16] = KL1;
		sk.k[17] = KL2;
		Roll128(KA1, KA2, 17); //rotate another 17 left (111 total) KA
		sk.kw[2] = KA1;
		sk.kw[3] = KA2;
	}

	else{
		sk.kw[0] = KL1;
		sk.kw[1] = KL2;
		sk.k[0] = KB1;
		sk.k[1] = KB2;
		Roll128(KR1, KR2, 15); ////rotate another 15 left (15 total) KR
		sk.k[2] = KR1;
		sk.k[3] = KR2;
		Roll128(KA1, KA2, 15); //rotate another 15 left (15 total) KA
		sk.k[4] = KA1;
		sk.k[5] = KA2;
		Roll128(KR1, KR2, 15); //rotate another 15 left (30 total) KR
		sk.ke[0] = KR1;
		sk.ke[1] = KR2;
		Roll128(KB1, KB2, 30); //rotate another 30 left (30 total) KB
		sk.k[6] = KB1;
		sk.k[7] = KB2;
		Roll128(KL1, KL2, 45); //rotate another 45 left (45 total) KL
		sk.k[8] = KL1;
		sk.k[9] = KL2;
		Roll128(KA1, KA2, 30); //rotate another 30 left (45 total) KA
		sk.k[10] = KA1;
		sk.k[11] = KA2;
		Roll128(KL1, KL2, 15); //rotate another 15 left (60 total) KL
		sk.ke[2] = KL1;
		sk.ke[3] = KL2;
		Roll128(KR1, KR2, 30); //rotate another 30 left (60 total) KR
		sk.k[12] = KR1;
		sk.k[13] = KR2;
		Roll128(KB1, KB2, 30); //rotate another 30 left (60 total) KB
		sk.k[14] = KB1;
		sk.k[15] = KB2;
		Roll128(KL1, KL2, 17); //rotate another 17 left (77 total) KL
		sk.k[16] = KL1;
		sk.k[17] = KL2;
		Roll128(KA1, KA2, 32); //rotate another 32 left (77 total) KA
		sk.ke[4] = KA1;
		sk.ke[5] = KA2;
		Roll128(KR1, KR2, 34); //rotate another 34 left (94 total) KR
		sk.k[18] = KR1;
		sk.k[19] = KR2;
		Roll128(KA1, KA2, 17); //rotate another 17 left (94 total) KA
		sk.k[20] = KA1;
		sk.k[21] = KA2;
		Roll128(KL1, KL2, 34); //rotate another 34 left (111 total) KL
		sk.k[22] = KL1;
		sk.k[23] = KL2;
		Roll128(KB1, KB2, 51); //rotate another 51 left (111 total) KB
		sk.kw[2] = KB1;
		sk.kw[3] = KB2;
	}
	
	return sk;
}

uint64_t F(uint64_t F_IN, uint64_t KE){
	uint64_t F_OUT;
	uint64_t x;
	uint8_t t1, t2, t3, t4, t5, t6, t7, t8;
	uint8_t y1, y2, y3, y4, y5, y6, y7, y8;

	x = F_IN ^ KE;
	t1 = (uint8_t)(x >> 56);
	t2 = (uint8_t)((x >> 48) & MASK8);
	t3 = (uint8_t)((x >> 40) & MASK8);
	t4 = (uint8_t)((x >> 32) & MASK8);
	t5 = (uint8_t)((x >> 24) & MASK8);
	t6 = (uint8_t)((x >> 16) & MASK8);
	t7 = (uint8_t)((x >> 8) & MASK8);
	t8 = (uint8_t)(x & MASK8);

	t1 = SBOX1[t1];
	t2 = Roll8(SBOX1[t2], 1); //SBOX2[x] = SBOX1[x] <<< 1
	t3 = Roll8(SBOX1[t3], 7); //SBOX3[x] = SBOX1[x] <<< 7
	t4 = SBOX1[Roll8(t4, 1)]; //SBOX4[x] = SBOX1[x <<< 1]
	t5 = Roll8(SBOX1[t5], 1);
	t6 = Roll8(SBOX1[t6], 7);
	t7 = SBOX1[Roll8(t7, 1)];
	t8 = SBOX1[t8];

	y1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8;
	y2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8;
	y3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8;
	y4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7;
	y5 = t1 ^ t2 ^ t6 ^ t7 ^ t8;
	y6 = t2 ^ t3 ^ t5 ^ t7 ^ t8;

	y7 = t3 ^ t4 ^ t5 ^ t6 ^ t8;
	y8 = t1 ^ t4 ^ t5 ^ t6 ^ t7;

	F_OUT = ((uint64_t)y1 << 56) + ((uint64_t)y2 << 48) + ((uint64_t)y3 << 40) + ((uint64_t)y4 << 32) + ((uint64_t)y5 << 24) + ((uint64_t)y6 << 16) + ((uint64_t)y7 << 8) + (uint64_t)y8;
	return F_OUT;
}

uint64_t FL(uint64_t FL_IN, uint64_t KE){
	uint64_t FL_OUT;
	uint32_t x1, x2, k1, k2;

	x1 = (uint32_t)(FL_IN >> 32);
	x2 = (uint32_t)(FL_IN & MASK32);
	k1 = (uint32_t)(KE >> 32);
	k2 = (uint32_t)(KE & MASK32);
	x2 = x2 ^ Roll32((uint32_t)(x1 & k1), 1);
	x1 = x1 ^ (x2 | k2);
	FL_OUT = ((uint64_t)x1 << 32) | x2;

	return FL_OUT;
}

uint64_t FLINV(uint64_t FLINV_IN, uint64_t KE){
	uint64_t FLINV_OUT;
	uint32_t y1, y2, k1, k2;

	y1 = (uint32_t)(FLINV_IN >> 32);
	y2 = (uint32_t)(FLINV_IN & MASK32);
	k1 = (uint32_t)(KE >> 32);
	k2 = (uint32_t)(KE & MASK32);
	y1 = y1 ^ (y2 | k2);
	y2 = y2 ^ Roll32((uint32_t)(y1 & k1), 1);
	FLINV_OUT = ((uint64_t)y1 << 32) | y2;

	return FLINV_OUT;
}

uint8_t *ProcBlock(uint8_t *input, SubKey sk, key_init ki){
	uint64_t D1, D2;
	D1 = DataToUint64(input, 0);
	D2 = DataToUint64(input, 8);

	D1 = D1 ^ sk.kw[0];	// Prewhitening
	D2 = D2 ^ sk.kw[1];
	D2 = D2 ^ F(D1, sk.k[0]);	// Round 1
	D1 = D1 ^ F(D2, sk.k[1]);	// Round 2
	D2 = D2 ^ F(D1, sk.k[2]);	// Round 3
	D1 = D1 ^ F(D2, sk.k[3]);	// Round 4
	D2 = D2 ^ F(D1, sk.k[4]);	// Round 5 
	D1 = D1 ^ F(D2, sk.k[5]);	// Round 6

	D1 = FL(D1, sk.ke[0]);	// FL
	D2 = FLINV(D2, sk.ke[1]);	//FLINV
	D2 = D2 ^ F(D1, sk.k[6]);	// Round 7
	D1 = D1 ^ F(D2, sk.k[7]);	// Round 8
	D2 = D2 ^ F(D1, sk.k[8]);	// Round 9
	D1 = D1 ^ F(D2, sk.k[9]);	// Round 10
	D2 = D2 ^ F(D1, sk.k[10]);	// Round 11
	D1 = D1 ^ F(D2, sk.k[11]);	// Round 12

	D1 = FL(D1, sk.ke[2]);	//FL
	D2 = FLINV(D2, sk.ke[3]);	//FLINV
	D2 = D2 ^ F(D1, sk.k[12]);	// Round 13
	D1 = D1 ^ F(D2, sk.k[13]);	// Round 14
	D2 = D2 ^ F(D1, sk.k[14]);	// Round 15
	D1 = D1 ^ F(D2, sk.k[15]);	// Round 16
	D2 = D2 ^ F(D1, sk.k[16]);	// Round 17
	D1 = D1 ^ F(D2, sk.k[17]);	// Round 18

	if (ki.len_key > 16){
		D1 = FL(D1, sk.ke[4]);	//FL
		D2 = FLINV(D2, sk.ke[5]);	//FLINV
		D2 = D2 ^ F(D1, sk.k[18]);	// Round 19
		D1 = D1 ^ F(D2, sk.k[19]);	// Round 20
		D2 = D2 ^ F(D1, sk.k[20]);	// Round 21
		D1 = D1 ^ F(D2, sk.k[21]);	// Round 22
		D2 = D2 ^ F(D1, sk.k[22]);	// Round 23
		D1 = D1 ^ F(D2, sk.k[23]);	// Round 24
	}

	D2 = D2 ^ sk.kw[2];	// Postwhitening
	D1 = D1 ^ sk.kw[3];

	uint8_t *res = new uint8_t[16]{};
	Uint64ToMass(res, D2, 0);
	Uint64ToMass(res, D1, 8);
	
	return res;
}

SubKey DecryptionMode(SubKey sk, key_init ki){
	swap(sk.kw[0], sk.kw[2]);
        swap(sk.kw[1], sk.kw[3]);

        if (ki.len_key > 16){
                reverse(sk.k, sk.k+24);
                reverse(sk.ke, sk.ke+6);
        }
        else {
                reverse(sk.k, sk.k+18);
                reverse(sk.ke, sk.ke+4);
        }
	return sk;	
}

int main(int argc, char* argv[]){
	
	key_init ki;
	uint8_t *mainProc = NULL;
	char mode;
	string filein, fileout;
	string msg1, msg2;

	cout << "Please select the mode:" << endl;
	cout << "1. Encryption mode" << endl;
	cout << "2. Decryptin mode" << endl;
	cout << "3. Exit" << endl;
	cin >> mode;

	//cout << "Please enter password: ";
	//cin >> ki.key;
	ki.key = "hellow_world_key";
//	ki.key = "0123456789abcdeffedcba9876543210";
	ki.len_key = ki.key.length();
	while (ki.len_key != 16 && ki.len_key != 24 && ki.len_key != 32){
		cout << "Key must 128-, 192-, or 256-bit (16, 24, or 32 bytes respectively)" << endl;
		cout << "Please enter password: ";
 	      	cin >> ki.key;
	       	ki.len_key = ki.key.length();
	};
	
	SubKey sk = keyScheduling(ki);
	
	switch(mode){
		case '1':
			{
				cout << "Enter filename for encryption: ";
				cin >> filein;
				cout << "Enter output filename: ";
				cin >> fileout;
				msg1 = "encrytion";
				msg2 = "The file is encrypted";
				break;
			}
		case '2':
			{
				sk = DecryptionMode(sk, ki);
				cout << "Enter filename for decryption: ";
                                cin >> filein;
				cout << "Enter output filename: ";
                                cin >> fileout;
				msg1 = "decryption";
				msg2 = "The file is decrypted";
				break;
			}
		default:
			return 0;
	}

	ifstream fin(filein, ios_base::in | ios_base::binary);
	if (fin.is_open()){
		cout << "------------" << endl;
		cout << "File for "<< msg1 << ": " << filein << endl;
		cout << "------------" << endl;
	}
	else {
		perror("File not found");
		return __LINE__;
	}

	ofstream fout(fileout, ios_base::app | ios_base::binary);
	if (fout.is_open()){
		cout << "------------" << endl;
                //cout << "File " << fileout << " created" << endl;
		cout << "------------" << endl;
        }
        else {
                perror("File not created");
                return __LINE__;
        }
	
	int size = 0;

	while (!fin.eof()){
		uint8_t buff[16]{};
                fin.read((char*)buff, 16);
		
                cout << buff;
		mainProc = ProcBlock(buff, sk, ki);
		fout << mainProc;
		size += strlen((char*)buff);

		delete [] mainProc;
	}

	cout << size << endl;	
	fin.close();
	fout.close();

/*
	uint8_t *dec;		
	cout << dataT << endl;
	int size = strlen(len);
	int count = 0;
	while(count < size){
		uint8_t *buffT = new uint8_t[16];
		int i = 0;
		for (; i < 16; i++) {
			if (dataT[i+count] == '\0') break;
			buffT[i] = dataT[i+count];}
		
		mainProc = ProcBlock(buffT, sk, ki);
		cout << mainProc << endl;
		sk = DecryptionMode(sk, ki);
		dec = ProcBlock(mainProc, sk, ki);
		cout << dec;
		count += i;
		delete [] buffT;
	}
	cout << endl;*/
	return 0;
}
