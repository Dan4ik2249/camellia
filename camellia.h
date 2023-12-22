#include <cstdint>
#include <cstring>

#define MASK8 0xFF

using namespace std;

uint64_t Sigma[] = {0xA09E667F3BCC908B, 0xB67AE8584CAA73B2, 0xC6EF372FE94F82BE, 0x54FF53A5F1D36F1C, 0x10E527FADE682D1D, 0xB05688C2B3E6C1FD};

struct SubKey{
	uint64_t *k;
	uint64_t *kw;
	uint64_t *ke;
};

SubKey init_SubKey(int a, int b){
	SubKey sk;
	sk.k = new uint64_t [a];
	sk.kw = new uint64_t [4];
	sk.ke = new uint64_t [b];
	return sk;
}

uint64_t keyToUint64(string arr, int count){
        uint64_t out = 0;
	int k = 7;
        for (int i = 0; i < 64; i+=8){
                out += ((uint64_t)arr[k+count] << i);
		k--;
        }
        return out;
}

uint64_t DataToUint64(uint8_t *arr, int count){
        uint64_t out = 0;
        int k = 7;
        for (int i = 0; i < 64; i+=8){
                out += ((uint64_t)arr[k+count] << i);
                k--;
        }
        return out;
}

void Uint64ToMass(uint8_t *res, uint64_t param, int i){
	res[7 + i] = (uint8_t)param & MASK8;
	param = param >> 8;
	res[6 + i] = (uint8_t)param & MASK8;
	param = param >> 8;
	res[5 + i] = (uint8_t)param & MASK8;
	param = param >> 8;
	res[4 + i] = (uint8_t)param & MASK8;
	param = param >> 8;
	res[3 + i] = (uint8_t)param & MASK8;
	param = param >> 8;
	res[2 + i] = (uint8_t)param & MASK8;
	param = param >> 8;
	res[1 + i] = (uint8_t)param & MASK8;
	param = param >> 8;
	res[i] = (uint8_t)param & MASK8;
}

//replace operation "<<<"
void Roll128(uint64_t& high, uint64_t& low, int offset){
	uint64_t dhigh = high, dlow = low;
	high = (uint64_t)(dhigh << offset) + (uint64_t)(dlow >> (64 - offset));
	low = (uint64_t)(dlow << offset) + (uint64_t)(dhigh >> (64 - offset));
}

uint32_t Roll32(uint32_t param, int offset){
	uint32_t res = param << offset;
	res = res | ((uint32_t)param >> (32 - offset));
	return res;
}

uint8_t Roll8(uint8_t u, int k){
        u = (u << k) | (u >> (8-k));
        return u;
}

uint8_t SBOX1[] = {112, 130, 44, 236, 179, 39, 192, 229, 228, 133, 87, 53, 234, 12, 174, 65, 
	35, 239, 107, 147, 69, 25, 165, 33, 237, 14, 79, 78, 29, 101, 146, 189, 
	134, 184, 175, 143, 124, 235, 31, 206, 62, 48, 220, 95, 94, 197, 11, 26, 
	166, 225, 57, 202, 213, 71, 93, 61, 217, 1, 90, 214, 81, 86, 108, 77, 
	139, 13, 154, 102, 251, 204, 176, 45, 116, 18, 43, 32, 240, 177, 132, 153, 
	223, 76, 203, 194, 52, 126, 118, 5, 109, 183, 169, 49, 209, 23, 4, 215, 
	20, 88, 58, 97, 222, 27, 17, 28, 50, 15, 156, 22, 83, 24, 242, 34, 
	254, 68, 207, 178, 195, 181, 122, 145, 36, 8, 232, 168, 96, 252, 105, 80, 
	170, 208, 160, 125, 161, 137, 98, 151, 84, 91, 30, 149, 224, 255, 100, 210, 
	16, 196, 0, 72, 163, 247, 117, 219, 138, 3, 230, 218, 9, 63, 221, 148, 
	135, 92, 131, 2, 205, 74, 144, 51, 115, 103, 246, 243, 157, 127, 191, 226, 
	82, 155, 216, 38, 200, 55, 198, 59, 129, 150, 111, 75, 19, 190, 99, 46, 
	233, 121, 167, 140, 159, 110, 188, 142, 41, 245, 249, 182, 47, 253, 180, 89, 
	120, 152, 6, 106, 231, 70, 113, 186, 212, 37, 171, 66, 136, 162, 141, 250, 
	114, 7, 185, 85, 248, 238, 172, 10, 54, 73, 42, 104, 60, 56, 241, 164, 
	64, 40, 211, 123, 187, 201, 67, 193, 21, 227, 173, 244, 119, 199, 128, 158};


