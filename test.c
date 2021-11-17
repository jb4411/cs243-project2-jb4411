#include "mirsa_lib.h"
#include <stdio.h>

void test_keys(void) {
	mr_verbose(1);
	mr_read_keyfile("jb4411.pvt");	
}

void test_encrypt(void) {
	key_t key0 = {0, 3763};
	key_t key1 = {1, 3763};
	key_t key2 = {2, 3763};
	key_t key3 = {3, 3763};
	key_t * key4 = mr_read_keyfile("jb4411.pub");
	uint64_t M = 1234;

	// e = 0
	uint64_t result0 = mr_encrypt(M, &key0);
        printf("e = 0: %lu\n", result0);
	// e= 1
	uint64_t result1 = mr_encrypt(M, &key1);
	printf("e = 1: %lu\n", result1);
	// e = 2
	uint64_t result2 = mr_encrypt(M, &key2);
	printf("e = 2: %lu\n", result2);
	// e = 3
	uint64_t result3 = mr_encrypt(M, &key3);
        printf("e = 3: %lu\n", result3);
	
	// test with real key
	uint64_t result4 = mr_encrypt(M, key4);
        printf("result: %lu\n", result4);
}

void test_decrypt(char *str) {
	/*key_t key1pub = {3, 3763};
	key_t key1pvt = {2427, 3763};
        uint64_t result1 = mr_decrypt(mr_encrypt(1234, &key1pub), &key1pvt);
        printf("expected: 1234 result: %lu\n\n", result1);
	*/	

	key_t * pub = mr_read_keyfile("test.pub");
	key_t * pvt = mr_read_keyfile("test.pvt");
	uint64_t encoded = mr_encode(str);
        uint64_t result2 = mr_decrypt(mr_encrypt(encoded, pub), pvt);
        printf("\nexpected: '%lu' result: '%lu'\n", encoded, result2);
	printf("expected: '%s' result: '%s'\n", str, mr_decode(result2));

}

void test_encode_decode(void) {
	char str1[2] = "2";
	char str2[4] = "sjc";
	char str3[5] = "Uf/;";
	mr_verbose(1);
	uint64_t s1 = mr_encode(str1);
	uint64_t s2 = mr_encode(str2);
	uint64_t s3 = mr_encode(str3);
	printf("\n");	
	
	printf("original value: <%s> decoded value: <%s>\n", str1, mr_decode(s1));
	printf("original value: <%s> decoded value: <%s>\n", str2, mr_decode(s2));
	printf("original value: <%s> decoded value: <%s>\n", str3, mr_decode(s3));
}

int main(void) {
	//test_encode_decode();
	//test_keys();
        //mr_verbose(1);
	//test_encrypt();
	test_decrypt(",");
	test_decrypt("plz");
	test_decrypt("69");
	test_decrypt("test");
        return 0;
}
