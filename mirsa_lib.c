/// file: mirsa_lib.c
/// description: The implementations for the miniature RSA library, mirsa_lib.
/// @author Jesse Burdick-Pless jb4411

#include "mirsa_lib.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <math.h>

/// Used to indicate verbose mode.

static bool verbose = 0;

/// Set a flag to print diagnostic information.

bool mr_verbose( bool value ) {
	bool old = verbose;
	verbose = value;
	return old;
}

/// Make public and private key values and key files.

bool mr_make_keys( uint64_t p, uint64_t q, const char * user ) {
	uint64_t n = p * q;
	uint64_t phi = (p - 1) * (q - 1);

	if( verbose ) {
		printf("Prime p = %ld\n", p);
		printf("Prime q = %ld\n", q);
		printf("Nonce = %ld\n", n);
		printf("Phi = %ld\n", phi);
	}

	int e = 2;
	uint64_t d = 0;
	bool done = 0;

	uint64_t tmp = 0, quotient = 0;
	uint64_t old_r = e, r = phi;
	uint64_t old_s = 1, s = 0;
       	long int old_t = 0;
       	long int t = 1;

	while( e < 9 && !done ) {
		e++;

		// compute multiplicative inverse
		tmp = 0, quotient = 0, old_r = e, r = phi, old_s = 1, s = 0, old_t = 0, t = 1; 
		while( r ) {
			quotient = old_r / r;
			tmp = r;
			r = old_r - quotient * tmp;
			old_r = tmp;

			tmp = s;
			s = old_s - quotient * tmp;
			old_s = tmp;

			tmp = t;
			t = old_t - quotient * tmp;
			old_t = tmp;
		}

		d = phi - abs(old_s);
		if( old_r == 1 ) {
			if( !(((e * d) - 1) % phi) ) {
				done = 1;
			}
		}

	}
	if( verbose) {
		printf("\nBézout coefficients: (%ld, %ld)\n", old_s, old_t);
		printf("greatest common divisor: %ld\n", old_r);
		printf("quotients by the gcd: (%ld, %ld)\n\n", t, s);
	}

	if( !done ) {
		fprintf( stderr, "error: mr_make_keys: failed to generate keyset.\n" );
		fprintf( stderr, "error: mr_make_keys: no keyset for <%lu, %lu>.\n", p, q );
		exit( EXIT_FAILURE );
	}
	if( verbose ) {
		printf("Public key = (e, n) = (%d, %ld)\n", e, n);
		printf("Private key = (d, n) = (%ld, %ld)\n\n", d, n);
	}

	// make keys
	key_t pvt_key = {d, n};
	key_t pub_key = {e, n};

	char* pvt_name = malloc(strlen(user) + 5);
	assert(pvt_name != NULL);
	strcpy(pvt_name, user);
	strcat(pvt_name, ".pvt");
	char* pub_name = malloc(strlen(user) + 5);
	assert(pub_name != NULL);
	strcpy(pub_name, user);
	strcat(pub_name, ".pub");

	if( verbose ) {
		printf("Writing private key file: '%s'\n", pvt_name);
	}
	FILE *pvt;
	pvt = fopen( pvt_name, "w" );
	assert(pvt != NULL);
	// write private key to file
	fwrite(&pvt_key, sizeof(key_t), 1, pvt);
	assert(fwrite != NULL);
	fclose( pvt );

	if( verbose ) {
		printf("Writing public key file: '%s'\n", pub_name);
	}
	FILE *pub;
	pub = fopen( pub_name, "w" );
	assert(pub != NULL);
	// write public key to file
	fwrite(&pub_key, sizeof(key_t), 1, pub);
	assert(fwrite != NULL);
	fclose( pub );

	free(pvt_name);
	free(pub_name);

	if( verbose ) {
		printf("\nFinished, exiting...\n");
	}
	return true;
}

/// Reads a keypair from the specified file.

key_t * mr_read_keyfile( const char * file_name ) {
	if( verbose ) {
		printf("\nOpening: '%s'\n", file_name);
	}
	FILE *fp;
	fp = fopen( file_name, "r" );
	if( fp == NULL ) {
		fprintf( stderr, "error: mr_read_keyfile: '%s': %s\n", file_name, strerror(errno) ); 
		fprintf( stderr, "error: mr_read_keyfile: invalid file: '%s'\n", file_name );
		exit( EXIT_FAILURE );
	}
	
	key_t *key;
	key = malloc(sizeof(key_t));
	assert(key != NULL);

	fread(key, sizeof(key_t), 1, fp);
	if( key == NULL ) {
		fprintf( stderr, "error: mr_read_keyfile: '%s': %s\n", file_name, strerror(errno) );	
		fprintf( stderr, "error: mr_read_keyfile: '%s': read error\n", file_name );
		fclose( fp );
		exit( EXIT_FAILURE );
	}
	fclose( fp );

	if( verbose ) {
		printf("Key: %ld\n", key->key);
		printf("Nonce: %ld\n", key->nonce);
	}

	return key;
}

/// Uses pubkey to encrypt the message encoded in p.

uint64_t mr_encrypt( uint64_t p, const key_t * pubkey) {
	if( verbose ) {
                printf("Encoded text = %lu\n", p);
        }

	if( p >= pubkey->nonce ) {
		fprintf( stderr, "error: mr_encrypt: code overflow.\n" );
		fprintf( stderr, "error: mr_encrypt: limit exceeded by code value: %lu.\n", p );
		exit( EXIT_FAILURE );
	}
	
	uint64_t e = pubkey->key;
	uint64_t n = pubkey->nonce;
	uint64_t c = 1;
	uint64_t power = e;
	uint64_t step = 1;
	uint64_t num = 1;
	uint64_t *array;

	// encryption math
	if( power > 0 ) {
		array = calloc(floor(log2(power))+1, sizeof(uint64_t));
		assert(array != NULL);
		int i = 1;
		num = p % n;
		step = 1;
		array[0] = num;
		while( (step * 2) <= power ) {
			num = (num * num) % n;
			step *= 2;
			array[i] = num;
			i++;
		}

		uint64_t size = 0;
		while( power ) {
			size = floor(log2(power));
			c = (c * array[(int) size]) % n;
			power -= (uint64_t) pow(2, size);
		}
		free(array);
	}
	
	if( verbose ) {
		printf("Cipher text = %lu\n", c);
	}

	return c;
}

/// Uses pvtkey to decrypt the ciphertext c.

uint64_t mr_decrypt( uint64_t c, const key_t * pvtkey) { 
	if( verbose ) {
		printf("Cipher text = %lu\n", c);
	}

	if( c >= pvtkey->nonce ) {
		fprintf( stderr, "error: mr_decrypt: cipher overflow.\n" );
		exit( EXIT_FAILURE );
	}

	uint64_t d = pvtkey->key;
	uint64_t n = pvtkey->nonce;
	uint64_t p = 1;
	uint64_t power = d;
	uint64_t step = 1;
	uint64_t num = 1;
	uint64_t *array;

	array = calloc(floor(log2(power))+1, sizeof(uint64_t));
	assert(array != NULL);
	num = c % n;
	array[0] = num;
	int i = 1;
	while( (step * 2) <= power ) {
		num = (num * num) % n;
		step *= 2;
		array[i] = num;
		i++;
	}
	
	uint64_t size = 0;
	while( power ) {
		size = floor(log2(power));
		p = (p * array[(int) size]) % n;
		power -= (uint64_t) pow(2, size);
	}
		
	if( verbose ) {
		printf("Decrypted code = %lu\n", p);
	}

	free(array);	
	return p;
}

/// Converts the string st into an unsigned long code.

uint64_t mr_encode( const char * st) {
	int len = strlen(st);
	if( verbose ) {
		printf("message <%s>:\t", st);
		printf("len%d OK: ", len);
		if(len > 4) {
			printf("FALSE\n");
		} else {
			printf("TRUE\t");
		}
	}
	if(len > 4) {
		fprintf( stderr, "error: mr_encode: could not convert '%s'.\n", st);
		exit( EXIT_FAILURE );
	}
	int val_ok = 1;
	char hex[9];
	char tmp[4];
	char *rst;
	int i = 0, j = 0;
	while(st[i]) {
		sprintf(tmp, "%x", (int) st[i]);
		if(strtol(tmp, &rst, 16) < strtol("10", &rst, 16)) {
			hex[j++] = '0';
                        hex[j++] = tmp[0];
		} else {
			hex[j++] = tmp[0];
			hex[j++] = tmp[1];
		}
		i++;
		if(strtol(tmp, &rst, 16) > strtol("FF", &rst, 16)) {
			val_ok = 0;
		}
	}
	if( verbose ) {
		printf("valOK: ");
		if(val_ok) {
			printf("TRUE\t");
		} else {
			printf("FALSE\n");
		}
	}
	while(j < 9) {
		hex[j] = '0';
		j++;
	}
	hex[8] = '\0';
	uint64_t result = strtol(hex, &rst, 16);
	if(!val_ok) {
		fprintf( stderr, "error: mr_encode: could not convert '%s'.\n", st);
		exit( EXIT_FAILURE );
	}
	if( verbose ) {
		printf("code: <%lu> 0x%s\n", result, hex);
	}

	return result;
}

/// Converts an unsigned code into a string.

char * mr_decode( uint64_t code) {
	double bits = 0;
	bits = log2(code); 
	bits = ceil(bits);
	bits = bits/8;
	int size = ceil(bits);
	
	if( verbose ) {
		printf("Message size (bytes): %d\n", size);
	}

	if( size > 4) {
		fprintf( stderr, "error: mr_decode: size overflow on '%lu'.\n", code );
		exit( EXIT_FAILURE );
	} else if( size < 0 ) {
		fprintf( stderr, "error: uncomputable array length: %lu.\n", code );
		exit( EXIT_FAILURE );
	}

	char *str = calloc(size + 1, sizeof(char));
	assert(str != NULL);

	uint64_t bitmask = 255;
	int i = 0;
	while(i < size) {
		str[i] = (char) ((code >> (8 * i)) & bitmask);
		i++;
	}

	if( verbose ) {
		printf("Reversed string: %s\n", str);
	}

	char *result = calloc(size + 1, sizeof(char));
	assert(result != NULL);
	int j = 0, k = size-1;
	while( j < size ) {
		result[k--] = str[j++];
	}

	if( verbose ) {
		printf("Result string: %s\n", result);
	}
	free(str);
	return result;
}
