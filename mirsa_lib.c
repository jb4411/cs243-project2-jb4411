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
	unsigned long int n = p * q;
	unsigned long int phi = (p - 1) * (q - 1);

	if( verbose ) {
		printf("Prime p = %ld\n", p);
		printf("Prime q = %ld\n", q);
		printf("Nonce = %ld\n", n);
		printf("Phi = %ld\n", phi);
	}

	int e = 2;
	unsigned long int d = 0;
	bool done = 0;

	unsigned long int tmp = 0, quotient = 0;
	unsigned long int old_r = e, r = phi;
	unsigned long int old_s = 1, s = 0, old_t = 0, t = 1;

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

		if( old_r == 1 ) {
			done = 1;
		}
		d = phi - abs(old_s);

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
