/// file: mirsa_lib.c
/// description:
/// @author Jesse Burdick-Pless jb4411

#include <stdio.h>
#include <stdbool.h>
#include "mirsa_lib.h"

bool mr_make_keys( uint64_t p, uint64_t q, const char * user ) {
	unsigned long int n = p * q;
	unsigned long int phi = (p - 1) * (q - 1);

	int e = 2;
	unsigned long int k = 1;	
	unsigned long int d = 0;
	unsigned long int res = 0;
	bool done = 0;

	while( e <= 9 && !done ) {
		e++;
		while( !__builtin_umull_overflow (k, phi, &res) ) {
			if( (1 + (k * phi)) % e) {
				k++;
			} else {
				d = (1 + (k * phi)) / e;
				done = 1;
				break;
			}
		}
	}

	printf("Public key = (e, n) = (%d, %ld)\n", e, n);
	printf("Private key = (d, n) = (%ld, %ld)\n", d, n);
	
	return true;
}
