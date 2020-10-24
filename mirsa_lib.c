/// file: mirsa_lib.c
/// description:
/// @author Jesse Burdick-Pless jb4411

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "mirsa_lib.h"

bool mr_make_keys( uint64_t p, uint64_t q, const char * user ) {
	unsigned long int n = p * q;
	unsigned long int phi = (p - 1) * (q - 1);
	
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
	
		/*printf("Bézout coefficients: (%ld, %ld)\n", old_s, old_t);
		printf("greatest common divisor: %ld\n", old_r);
		printf("quotients by the gcd: (%ld, %ld)\n\n", t, s);*/
	}
	
	if( !done ) {
		fprintf( stderr, "error: mr_make_keys: no keyset for <%lu, %lu>.\n", p, q );
		exit( EXIT_FAILURE );
	} else {
		printf("Public key = (e, n) = (%d, %ld)\n", e, n);
		printf("Private key = (d, n) = (%ld, %ld)\n", d, n);
	}

	return true;
}
