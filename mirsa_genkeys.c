/// file: mirsa_genkeys.c
/// description: 
/// @author Jesse Burdick-Pless jb4411

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include "mirsa_lib.h"

void usage() {
	fprintf( stderr, "usage: mirsa_genkeys [-hv] [-k key] [-s seed]\n" );
}

int main( int argc, char * argv[] ) {
	int opt;
	char *name;
	int seed = 0;
	int fall = 0;
	while ( (opt = getopt( argc, argv, "hvs:lk:x") ) != -1 ) {
		switch( opt ) {
			case 'h':
				usage();
				exit( EXIT_SUCCESS );
				break;
			case 'v':
				//mr_verbose();
				break;
			case 's':
				seed = (int) strtol( optarg, NULL, 10 );
				if( seed > 0 ) {
					break;
				}
				if( optarg != NULL ) {
					fprintf( stderr, "error: invalid seed value '%s'.\n", optarg );
					usage();
					exit( EXIT_FAILURE );
				}
				fall = 1;
				/* fall through */
			case 'k':
				if( !fall ) {
					name = optarg;
					if( name != NULL ) {
						break;
					}
				}
				/* fall through */
			case '?':
				usage();
				exit( EXIT_FAILURE );
			default:
				fprintf( stderr, "error: unknown flag" ); 
				exit( EXIT_FAILURE );
		}
	}
	if(optind < argc) {
		fprintf( stderr, "error: extra argument: '%s'.\n", argv[optind] );
		usage();
		exit( EXIT_FAILURE );
	}
	
	// choose primes and generate keys	
	
	unsigned long int p = 0, q = 0;
	mr_make_keys(p, q, "uwu");

}
