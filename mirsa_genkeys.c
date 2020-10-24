/// file: mirsa_genkeys.c
/// description: 
/// @author Jesse Burdick-Pless jb4411

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <time.h>
#include <unistd.h>
#include "mirsa_lib.h"

void usage() {
	fprintf( stderr, "usage: mirsa_genkeys [-hv] [-k key] [-s seed]\n" );
}

int main( int argc, char * argv[] ) {
	int opt;
	char *name;
	name = NULL;
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
	FILE *fp;
        fp = fopen( "Primes.txt", "r" );

        // check to be sure the open succeeded
        if( fp == NULL ) {
                // something went wrong - report it, and exit
                perror( "Primes.txt" );
                exit( EXIT_FAILURE );
	}

	int num_primes = 0;	
	fscanf(fp, "%d", &num_primes);
	unsigned long int *primes = malloc(sizeof(unsigned long int) * num_primes);	
	
	int i = 0;
	while( fscanf(fp, "%lu", &primes[i]) && i < num_primes ) {
		i++;
	}
	
	
	if( seed == 0 ) {
		seed = (unsigned) time(0);
	}
	srand((unsigned) seed);

	unsigned long int p = 0, q = 0, res = 0;
	int j = 0;
	bool success = 0;
	while( j < 3 ) {
		p = primes[rand() % num_primes];
		q = primes[rand() % num_primes];
		if(  __builtin_umull_overflow(p, q, &res) ) {
			j++;
		} else {
			success = 1;
			break;
		}
	}
	free(primes);

	if( !success ) {
		fprintf( stderr, "error: mr_make_keys: failed to generate keyset.\n" );
		exit( EXIT_FAILURE );
	}
	
	if( name == NULL ) {
		name = getlogin();
	}
	mr_make_keys(p, q, name);
	

}
