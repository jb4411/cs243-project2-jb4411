/// file: mirsa_genkeys.c
/// description: a program that generates public and private key files.
/// @author Jesse Burdick-Pless jb4411

#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <time.h>
#include <unistd.h>
#include "mirsa_lib.h"

/// Output a usage message to stderr, standard error.
/// Used when the program has incomplete command line input.

void usage() {
	fprintf( stderr, "\nusage: mirsa_genkeys [-hv] [-k key] [-s seed]\n" );
}

/// The main program takes command line input, processes argument flags, picks
/// two random prime numbers using the time or the optinally provieded seed as 
/// the seed for rand(). The names of the files is the name of the current user 
/// or the optionally provided name. mr_make_keys is then called to generate the 
/// public and prives keys along with their respective files.
///
/// @param argc integer value for the number of command line input
///        values
/// @param argv array of C string values, the command line arguments
/// @return 0 to tell the OS that the process ran successfully, OR
///         return 1 to tell the OS there were not enough command line
///         input values


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
				mr_verbose(1);
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
					fprintf( stderr, "error: missing key file name.\n" ); 
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
               	fprintf( stderr, "error: missing primes file.\n" );
		exit( EXIT_FAILURE );
	}

	int num_primes = 0;	
	fscanf(fp, "%d", &num_primes);
	unsigned long int *primes = malloc(sizeof(unsigned long int) * num_primes);	
	
	int i = 0;
	while( fscanf(fp, "%lu", &primes[i]) && i < num_primes ) {
		i++;
	}
	fclose( fp );	
	if( i < num_primes ) {
		fprintf( stderr, "error: primes file has invalid count.\n" );
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
		fprintf( stderr, "error: mr_make_keys: overflow. no keyset for <%lu, %lu>.\n", p, q );
		exit( EXIT_FAILURE );
	}
	
	if( name == NULL ) {
		name = getlogin();
	}

	mr_make_keys(p, q, name);
	
	exit( EXIT_SUCCESS );	
}
