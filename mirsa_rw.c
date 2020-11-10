/// file: mirsa_lib.c
/// description: TODO
/// @author Jesse Burdick-Pless jb4411

#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include "mirsa_lib.h"

/// Output a usage message to stderr, standard error.
/// Used when the program has incomplete command line input.

void usage() {
	fprintf( stderr, "usage:\n" );
	fprintf( stderr, "Reader use: mirsa_rw [-vh] [-k keyname] -r cipherfile [plainfile]\n" );
	fprintf( stderr, "\tIf plainfile is not provided, then reader output is to stdout.\n" );
	fprintf( stderr, "Writer use: mirsa_rw [-vh] [-k keyname] -w cipherfile [plainfile]\n" );
	fprintf( stderr, "\tIf plainfile is not provided, then writer input is from stdin.\n" );
	fprintf( stderr, "The -v flag turns on verbose output.\n" );
}

int main( int argc, char * argv[] ) {
        if( argc < 2 ) {
		fprintf( stderr, "error: file error\n" );
		fprintf( stderr, "error: missing file argument\n" );
		usage();
		exit( EXIT_FAILURE );
	}
	int opt;
	char mode = '\0';
	char *keyname = NULL;
        while ( (opt = getopt( argc, argv, "hvk:xr:zw:a") ) != -1 ) {
                switch( opt ) {
			case 'h':
				fprintf( stderr, "\n" );
				usage();
				exit( EXIT_SUCCESS );
				break;
			case 'v':
				mr_verbose(1);
				break;
			case 'k':
				keyname = optarg;
				if( keyname != NULL ) {
					break;
				}
				fprintf( stderr, "error: file error\n" );
				fprintf( stderr, "error: missing key file name\n" );
				usage();
				exit( EXIT_FAILURE );
				break;
			case 'r':
				mode = 'r';
				if( optarg == NULL ) {
					fprintf( stderr, "error: file error\n" );
					fprintf( stderr, "error: missing cipherfile\n" );
					usage();
					exit( EXIT_FAILURE );
				}
				break;
			case 'w':
				mode = 'w';
				break;
			case '?':
				fprintf( stderr, "error: unknown flag" );
				usage();
				exit( EXIT_FAILURE );
			default:
				fprintf( stderr, "error: unknown flag" );
				usage();
				exit( EXIT_FAILURE );
		}
	}
	key_t *key;
	if( keyname == NULL ) {
		char *username = getlogin();
		char ext[5] = ".pvt";
		username = (char *) realloc(username, (strlen(username) + 5));
		strncat(username, ext, 5);
		key = mr_read_keyfile(username);
		free(username);
		username = NULL;
	} else {
		key = mr_read_keyfile(keyname);
	}
	FILE *cipher_file;
	FILE *plain_file;
	int has_plainfile = 0;
	if( (optind + 1) < argc ) {
		has_plainfile = 1;
		if( mode == 'r' ) {
			plain_file = fopen(argv[optind+1], "w");
			if( plain_file == NULL ) {
				fprintf( stderr, "error: miRSA could not open '%s' for writing.\n", argv[optind+1] );
				exit( EXIT_FAILURE );
			}
		} else {
			plain_file = fopen(argv[optind+1], "r");
			if( plain_file == NULL ) {
				fprintf( stderr, "error: miRSA could not open '%s'.\n", argv[optind+1] );
				exit( EXIT_FAILURE );
			}
		}
	}
	char *text = NULL;
	if( mode == '\0' ) {
		usage();
		exit( EXIT_FAILURE );
	} else if( mode == 'r' ) {
		cipher_file = fopen(argv[optind], "r");
		if( cipher_file == NULL ) {
			fprintf( stderr, "error: miRSA could not open '%s'.\n", argv[optind] );
		}
		uint64_t decrypted = 0;
		uint64_t cipher_text = 0;
		while( fread(&cipher_text, sizeof(uint64_t), 1, cipher_file) ) {
			decrypted = mr_decrypt(cipher_text, key);
			text = mr_decode(decrypted);
			if( has_plainfile ) {
				fwrite(text, sizeof(char), strlen(text), plain_file);
			} else {
				printf("%s", text);
			}
		}
		if( !has_plainfile ) {
			printf("\n");
		} else {
			fclose(plain_file);
		}
	} else if( mode == 'w' ) {
		FILE *plain_text;
		if( has_plainfile ) {
			plain_text = plain_file;
		} else {
			plain_text = stdin;
		}
		cipher_file = fopen(argv[optind], "w");
		if( cipher_file == NULL ) {
			fprintf( stderr, "error: miRSA could not open '%s' for writing.\n", argv[optind] );
		}

		uint64_t encoded = 0;
		uint64_t cipher_text = 0;
		text = calloc(1024, sizeof(char));
		size_t bytes_read = 0;
		char *chunk = calloc(5, sizeof(char));
		while( (bytes_read = fread(text, sizeof(char), 1024, plain_text)) ) {
			size_t i = 0;
			while( i < bytes_read ) {
				strncpy(chunk, &(text[i]), 4);
				encoded = mr_encode(chunk);
				cipher_text = mr_encrypt(encoded, key);
				if(fwrite(&cipher_text, sizeof(uint64_t), 1, cipher_file) < 1) {
					fprintf( stderr, "error: miRSA fwrite failed.\n" );
					exit( EXIT_FAILURE );
				}
				i += 4;
			}

			if(bytes_read < 1024) {
				break;
			}
		}
		free(chunk);
		chunk = NULL;
		if( has_plainfile ) {
			fclose(plain_file);
		}
	}

	fclose(cipher_file);
	free(text);
	text = NULL;
	free(key);
	key = NULL;
	return 0;
}
