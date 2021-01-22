#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <stdbool.h>
#include <gcrypt.h>

#include "../include/main.h"

float version = 1.0;

// User Input & settings
char *inputHash;
char *algorithm;
char *outputFilename;
bool outputToFile = false;
int threadAmount;
short algorithmSelectedNum;
char algorithms[][15] = {
    "MD4",
    "MD5",
    "RIPEMD-160",
    "TIGER",
    "TIGER1",
    "TIGER2",
    "SHA-1",
    "SHA-224",
    "SHA-256",
    "SHA-384",
    "SHA-512",
    "SHA3-224",
    "SHA3-256",
    "SHA3-384",
    "SHA3-512",
    "SHAKE-128",
    "SHAKE-256",
    "WHIRLPOOL",
    "GOSTR-34.11-94",
    "STRIBOG-256",
    "STRIBOG-512",
    "BLAKE2B-160",
    "BLAKE2B-256",
    "BLAKE2B-384",
    "BLAKE2B-512",
    "BLAKE2S-128",
    "BLAKE2S-160",
    "BLAKE2S-224",
    "BLAKE2S-256"
};
char gcryAlgorithms[][20] = {
    "GCRY_MD_MD4",
    "GCRY_MD_MD5",
    "GCRY_MD_RMD160",
    "GCRY_MD_TIGER",
    "GCRY_MD_TIGER1",
    "GCRY_MD_TIGER2",
    "GCRY_MD_SHA1",
    "GCRY_MD_SHA224",
    "GCRY_MD_SHA256",
    "GCRY_MD_SHA384",
    "GCRY_MD_SHA512",
    "GCRY_MD_SHA3_224",
    "GCRY_MD_SHA3_256",
    "GCRY_MD_SHA3_384",
    "GCRY_MD_SHA3_512",
    "GCRY_MD_SHAKE128",
    "GCRY_MD_SHAKE256",
    "GCRY_MD_WHIRLPOOL",
    "GCRY_MD_GOSTR3411_94",
    "GCRY_MD_STRIBOG256",
    "GCRY_MD_STRIBOG512",
    "GCRY_MD_BLAKE2B_160",
    "GCRY_MD_BLAKE2B_256",
    "GCRY_MD_BLAKE2B_384",
    "GCRY_MD_BLAKE2B_512",
    "GCRY_MD_BLAKE2S_128",
    "GCRY_MD_BLAKE2S_160",
    "GCRY_MD_BLAKE2S_224",
    "GCRY_MD_BLAKE2S_256"
};

int main(int argc, char **argv) {
    int options;
    while ((options = getopt(argc, argv, "hli:a:o:g:t:")) != -1) {
        switch (options) {
            case 'h':
                print_help();

            case 'l':
                print_algorithms();

            case 'i':
                inputHash = optarg;
                break;

            case 'a':
                algorithm = optarg;
                printf("algorithm: %s\n", algorithm);
                break;

            case 'o':
                outputFilename = optarg;
                outputToFile = true;
                printf("OutFilename: %s\n", outputFilename);
                break;

            case 'g':
                printf("Feature not available yet.\n");
                break;

            case 't':
                threadAmount = optarg; 
                printf("%i\n", threadAmount);
                break;

            default:
                print_usage();
                printf("dehashr -h for more information\n");
                exit(2);
        }
    }

    char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*.,;:-_(){}[]";
    bool cracked = false;

    while(cracked == false) {
            int   alphaLen = strlen(alphabet);
    int maxlen = 5;
    int   len      = 0;
    char *buffer   = malloc((maxlen + 1) * alphaLen * alphaLen * alphaLen);
    int  *letters  = malloc(maxlen * sizeof(int));
	char endResult[400];

    if (buffer == NULL || letters == NULL) {
		fprintf(stderr, "Not enough memory.\n");
		exit(1);
    }

    // This for loop generates all 1 letter patterns, then 2 letters, etc,
    // up to the given maxlen.
    for (len=1;len<=maxlen;len++) {
	// The stride is one larger than len because each line has a '\n'.
	int i;
	int stride = len+1;
	int bufLen = stride * alphaLen * alphaLen * alphaLen;

	if (len == 1) {
	    // Special case.  The main algorithm hardcodes the last two
	    // letters, so this case needs to be handled separately.
	    int j = 0;
	    bufLen = (len + 1) * alphaLen;
	    for (i=0;i<alphaLen;i++) {
		buffer[j++] = alphabet[i];
		buffer[j++] = '\n';
	    }
		
	    ////strcat(endResult, buffer);
	    continue;
	} else if (len == 2) {
	    // Also a special case.
	    int let0 = 0;
	    int let1 = 0;
	    bufLen = (len + 1) * alphaLen * alphaLen;
	    for (i=0;i<bufLen;i+=stride) {
		buffer[i]   = alphabet[let0];
		buffer[i+1] = alphabet[let1++];
		buffer[i+2] = '\n';
		if (let1 == alphaLen) {
		    let1 = 0;
		    let0++;
		    if (let0 == alphaLen)
			let0 = 0;
		}
	    }
		
	    ////strcat(endResult, buffer);
	    continue;
	}

	// Initialize buffer to contain all first letters.
	memset(buffer, alphabet[0], bufLen);

	// Now write all the last 3 letters and newlines, which
	// will after this not change during the main algorithm.
	{
	    // Let0 is the 3rd to last letter.  Let1 is the 2nd to last letter.
	    // Let2 is the last letter.
	    int let0 = 0;
	    int let1 = 0;
	    int let2 = 0;
	    for (i=len-3;i<bufLen;i+=stride) {
		buffer[i]   = alphabet[let0];
		buffer[i+1] = alphabet[let1];
		buffer[i+2] = alphabet[let2++];
		buffer[i+3] = '\n';
		if (let2 == alphaLen) {
		    let2 = 0;
		    let1++;
		    if (let1 == alphaLen) {
			let1 = 0;
			let0++;
			if (let0 == alphaLen)
			    let0 = 0;
		    }
		}
	    }
	}

	// Write the first sequence out.
	
	////strcat(endResult, buffer);

	// Special case for length 3, we're already done.
	if (len == 3)
	    continue;

	// Set all the letters to 0.
	for (i=0;i<len;i++)
	    letters[i] = 0;

	// Now on each iteration, increment the the fourth to last letter.
	i = len-4;
	do {
	    char c;
	    int  j;

	    // Increment this letter.
	    letters[i]++;

	    // Handle wraparound.
	    if (letters[i] >= alphaLen)
		letters[i] = 0;

	    // Set this letter in the proper places in the buffer.
	    c = alphabet[letters[i]];
	    for (j=i;j<bufLen;j+=stride)
		buffer[j] = c;

	    if (letters[i] != 0) {
		// No wraparound, so we finally finished incrementing.
		// Write out this set.  Reset i back to second to last letter.
		
		////strcat(endResult, buffer);
		i = len - 4;
		continue;
	    }

	    // The letter wrapped around ("carried").  Set up to increment
	    // the next letter on the left.
	    i--;
	    // If we carried past last letter, we're done with this
	    // whole length.
	    if (i < 0)
		break;
	} while(1);
    }

    // Clean up.


        char *bfValue = "demonstration";

        unsigned char digest[256];
        char outputHash[32+1] = {0,};

        // Getting the lenght of the specified algorithm
        int digest_length = gcry_md_get_algo_dlen(GCRY_MD_SHA256);

        // Hashing with selected algorithm
        gcry_md_hash_buffer(GCRY_MD_SHA256, digest, endResult, strlen(bfValue));

        for (int i=0; i < digest_length; i++) {
                sprintf(outputHash+(i*2), "%02x", digest[i]);
        }
        free(letters);
        free(buffer);
        /* char *generatedHash = hash(GCRY_MD_SHA256, bfValue); */
        if(strcmp(outputHash, inputHash) == 0) {
            cracked = true;
            printf("Hash was successfully cracked\n");
            printf("Input Hash: %s\n", inputHash);
            printf("Cracked Value: %s\n", bfValue);
        }
    }

    return 0;
}

// --------------------------------------------
// CLI Functions
// --------------------------------------------

void print_logo() {
    printf(
        " _|  _  |_   _.  _ |_  ._  \n"
        "(_| (/_ | | (_| _> | | |  v%0.1f\n"
        "Performant Hash-Cracker\n\n",
        version
    );
}

void print_usage() {
    printf("Usage: dehashr -i <inputHash> -t <algorithm> \n");
}

void print_help() {
    print_logo();

    print_usage();

    printf(
        "Options:\n"
        "-h              Print the help page\n"
        "-l              list all available inputHashing algorithms\n" 
        "-i <inputHash>  inputHash\n"
        "-a <algorithm>  hash algorithm\n"
        "-o <filename>   [Optional] Enable saving result in file.\n"
        "                (Filename needs to be specified)\n"
        "-g <guess>      guess the result\n"
        "-t <amount>     [Optional] Specify amount of threads. \n"
        "                Default: Calculates most efficient amount\n"
        );

    exit(0);
}

void print_algorithms() {
    print_logo();

    printf("Hashing Algorithms:\n");

    for (int i = 0; i < 29; i++) {
        printf("%s\n", algorithms[i]);
    }

    exit(0);
}
