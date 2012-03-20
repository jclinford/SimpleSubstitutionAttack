/*
	Author: John Linford

	Attempts to solve cipher-text that
	expects German plain-text. Uses letter frequencies
	and digrams found in German to do this.

	Attempts to iterate through the key to get the best
	'score' of digrams.

 */

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

int cipher_length = 0;
int freq[27];
char key[27];
int bestGuess = 0;

FILE *output;

int germanfreq[27] = {'E', 'I', 'D', 'L', 'S', 'N', 'U', 'R', 'C', 'H',
		'T', 'A', 'B', 'V', 'F', 'G', 'K', 'M', 'O', 'Z', 'P', 'W', 'Y', 'X', 'Q', 'J'};


int bigrams[] = {'E','R','E','N','C','H','D','E','E','I','N','D','T','E','I',
		'N','I','E','G','E','E','S','N','E','U','N','S','T','R','E','H','E','A','N','B','E',
		'A', 'U', 'D', 'I', 'I', 'S', 'I', 'T', 'M', 'E', 'M', 'A', 'N', 'A'};

int trigrams[] = {'E', 'I', 'N', 'I', 'C', 'H', 'N', 'D', 'E', 'D', 'I', 'E', 'U', 'N', 'D',
		'D', 'E', 'R', 'C', 'H', 'E', 'E', 'N', 'D', 'G', 'E', 'N', 'S', 'C', 'H', 'C', 'H', 'T',
		'D', 'E', 'N', 'I', 'N', 'E', 'N', 'G', 'E', 'N', 'U', 'N', 'U', 'N', 'G', 'D', 'A', 'S',
		'H', 'E', 'N', 'I', 'N', 'D', 'E', 'N', 'W', 'E', 'N', 'S', 'I', 'E', 'S', 'S', 'T', 'E',
		'T', 'E', 'N', 'E', 'R', 'E', 'L', 'I', 'C', 'A', 'C', 'H', 'N', 'D', 'I', 'S', 'S', 'E'};

int fourgrams[] = {'S', 'I', 'C', 'H', 'S', 'E', 'I', 'N', 'S', 'I', 'N', 'D', 'E', 'I', 'N', 'E',
		'A', 'U', 'C', 'H', 'N', 'I', 'C', 'H', 'T', 'W', 'I', 'R', 'D', 'H', 'A', 'B', 'E',
		'D', 'A', 'S', 'S', 'N', 'A', 'C', 'H', 'N', 'O', 'C', 'H', 'A', 'B', 'E', 'R', 'O', 'D', 'E', 'R',
		'M', 'E', 'H', 'R', 'K', 'A', 'N', 'N', 'W', 'E', 'N', 'N', 'S', 'E', 'I', 'N', 'D', 'A', 'N', 'N'};


// smaller sets of digrams sometimes work better due to the very small input size
//int bigrams[] = {'E', 'R', 'E', 'N', 'I', 'N', 'I', 'M', 'Z', 'U', 'E', 'S', 'A', 'N', 'U', 'M',
//		'S', 'O'};
//
//int trigrams[] = {'D', 'E', 'R', 'D', 'I', 'E', 'U', 'N', 'D', 'V', 'O', 'N', 'D', 'A', 'S',
//		'M', 'I', 'T', 'A', 'U', 'F', 'I', 'S', 'T', 'S', 'E', 'I', 'D', 'E', 'N', 'D', 'E', 'M'};
//

// simply counts frequencies of cipher text
void Calc_Freq(int length, char cipher[])
{
	int i = 0;
	char tmpChar;

	// initialize frequencies to 0
	for (i = 0; i < 26; i++)
		freq[i] = 0;

	// count frequencies
	for (i = 0; i < length; i++)
	{
		// 65 is A in ascii so
		tmpChar = cipher[i];
		freq[tmpChar - 65] += 1;
	}

	// display frequencies
	printf("Frequencies:\t");
	for (i = 0; i < 26; i++)
	{
		printf("%c:%d   ", i+65, freq[i]);
	}
	printf("\nTotal Count:\t%d\n\n", strlen(cipher));
}

// converts cipher to plaintext using key
// if print is 1, will also print to the user
void Convert_To_Plain(char cipher[], int print, int matches)
{
	int i = 0;
	int letter = 0;
	char plaintext[cipher_length];

	// decrypt cipher
	for (i = 0; i < cipher_length; i++)
	{
		letter = cipher[i];
		plaintext[i] = cipher[i];
		plaintext[i] = key[letter - 65];
	}

	// print plaintext
	if (print == 1)
	{
		// print out the plaintext to file
		fprintf(output, "%d:\t", matches);
		for (i = 0; i < cipher_length; i++)
		{
			if (i == cipher_length - 5)
				fprintf(output, "  ");
			fprintf(output, "%c", plaintext[i]);
		}
		fprintf(output,"\n");

		// print out the key for further analysis
		for (i = 0; i < 26; i++)
		{
			fprintf(output, "%c", germanfreq[i]);
		}
		fprintf(output, "\n\n");
	}
}

// switch i and j in the key
void Swap_Positions(int i, int j)
{
	int tmp;

	tmp = germanfreq[i];
	germanfreq[i] = germanfreq[j];
	germanfreq[j] = tmp;
}

// decrypts and calculates score
// returns the score
int Calculate_Score(char cipher[])
{
	int i = 0;
	int j = 0;
	int index = 0;
	int tmp = 0;
	int numMatches = 0;		// number of matches found in dictionary
	char plaintext[cipher_length];
	int letter = 0;
	int tmpFreq[27];

	for (i = 0; i < 26; i++)
	{
		tmpFreq[i] = freq[i];
	}

	// find the most common letter and replace it with the germanfreq letter in key,
	// and then find 2nd most.. etc
	for (j = 0; j < 26; j++)
	{
		index = 0;
		tmp = 0;
		for (i = 0; i < 26; i++)
		{
			if (tmpFreq[i] > tmp)
			{
				tmp = tmpFreq[i];
				index = i;
			}
		}
		// arrange key according to frequencies that were calculated
		if (tmp > 0)
		{
			tmpFreq[index] = 0;
			key[index] = germanfreq[j];
		}
	}

	// change into plaintext so i can check for N-grams..
	for (i = 0; i < cipher_length; i++)
	{
		letter = cipher[i];
		plaintext[i] = cipher[i];

		//if (key[letter - 65] != NULL)
		//{
		plaintext[i] = key[letter - 65];
		//}
	}

	int test[2];
	int bigram[2];

	// check for bigrams
	for (i = 0; i < cipher_length - 5; i++)
	{
		test[0] = plaintext[i];
		test[1] = plaintext[i+1];

		for (j = 0; j < (sizeof(bigrams) / sizeof(int)); j += 2)
		{
			bigram[0] = bigrams[j];
			bigram[1] = bigrams[j+1];

			if (bigram[0] == test[0] && bigram[1] == test[1])
			{
				//printf("%c %c, %c %c\t", bigram[0], bigram[1], test[0], test[1]);
				numMatches++;
				break;
			}
		}
	}

	int test3[3];
	int trigram[3];
	// trigrams
	for (i = 0; i < cipher_length - 5; i++)
	{
		test3[0] = plaintext[i];
		test3[1] = plaintext[i+1];
		test3[2] = plaintext[i+2];

		for (j = 0; j < (sizeof(trigrams) / sizeof(int)); j += 3)
		{
			trigram[0] = trigrams[j];
			trigram[1] = trigrams[j+1];
			trigram[2] = trigrams[j+2];

			if (trigram[0] == test3[0] && trigram[1] == test3[1] && trigram[2] == test3[2])
			{
				//printf("%c %c, %c %c\t", trigram[0], trigram[1], test3[0], test3[1]);
				numMatches++;
				break;
			}
		}
	}

	int test4[4];
	int fourgram[4];
	// fourgrams
	for (i = 0; i < cipher_length - 5; i++)
	{
		test4[0] = plaintext[i];
		test4[1] = plaintext[i+1];
		test4[2] = plaintext[i+2];
		test4[3] = plaintext[i+3];

		for (j = 0; j < (sizeof(fourgrams) / sizeof(int)); j += 4)
		{
			fourgram[0] = fourgrams[j];
			fourgram[1] = fourgrams[j+1];
			fourgram[2] = fourgrams[j+2];
			fourgram[3] = fourgrams[j+3];

			if (fourgram[0] == test4[0] && fourgram[1] == test4[1] && fourgram[2] == test4[2] && fourgram[3] == test4[3])
			{
				//printf("%c %c, %c %c\t", fourgram[0], fourgram[1], test4[0], test4[1]);
				numMatches++;
				break;
			}
		}
	}

	//printf("\nNumber of matches: %d\n", numMatches);
	return numMatches;
}

int main(int argc, char *argv[])
{
	int i = 0;
	int j = 0;
	int k = 0;
	cipher_length = strlen(argv[1]);
	char cipher[cipher_length];
	int tmpBestGuess = 2;


	if (argc != 2)
	{
		printf("Please input ciphertext as commandline arg (ie 'program12 ciphertext')");
		exit(-1);
	}

	strncpy(cipher, argv[1], cipher_length);

	// write output to a file for further analysis
	if ((output = fopen("DigramOut.txt", "w")) == NULL)
	{
		printf("Cannot open file");
		exit(-1);
	}


	printf("Ciphertext:\t");
	for (i = 0; i < cipher_length; i++)
	{
		printf("%c", cipher[i]);
		//printf("%d", germanfreq[i]);
	}
	printf("\n\n");


	// count the initial frequencies in the input
	Calc_Freq(cipher_length, cipher);

	// count the intial score
	tmpBestGuess = Calculate_Score(cipher);

	//		for (k = 0; k < 10; k++)
	//		{

	// run through the initial key,
	// calc the score,
	// then swap key around,
	// repeat.
	// Starting at 2 because I am 99% sure the highest freq is E and second highest is I
	for (i = 2; i < 26; i++)
	{
		for (j = 2; j < 26; j++)
		{
			Swap_Positions(i, j);
			tmpBestGuess = Calculate_Score(cipher);

			Convert_To_Plain(cipher, 1, tmpBestGuess);

			if (tmpBestGuess >= bestGuess)
			{
				bestGuess = tmpBestGuess;
			}
			else
			{
				// switch back if the two swaps make it worse
				Swap_Positions(j, i);
			}
		}
		//	}
	}

	fclose(output);

	exit(1);
}
