#include <stdio.h>
#include <stdlib.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string.h>
#include "certcheck.h"


int main(int argc, char *argv[]){

    // Check the command line arguments
    if(argc < 2){
        printf("Usage: ./ [path to file]\n");
        exit(EXIT_FAILURE);
    }

    // Initialise openSSL
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    char cert_path[1024], outputfile[1024];
    FILE *csv, *stream;

    // Get the path then open the csv file if valid
    strcpy(cert_path, argv[1]);

    if((stream = fopen(cert_path, "r")) == NULL)
    {
        perror("Error");
        exit(EXIT_FAILURE);
    }

    // Remove the input file from the path and add the output file (output.csv)
    char *temp;
    temp = strrchr(cert_path,'/') + 1;
    *temp = '\0';
    strcpy(outputfile, cert_path);
    strcat(outputfile, "output:.csv");
    printf("path after: %s\n", outputfile);


    // Open or create output csv
    if((csv = fopen(outputfile, "w+")) == NULL)
    {
        perror("Error");
        exit(EXIT_FAILURE);
    }

    char line[1024];
    while (fgets(line, 1024, stream))
    {
        int result = 0;
        char* path = getfield(line, PATH);
        char* url = getfield(line, URL);

        //Check the certificate
//        result = check_cert(path, url);

        fprintf(csv, "%s,%s,%d\n", path, url, result);

        free(path);
        free(url);
    }

    return 0;
}

int check_cert(char* path, char* url)
{
    return 0;
}

char* getfield(char* line, int field)
{
    int i = 0, pthsize = 0, urlsize = 0, delim = 0;
    char * path;
    char * url;

    path = malloc(sizeof(char) * 1024);
    url = malloc(sizeof(char) * 1024);


    for(i = 0; i < 1024; i++){

        if((line[i] == ',') || (line[i] == ' ') || (line[i] == '\0')){
            delim++;
        }

        if(delim == 0){
            path[i] = line[i];
            pthsize++;

        } else if(delim == 1){
            url[i - pthsize] = line[i + delim];
            urlsize++;

        } else {
            path[i - urlsize] = '\0';
            url[i - (pthsize + delim)] = '\0';
        }
    }
    if(field == PATH){
        free(url);
        return path;
    }
    if(field == URL){
        free(path);
        return url;
    }
    return NULL;
}