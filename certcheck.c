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
        perror("Usage: ./ [path to file]\n");
        exit(EXIT_FAILURE);
    }

    // Initialise openSSL
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    char cert_path[1024], filename[1024];
    FILE* csv;

    // Get the path then open the csv file
    strcpy(cert_path, argv[1]);
    FILE* stream = fopen(cert_path, "r");

    // Remove the path, get the file name, remove the ext then add "-output.csv"
    char *temp;
    temp = strchr(cert_path,'.');
    *temp = '\0';
    temp = strrchr(cert_path, '/') + 1;
    strcpy(filename, temp);
    strcat(filename, "-output.csv");

    // Create a new csv for output
    csv = fopen(filename, "w+");

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