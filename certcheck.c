#include <stdio.h>
#include <stdlib.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string.h>
#include "certcheck.h"


char* getfield(char* line, int num)
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
            url[i - pthsize] = '\0';
        }
    }
    if(num == PATH){
        free(url);
        return path;
    }
    if(num == URL){
        free(path);
        return url;
    }
    return NULL;
}


int main(int argc, char *argv[]){

    // Check the command line arguments
    if(argc < 2){
        perror("Usage: ./ [path to file]\n");
        exit(EXIT_FAILURE);
    }

    char cert_path[1024];

    strcpy(cert_path, argv[1]);

    FILE* stream = fopen(cert_path, "r");

    char line[1024];
    while (fgets(line, 1024, stream))
    {
//        char* tmp[];
//        strcpy(tmp,line);

        printf("Path: %s\n", getfield(line, PATH));
        printf("URL: %s\n", getfield(line, URL));

//        free(tmp);
    }

    return 0;
}