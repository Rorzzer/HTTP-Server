#include <stdio.h>
#include <stdlib.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/asn1_mac.h>
//#include <openssl/asn1t.h>
#include <openssl/ssl.h>
#include <string.h>
#include <time.h>
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

    char inputfile[1024], outputfile[1024];
    FILE *csv, *stream;

    // Get the path then open the csv file if valid
    strcpy(inputfile, argv[1]);
    if((stream = fopen(inputfile, "r")) == NULL)
    {
        perror("Error");
        exit(EXIT_FAILURE);
    }

    // Remove the input file from the path and add the output file (output.csv)
    char *temp;
    temp = strrchr(inputfile,'/') + 1;
    *temp = '\0';
    strcpy(outputfile, inputfile);
    strcat(outputfile, "output.csv");
//    printf("path after: %s\n", outputfile);


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
        char filepath[1024];
        char* cert_path = getfield(line, PATH);
        char* domain = getfield(line, DOMAIN);

        strcpy(filepath, inputfile);
        strcat(filepath, cert_path);

//        printf("cert_path: %s, input file: %s, fpath: %s\n", cert_path, inputfile, filepath);

        //Check the certificate
        result = check_cert(filepath, domain);

        fprintf(csv, "%s,%s,%d\n", cert_path, domain, result);

            free(cert_path);
            free(domain);
    }

    return 0;
}

int check_cert(char* path, char* domain) {


    BIO *certificate_bio = NULL;
    X509 *cert = NULL;
    X509_NAME *cert_issuer = NULL, *cert_name = NULL;
    X509_CINF *cert_inf = NULL;
    STACK_OF(X509_EXTENSION) *ext_list;

    //create BIO object to read certificate
    certificate_bio = BIO_new(BIO_s_file());

    printf("%s\n", path);

    //Read certificate into BIO
    if (!(BIO_read_filename(certificate_bio, path))) {
        fprintf(stderr, "Error in reading cert BIO filename");
        exit(EXIT_FAILURE);
    }
    if (!(cert = PEM_read_bio_X509(certificate_bio, NULL, 0, NULL))) {
        fprintf(stderr, "Error in loading certificate");
        exit(EXIT_FAILURE);
    }

    // get the not before and after times and the current time
    ASN1_TIME *currTime = NULL, *notBefore, *notAfter;
    time_t t = time(NULL);
    ASN1_TIME_set(currTime, t);
    notBefore = X509_get_notBefore(cert);
    notAfter = X509_get_notAfter(cert);

    // check the times are valid
    if (check_time(notBefore, currTime) == 0){
//        printf("current time before not before time\n");
        printf("failed not before check\n");

        return 0;
    }

    if (check_time(currTime, notAfter) == 0){
//        printf("current time after not after time\n");
        printf("failed not after check\n");

        return 0;
    }



//    int lastpos = -1;
//    X509_NAME_ENTRY *e;
//
//    for (;;)
//    {
//        lastpos = X509_NAME_get_index_by_NID(cert_issuer, NID_commonName, lastpos);
//        if (lastpos == -1)
//            break;
//        e = X509_NAME_get_entry(cert_issuer, lastpos);
//
//    }

    char subject_cn[256] = "Subject CN NOT FOUND";
    cert_name = X509_get_subject_name(cert);
    X509_NAME_get_text_by_NID(cert_name, NID_commonName, subject_cn, 256);

    if(strcmp(domain, subject_cn) != 0){
        printf("failed cn check\n");
//    printf("\"%s\", \"%s\"\n", domain, subject_cn);
    return 0;
    }

    cert_issuer = X509_get_issuer_name(cert);
    char issuer_cn[256] = "Issuer CN NOT FOUND";
    X509_NAME_get_text_by_NID(cert_issuer, NID_commonName, issuer_cn, 256);
//    printf("Issuer CommonName:%s\n", issuer_cn);

    //Need to check extension exists and is not null
    X509_EXTENSION *ex = X509_get_ext(cert, X509_get_ext_by_NID(cert, NID_subject_key_identifier, -1));
    ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
    char buff[1024];
    OBJ_obj2txt(buff, 1024, obj, 0);
//    printf("Extension:%s\n", buff);

    BUF_MEM *bptr = NULL;
    char *buf = NULL;

    BIO *bio = BIO_new(BIO_s_mem());
    if (!X509V3_EXT_print(bio, ex, 0, 0))
    {
        fprintf(stderr, "Error in reading extensions");
    }
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bptr);

    //bptr->data is not NULL terminated - add null character
    buf = (char *)malloc((bptr->length + 1) * sizeof(char));
    memcpy(buf, bptr->data, bptr->length);
    buf[bptr->length] = '\0';

    //Can print or parse value
//    printf("%s\n", buf);

//    X509_free(cert);
    BIO_free_all(certificate_bio);
    BIO_free_all(bio);
    free(buf);


    return 1;
}

/*
 * returns 1 if the first time is earlier than the second time, 0 in all other cases
 * */
int check_time(ASN1_TIME *firstTime, ASN1_TIME *secondTime){

    int day, sec;

    if (ASN1_TIME_diff(&day, &sec, firstTime, secondTime)) {
        if (day > 0 || sec > 0) {
            return 1;
        } else {
            return 0;
        }
    } else {
        //invalid time format
        return 0;
    }

/*
 * time check code, pre-optimization
 * */
    //    int day, sec;
//
//    if (ASN1_TIME_diff(&day, &sec, notB, currTime)) {
//        if (day > 0 || sec > 0) {
//            printf("not before\n");
//        } else if (day < 0 || sec < 0) {
//            printf("before notB\n");
//            return 0;
//        } else {
//            printf("Same\n");
//        }
//    } else {
//        //invalid time format
//        return 0;
//    }
//
//    if (ASN1_TIME_diff(&day, &sec, currTime, notA)) {
//        if (day > 0 || sec > 0) {
//            printf("not after notA\n");
//        } else if (day < 0 || sec < 0) {
//            printf("after notA\n");
//            return 0;
//        } else {
//            printf("curre Same\n");
//        }
//    } else {
//        // invalid time format
//        return 0;
//    }

}

char* getfield(char* line, int field)
{

    /* possible optimisation code for later
     *
    if(field == PATH){
//        path = malloc(sizeof(char) * 1024);
        char temp[1024], *pathptr;
        strcpy(temp, line);
        pathptr = strchr(temp,',');
        *pathptr = '\0';
//        strcpy(path, line);
        return line;
    }
    if(field == URL){
        char *urlptr;
        urlptr = strrchr(line,',') + 1;
//        printf("%s\n",urlptr);
//        strcpy(url, urlptr);
        return urlptr;
    }
*/

    int i = 0, pthsize = 0, urlsize = 0, delim = 0;
    char * path;
    char * domain;


    path = malloc(sizeof(char) * 1024);
    domain = malloc(sizeof(char) * 1024);

    for(i = 0; i < 1024; i++){

        if((line[i] == ',') || (line[i] == ' ') || (line[i] == '\0')){
            delim++;
        }

        if(delim == 0){
            path[i] = line[i];
            pthsize++;

        } else if(delim == 1){
            domain[i - pthsize] = line[i + delim];
            urlsize++;

        } else {
            path[i - urlsize] = '\0';
            domain[i - (pthsize + delim)] = '\0';
        }
    }
    if(field == PATH){
        free(domain);
        return path;
    }
    if(field == DOMAIN){
        free(path);
        return domain;
    }

    return NULL;
}