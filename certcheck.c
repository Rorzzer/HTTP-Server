//
// Created by Rory Powell - 638753
//

#include <stdio.h>
#include <stdlib.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/asn1_mac.h>
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

    strcpy(outputfile, "output.csv");
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
        char* cert_path = getfield(line, PATH);
        char* domain = getfield(line, DOMAIN);

        //Check the certificate
        result = check_cert(cert_path, domain);

        // write line to file
        fprintf(csv, "%s,%s,%d\n", cert_path, domain, result);

            free(cert_path);
            free(domain);
    }

    return 0;
}

int check_cert(char* path, char* domain) {


    BIO *certificate_bio = NULL;
    X509 *cert = NULL;
    X509_NAME *cert_name = NULL;

    //create BIO object to read certificate
    certificate_bio = BIO_new(BIO_s_file());

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
    if (check_time(notBefore, currTime) == 0) {
//        printf("failed not before check\n");
        return CERT_FAIL;
    }

    if (check_time(currTime, notAfter) == 0) {
//        printf("failed not after check\n");
        return CERT_FAIL;
    }

    // get subject common name
    char subject_cn[256] = "Subject CN NOT FOUND";
    cert_name = X509_get_subject_name(cert);
    X509_NAME_get_text_by_NID(cert_name, NID_commonName, subject_cn, 256);

    // check for wildcard, else compare the common name to the domain
    if (subject_cn[0] == '*') {
        if((wildcard_check(domain, subject_cn) == 0) && (check_SAN(cert, domain) == 0)) {
//                 printf("failed wildcard and san check\n");
                return CERT_FAIL;
        }
    } else {
        if ((strcmp(domain, subject_cn) != 0) && check_SAN(cert, domain) == 0) {
//            printf("failed cn and san check\n");
            return CERT_FAIL;
        }
    }

    if(check_keylength(cert) == 0){
//        printf("failed min key length\n");
        return CERT_FAIL;
    }


    if(check_constraints(cert) == 0){
//        printf("failed basic constraints\n");
        return CERT_FAIL;
    }

    if(check_keyusage(cert) == 0){
//        printf("failed key usage\n");
        return CERT_FAIL;
    }

    X509_free(cert);
    BIO_free_all(certificate_bio);

    return CERT_PASS;
}

/*
 * checks the constraint flags for CA:FALSE
 * */
int check_constraints(X509 *cert){

    //Need to check extension exists and is not null
    X509_EXTENSION *ex = X509_get_ext(cert, X509_get_ext_by_NID(cert, NID_basic_constraints, -1));
    ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
    char buff[1024];
    OBJ_obj2txt(buff, 1024, obj, 0);

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

    if(strstr(buf, CA_FALSE) == NULL){
        BIO_free_all(bio);
        free(buf);
        return FAIL;
    }
    BIO_free_all(bio);
    free(buf);
    return PASS;
}

/*
 * checks the key usage value for TLS server auth
 * */
int check_keyusage(X509 *cert){

    //Need to check extension exists and is not null
    X509_EXTENSION *ex = X509_get_ext(cert, X509_get_ext_by_NID(cert, NID_ext_key_usage, -1));
    ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
    char buff[1024];
    OBJ_obj2txt(buff, 1024, obj, 0);

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

    if(strstr(buf, TLS_AUTH) == NULL){
        BIO_free_all(bio);
        free(buf);
        return FAIL;
    }
    BIO_free_all(bio);
    free(buf);
    return PASS;
}

/*
 * checks the length of the certificates key
 * */
int check_keylength(X509 *cert){

    EVP_PKEY *pkey = NULL;
    RSA *rsakey = NULL;
    pkey = X509_get_pubkey(cert);
    if(pkey == NULL){
        fprintf(stderr, "Error reading public key");
        return FAIL;
    }
    rsakey = EVP_PKEY_get1_RSA(pkey);
    if(rsakey == NULL) {
        fprintf(stderr, "Error reading RSA key");
        return FAIL;
    }
    int keylength = RSA_size(rsakey) * BITS;
    if(keylength < MIN_KEY_LENGTH){
        return FAIL;
    }
    return PASS;
}

/*
 * removes the wildcard part of the domain and checks if that is a substring of the common name
 * */
int wildcard_check(char *domain, char *subject_cn){

    char *temp, tmpdom[1024], tmpsubcn[1024];

    strcpy(tmpdom, domain);
    strcpy(tmpsubcn, subject_cn);
    temp = strchr(tmpsubcn,'.') + 1;
    if((strstr(tmpdom, temp) != NULL) && (strcmp(tmpdom, temp) != 0)){
        return PASS;
    }
    return FAIL;
}

/*
 * checks the domain against the SAN values if they exist
 * */
int check_SAN(X509 *cert, char *domain){

    int i;
    int total_sans = -1;
    STACK_OF(GENERAL_NAME) *san_names = NULL;

    san_names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (san_names == NULL) {
        sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
        return FAIL;
    } else {
        total_sans = sk_GENERAL_NAME_num(san_names);
        for (i = 0; i < total_sans; i++) {
            const GENERAL_NAME *current_name = sk_GENERAL_NAME_value(san_names, i);
            char *dns_name = (char *) ASN1_STRING_data(current_name->d.dNSName);
            if (dns_name[0] == '*') {
                if(wildcard_check(domain, dns_name) == 1) {
                    sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
                    return PASS;
                }
            } else {
                if (strcmp(domain, dns_name) == 0) {
                    sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
                    return PASS;
                }
            }
        }
    }
    sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
    return FAIL;
}

/*
 * returns 1 if the first time is earlier than the second time, 0 in all other cases
 * */
int check_time(ASN1_TIME *firstTime, ASN1_TIME *secondTime){

    int day, sec;

    if (ASN1_TIME_diff(&day, &sec, firstTime, secondTime)) {
        if (day > 0 || sec > 0) {
            return PASS;
        } else {
            return FAIL;
        }
    } else {
        //invalid time format
        return FAIL;
    }
}

/*
 * returns the value of the field specified
 * */
char* getfield(char* line, int field)
{

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