//
// Created by Rory Powell on 15/5/18.
//

#ifndef COMP30023_2018_PROJECT_2__H
#define COMP30023_2018_PROJECT_2_MAIN_H
#endif //COMP30023_2018_PROJECT_2_MAIN_H

#define PATH 0
#define DOMAIN 1
#define PASS 1
#define FAIL 0
#define CERT_FAIL 0
#define CERT_PASS 1
#define MIN_KEY_LENGTH 2048
#define BITS 8
#define CA_FALSE "CA:FALSE"
#define TLS_AUTH "TLS Web Server Authentication"

int check_SAN(X509 *cert, char *domain);
int check_keyusage(X509 *cert);
int check_constraints(X509 *cert);
int check_keylength(X509 *cert);
int wildcard_check(char *domain, char *subject_cn);
int check_time(ASN1_TIME *firstTime, ASN1_TIME *secondTime);
char* getfield(char* line, int num);
int check_cert(char* path, char* url);

