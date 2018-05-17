//
// Created by Rory Powell on 15/5/18.
//

#ifndef COMP30023_2018_PROJECT_2__H
#define COMP30023_2018_PROJECT_2_MAIN_H
#endif //COMP30023_2018_PROJECT_2_MAIN_H

#define PATH 0
#define DOMAIN 1

int check_time(ASN1_TIME *firstTime, ASN1_TIME *secondTime);
char* getfield(char* line, int num);
int check_cert(char* path, char* url);

