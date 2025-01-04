#include <stdio.h>
#include <stdlib.h>

#include "md5.h"

int input(char **string);

int main() {
    char *string = NULL;
    size_t length = input(&string);

    uint8_t digest[16];
    if (md5_hash((uint8_t *)string, length, digest))
        return 1;

    char hexdigest[33];
    to_hexdigest(digest, hexdigest);

    printf("%s\n", hexdigest);

    free(string);
}

int input(char **string) {
    if (!*string) {
        *string = malloc(sizeof(char));
        if (!*string) // in case allocation failed
            return -1;
    }

    int c;
    size_t length = 0, capacity = 1;
    while ((c = getchar()) != EOF && (char)c != '\0') {
        if (length == capacity) {
            capacity *= 2;
            *string = realloc(*string, capacity * sizeof(char));
            if (!*string)
                return -1;
        }

        (*string)[length++] = (char)c;
    }

    *string = realloc(*string, (length + 1) * sizeof(char));
    if (!*string)
        return -1;

    (*string)[length] = '\0';

    return length;
}
