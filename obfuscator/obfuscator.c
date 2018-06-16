#include <stdio.h>
#include <string.h>
#include <unistd.h>

void obfuscate(FILE*, FILE*, char*); 
FILE* openfile(char*, char*, int);

main(int argc, char** argv)
{
    FILE* in; FILE* out;
    char file[2][32], key[32];                                  // file[0] input, file[1] output
    int bin[2]; char c;

    bin[0] = 0; bin[1] = 0;
    char* name = argv[0];
    int i = 0, flag = 0;
    while ((c = getopt(argc, argv, "k:b:")) != -1) {
        switch (c) {
            case 'k':
                strcpy(key, optarg);
                flag = 1;
                break;
            case 'b':
                if (optind - 1 == 4) {
                    bin[0] = 1;
                    strcpy(file[0], optarg);
                } else {
                    bin[1] = 1;
                    strcpy(file[1], optarg);
                }
                break;
        }
    }
    if (flag == 0) {
        fprintf(stderr, "%s: gimme the key\n\n", name);
        return 0;
    }

    if (argc == 3)                                              // name + opt + key                               
            obfuscate(stdin, stdout, key);
    else {
        if (bin[0] == 0)
            strcpy(file[0], argv[optind++]);
        if (bin[1] == 0 && argc > 4) 
            strcpy(file[1], argv[optind++]);
        else {
            in = openfile(file[0], "r", bin[0]);
            if (in == NULL) {
                fprintf(stderr, "%s: can't open %s\n\n", name, file[0]);
                return 0;
            }
            obfuscate(in, stdout, key);
            return 0;
        }
        in  = openfile(file[0], "r", bin[0]);
        if (in == NULL) {
            fprintf(stderr, "%s: can't open %s\n\n", name, file[0]);
            return 0;
        }
        out = openfile(file[1], "w", bin[1]);
        if (out == NULL) {
            fprintf(stderr, "%s: can't open %s\n\n", name, file[1]);
            return 0;
        }
        obfuscate(in, out, key);
    }
    return 0;
}

FILE* openfile(char* name, char* mode, int bin)
{
    char new_mode[3];
    strcpy(new_mode, mode);
    if (bin) return fopen(name, strcat(new_mode, "b")); 
    else     return fopen(name, mode);
}

void obfuscate(FILE* in, FILE* out, char* key)
{
    int i = 0, keylen = strlen(key);
    char c;
    while (fread(&c, sizeof(char), 1, in))
        putc(c ^ key[i++ % keylen], out);
}
        
