#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>

#ifdef _WIN32
#include <direct.h>
#define MKDIR(p) _mkdir(p)
#define SEP "\\"
#else
#include <sys/stat.h>
#define MKDIR(p) mkdir((p), 0700)
#define SEP "/"
#endif

#define VAULT_DIR "vault"
#define MASTER_FILE VAULT_DIR SEP "master.dat"
#define INDEX_FILE VAULT_DIR SEP "index.dat"
#define MAX_NAME 63
#define MAX_PASSWORD 127
#define MAX_FILES 500

typedef struct {
    char name[MAX_NAME + 1];
    unsigned long long size;
    char timestamp[32];
} FileMeta;

typedef struct {
    char name[MAX_NAME + 1];
    unsigned long long size;
    char timestamp[32];
    uint32_t nonce;
} FileHeader;

static FileMeta files[MAX_FILES];
static size_t file_count = 0;

static void path_for(char *out, size_t cap, const char *name) {
    snprintf(out, cap, "%s%s%s.enc", VAULT_DIR, SEP, name);
}

static void trim_newline(char *s) {
    size_t n = strlen(s);
    while (n && (s[n-1] == '\n' || s[n-1] == '\r')) s[--n] = '\0';
}

static int read_line(const char *prompt, char *buf, size_t cap) {
    printf("%s", prompt);
    if (!fgets(buf, (int)cap, stdin)) return 0;
    trim_newline(buf);
    return 1;
}

static int valid_name(const char *s) {
    size_t n = strlen(s);
    if (n == 0 || n > MAX_NAME || s[0] == '.') return 0;
    for (size_t i = 0; i < n; ++i)
        if (!(isalnum((unsigned char)s[i]) || s[i] == '_' || s[i] == '-' || s[i] == '.')) return 0;
    return 1;
}

/* Simple educational salted checksum, NOT a password hashing algorithm. */
static uint32_t password_hash(const char *password, const char *salt) {
    uint32_t h = 2166136261u;
    for (const unsigned char *p = (const unsigned char *)salt; *p; ++p) { h ^= *p; h *= 16777619u; }
    for (const unsigned char *p = (const unsigned char *)password; *p; ++p) { h ^= *p; h *= 16777619u; }
    h ^= h >> 13; h *= 0x5bd1e995u; h ^= h >> 15;
    return h;
}

static uint32_t seed_for(const char *password, uint32_t nonce) {
    uint32_t x = password_hash(password, "locker-demo-salt");
    x ^= nonce + 0x9e3779b9u;
    return x ? x : 0xA341316Cu;
}

/* Reversible XOR stream for syllabus demonstration only. */
static void crypt_bytes(unsigned char *data, size_t n, const char *password, uint32_t nonce) {
    uint32_t state = seed_for(password, nonce);
    for (size_t i = 0; i < n; ++i) {
        state ^= state << 13; state ^= state >> 17; state ^= state << 5;
        data[i] ^= (unsigned char)(state & 0xffu);
    }
}

static int save_index(void) {
    FILE *f = fopen(INDEX_FILE, "wb");
    if (!f) return 0;
    uint32_t count = (uint32_t)file_count;
    int ok = fwrite(&count, sizeof count, 1, f) == 1 &&
             fwrite(files, sizeof(FileMeta), file_count, f) == file_count;
    fclose(f);
    return ok;
}

static int load_index(void) {
    FILE *f = fopen(INDEX_FILE, "rb");
    if (!f) { file_count = 0; return 1; }
    uint32_t count = 0;
    if (fread(&count, sizeof count, 1, f) != 1 || count > MAX_FILES ||
        fread(files, sizeof(FileMeta), count, f) != count) {
        fclose(f); fprintf(stderr, "Index file is damaged.\n"); return 0;
    }
    file_count = count;
    fclose(f);
    return 1;
}

static int find_file(const char *name) {
    for (size_t i = 0; i < file_count; ++i) if (strcmp(files[i].name, name) == 0) return (int)i;
    return -1;
}

static int store_master(const char *password) {
    char salt[17];
    for (int i = 0; i < 16; ++i) salt[i] = "0123456789abcdef"[rand() % 16];
    salt[16] = '\0';
    uint32_t hash = password_hash(password, salt);
    FILE *f = fopen(MASTER_FILE, "wb");
    if (!f) return 0;
    int ok = fwrite(salt, sizeof salt, 1, f) == 1 && fwrite(&hash, sizeof hash, 1, f) == 1;
    fclose(f);
    return ok;
}

static int verify_master(const char *password) {
    FILE *f = fopen(MASTER_FILE, "rb");
    if (!f) return -1;
    char salt[17]; uint32_t saved = 0;
    int ok = fread(salt, sizeof salt, 1, f) == 1 && fread(&saved, sizeof saved, 1, f) == 1;
    fclose(f);
    return ok && password_hash(password, salt) == saved;
}

static void make_timestamp(char *out, size_t cap) {
    time_t now = time(NULL); struct tm *t = localtime(&now);
    if (t) strftime(out, cap, "%Y-%m-%d %H:%M:%S", t); else snprintf(out, cap, "unknown");
}

static unsigned char *read_all(FILE *f, size_t *length) {
    size_t cap = 1024, used = 0;
    unsigned char *data = (unsigned char *)malloc(cap);
    if (!data) return NULL;
    for (;;) {
        if (used == cap) {
            if (cap > SIZE_MAX / 2) { free(data); return NULL; }
            cap *= 2;
            unsigned char *larger = (unsigned char *)realloc(data, cap);
            if (!larger) { free(data); return NULL; }
            data = larger;
        }
        size_t got = fread(data + used, 1, cap - used, f);
        used += got;
        if (got == 0) { if (ferror(f)) { free(data); return NULL; } break; }
    }
    *length = used;
    return data;
}

static void create_or_write(const char *password) {
    char name[MAX_NAME + 8], text[4096], path[256];
    if (!read_line("File name (letters/numbers/._-): ", name, sizeof name) || !valid_name(name)) {
        puts("Invalid file name."); return;
    }
    if (!read_line("Text to save (one line): ", text, sizeof text)) return;
    size_t n = strlen(text);
    unsigned char *data = (unsigned char *)malloc(n ? n : 1);
    if (!data) { puts("Not enough memory."); return; }
    if (n) memcpy(data, text, n);
    uint32_t nonce = (uint32_t)rand() ^ (uint32_t)time(NULL);
    crypt_bytes(data, n, password, nonce);
    FileHeader h; memset(&h, 0, sizeof h);
    snprintf(h.name, sizeof h.name, "%s", name); h.size = n; h.nonce = nonce;
    make_timestamp(h.timestamp, sizeof h.timestamp);
    path_for(path, sizeof path, name);
    FILE *f = fopen(path, "wb");
    int ok = f && fwrite(&h, sizeof h, 1, f) == 1 && fwrite(data, 1, n, f) == n;
    if (f) fclose(f);
    free(data);
    if (!ok) { puts("Could not save file."); return; }
    int idx = find_file(name);
    if (idx < 0) {
        if (file_count == MAX_FILES) { puts("Locker is full."); return; }
        idx = (int)file_count++;
    }
    snprintf(files[idx].name, sizeof files[idx].name, "%s", name);
    files[idx].size = n; snprintf(files[idx].timestamp, sizeof files[idx].timestamp, "%s", h.timestamp);
    if (!save_index()) puts("File saved, but index update failed."); else puts("File saved in encrypted demo format.");
}

static int load_encrypted(const char *password, const char *name, unsigned char **data, size_t *n, FileHeader *h) {
    char path[256]; path_for(path, sizeof path, name);
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    int ok = fread(h, sizeof *h, 1, f) == 1 && h->size <= SIZE_MAX;
    if (!ok) { fclose(f); return 0; }
    *n = (size_t)h->size;
    *data = (unsigned char *)malloc(*n ? *n : 1);
    if (!*data) { fclose(f); return 0; }
    ok = fread(*data, 1, *n, f) == *n;
    fclose(f);
    if (!ok) { free(*data); *data = NULL; return 0; }
    crypt_bytes(*data, *n, password, h->nonce);
    return 1;
}

static void open_file(const char *password) {
    char name[MAX_NAME + 8];
    if (!read_line("File name: ", name, sizeof name) || !valid_name(name)) { puts("Invalid name."); return; }
    unsigned char *data = NULL; size_t n = 0; FileHeader h;
    if (!load_encrypted(password, name, &data, &n, &h)) { puts("Could not read file."); return; }
    printf("\n--- %s (%zu bytes, saved %s) ---\n", h.name, n, h.timestamp);
    if (n) fwrite(data, 1, n, stdout);
    puts("\n--------------------------------"); free(data);
}

static void list_files(void) {
    if (!file_count) { puts("Locker is empty."); return; }
    puts("\nName                           Size(bytes)  Last saved");
    for (size_t i = 0; i < file_count; ++i)
        printf("%-30s %-11llu %s\n", files[i].name, files[i].size, files[i].timestamp);
}

static void delete_file(void) {
    char name[MAX_NAME + 8], path[256];
    if (!read_line("File name to delete: ", name, sizeof name) || !valid_name(name)) { puts("Invalid name."); return; }
    int idx = find_file(name);
    if (idx < 0) { puts("No such file in index."); return; }
    path_for(path, sizeof path, name);
    if (remove(path) != 0) { puts("Could not delete encrypted file."); return; }
    for (size_t i = (size_t)idx; i + 1 < file_count; ++i) files[i] = files[i+1];
    --file_count;
    if (!save_index()) puts("Deleted file, but index update failed."); else puts("File deleted.");
}

static void change_password(char *password) {
    char old[MAX_PASSWORD + 2], next[MAX_PASSWORD + 2], again[MAX_PASSWORD + 2];
    if (!read_line("Current master password: ", old, sizeof old) || strcmp(old, password) != 0) { puts("Wrong password."); return; }
    if (!read_line("New master password: ", next, sizeof next) || strlen(next) < 4) { puts("Use at least 4 characters for this demo."); return; }
    if (!read_line("Repeat new password: ", again, sizeof again) || strcmp(next, again) != 0) { puts("Passwords do not match."); return; }
    /* Re-encrypt every file using the new password before replacing master. */
    for (size_t i = 0; i < file_count; ++i) {
        unsigned char *data = NULL; size_t n = 0; FileHeader h;
        if (!load_encrypted(password, files[i].name, &data, &n, &h)) { puts("Could not decrypt all files; password unchanged."); return; }
        crypt_bytes(data, n, next, h.nonce);
        char path[256]; path_for(path, sizeof path, files[i].name);
        FILE *f = fopen(path, "wb");
        int ok = f && fwrite(&h, sizeof h, 1, f) == 1 && fwrite(data, 1, n, f) == n;
        if (f) fclose(f); free(data);
        if (!ok) { puts("Re-encryption failed; some files may need recovery."); return; }
    }
    if (!store_master(next)) { puts("Could not save new password verifier."); return; }
    strcpy(password, next); puts("Master password changed; files re-encrypted for this demo.");
}

static void log_action(const char *action) {
    char path[256]; snprintf(path, sizeof path, "%s%saccess.log", VAULT_DIR, SEP);
    FILE *f = fopen(path, "a");
    if (f) { time_t now = time(NULL); struct tm *t = localtime(&now); char stamp[32] = "unknown";
        if (t) strftime(stamp, sizeof stamp, "%Y-%m-%d %H:%M:%S", t);
        fprintf(f, "%s | %s\n", stamp, action); fclose(f); }
}

int main(void) {
    srand((unsigned int)time(NULL));
    if (MKDIR(VAULT_DIR) != 0 && errno != EEXIST) { perror("Cannot create vault folder"); return 1; }
    char password[MAX_PASSWORD + 2];
    FILE *mf = fopen(MASTER_FILE, "rb");
    if (!mf) {
        char again[MAX_PASSWORD + 2];
        puts("First run: create a master password (demo minimum: 4 characters).");
        if (!read_line("New master password: ", password, sizeof password) || strlen(password) < 4 ||
            !read_line("Repeat password: ", again, sizeof again) || strcmp(password, again) != 0) {
            puts("Password setup cancelled or passwords did not match."); return 1;
        }
        if (!store_master(password)) { puts("Could not write master password file."); return 1; }
        puts("Master password set.");
    } else {
        fclose(mf);
        if (!read_line("Master password: ", password, sizeof password)) return 1;
        if (verify_master(password) != 1) { puts("Access denied."); log_action("FAILED LOGIN"); return 1; }
    }
    log_action("LOGIN OK");
    if (!load_index()) return 1;
    for (;;) {
        char choice[16];
        puts("\n=== SECURE FILE LOCKER (classroom demo) ===");
        puts("1. Create / write file\n2. Open / read file\n3. List files\n4. Delete file\n5. Change master password\n0. Exit");
        if (!read_line("Choose: ", choice, sizeof choice)) break;
        if (strcmp(choice, "1") == 0) { create_or_write(password); log_action("CREATE/WRITE"); }
        else if (strcmp(choice, "2") == 0) { open_file(password); log_action("READ"); }
        else if (strcmp(choice, "3") == 0) { list_files(); log_action("LIST"); }
        else if (strcmp(choice, "4") == 0) { delete_file(); log_action("DELETE"); }
        else if (strcmp(choice, "5") == 0) { change_password(password); log_action("PASSWORD CHANGE ATTEMPT"); }
        else if (strcmp(choice, "0") == 0) { log_action("LOGOUT"); break; }
        else puts("Choose one of the listed options.");
    }
    return 0;
}