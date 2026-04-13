// shared between the kernel and user space code
#define PATH_MAX_DEPTH 32
#define PATH_FILENAME_MAX_LEN 255

struct fullpath {
    uint8_t pathbuf[PATH_MAX_DEPTH * PATH_FILENAME_MAX_LEN];
    int depth;
};

struct data_t {
    uint32_t pid;
    uint32_t uid;
    long ret;
    char comm[16];
    struct fullpath filename;
};
