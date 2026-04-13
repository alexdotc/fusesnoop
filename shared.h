// shared between the kernel and user space code
struct data_t {
   uint32_t pid;
   uint32_t uid;
   long ret;
   char comm[16];
   char filename[16];
};
