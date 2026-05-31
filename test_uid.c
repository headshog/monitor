            #define _GNU_SOURCE
            #define STRINGIZE(x) STRINGIZE2(x)
            #define STRINGIZE2(x) #x
            #define LINE_STRING STRINGIZE(__LINE__)
            #include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
            int main(void) {
                if (seteuid(1001) != 0) { perror(__FILE__ ":" LINE_STRING ":" "seteuid"); return 2; }
int fd0 ;
{ char pathname[29]; strcpy(pathname, "/sub_parent/parent/open_file"); fd0 = syscall(SYS_open, pathname, O_RDONLY | O_CREAT, 0777); }
int fd1 ;
{ char pathname[30]; strcpy(pathname, "/sub_parent/parent/creat_file"); fd1 = syscall(SYS_creat, pathname, 0777); }
{ char oldpath[32]; strcpy(oldpath, "/sub_parent/parent/file_to_link"); char newpath[31]; strcpy(newpath, "/sub_parent/parent/linked_file"); syscall(SYS_link, oldpath, newpath); }
{ char pathname[26]; strcpy(pathname, "/sub_parent/parent/folder"); syscall(SYS_mkdir, pathname, 0777); }
                return 0;
            }

