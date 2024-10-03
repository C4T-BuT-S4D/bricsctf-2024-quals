#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>

#define nullptr NULL
#define STDIN_FD 0
#define STDOUT_FD 1
#define CMD_SIZE 16
#define ENV_MAX_SIZE 1024
#define MAX_LINE_SIZE 4096
#define LOG_PATH "./cli.log"

void setup() {
    FILE* fp = fopen(LOG_PATH, "w");
    fputs("13:37:37 - auth.log created", fp);
    fputs("13:38:37 - user xetrov is logined", fp);
    fclose(fp);

    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
}

ssize_t read_into_buffer(void *buf, uint32_t size) 
{
    if (buf == NULL) {
        puts("[-] invalid buffer pointer");
        return -1;
    }

    if (size == 0) {
        puts("[-] invalid buffer size");
        return -1;
    }

    ssize_t nbytes = read(STDIN_FD, buf, size);

    if (nbytes < 0) {
        puts("[-] failed to read into buffer");
        return -1;
    }

    return nbytes;
}

ssize_t write_from_buffer(const void *buf, uint32_t size) 
{
    if (buf == NULL) {
        puts("[-] invalid buffer pointer");
        return -1;
    }

    if (size == 0) {
        puts("[-] invalid buffer size");
        return -1;
    }

    ssize_t nbytes = write(STDOUT_FD, buf, size);

    if (nbytes < 0) {
        puts("[-] failed to write from buffer");
        return -1;
    }

    return nbytes;
}

int read_integer(void)
{
    const size_t buflen = 8;

    char buf[buflen];
    ssize_t nbytes = read_into_buffer(buf, buflen);

    if (nbytes == -1) {
        puts("[-] failed to read int");
        return -1;
    }

    return atoi(buf);
}

void add_to_log(const char* string) {
    FILE* fp = fopen(LOG_PATH, "a");
    time_t tm = time(0);
    struct tm* tmp = gmtime(&tm);
    fprintf(fp, "%02d:%02d:%02d - %s\n", tmp->tm_hour, tmp->tm_min, tmp->tm_sec, string);
    fclose(fp);
}

void ls_cur_dir() {
    struct dirent * ptr;
    DIR * dir;
    dir = opendir(getenv("PWD"));

    while((ptr = readdir(dir)) != NULL) {
        printf("%s ", ptr->d_name);
    }

    puts("");
    add_to_log("ls used!");
}

void env_handler() {
    char option[CMD_SIZE];
    printf("Choose option: ");
    ssize_t nbytes = read_into_buffer(option, CMD_SIZE);
    
    char env_name[ENV_MAX_SIZE];
    char env_value[ENV_MAX_SIZE];
    char log_buffer[ENV_MAX_SIZE * 2 + 32];
    memset(log_buffer, 0x0, ENV_MAX_SIZE * 2 + 32);

    if (!strncmp(option, "set", 3)) {        
        printf("Enter env name: ");
        ssize_t nbytes = read_into_buffer(env_name, ENV_MAX_SIZE);
        
        if (nbytes > 0) {
            if (env_name[nbytes  - 1] == '\n')
                env_name[nbytes - 1] = '\0';
        }

        printf("Enter env value: ");
        nbytes = read_into_buffer(env_value, ENV_MAX_SIZE);
        
        if (nbytes > 0) {
            if (env_value[nbytes  - 1] == '\n')
                env_value[nbytes - 1] = '\0';
        }

        setenv(env_name, env_value, 1);
        snprintf(log_buffer, ENV_MAX_SIZE * 2 + 31, "new env %s=%s", env_name, env_value);
        add_to_log(log_buffer);
    } else if (!strncmp(option, "get", 3)) {
        printf("Enter env name: ");
        ssize_t nbytes = read_into_buffer(env_name, ENV_MAX_SIZE);
        if (nbytes > 0) {
            if (env_name[nbytes  - 1] == '\n')
                env_name[nbytes - 1] = '\0';
        }
        printf("%s\n", getenv(env_name));
        snprintf(log_buffer, ENV_MAX_SIZE * 2 + 31, "env %s=%s", env_name, getenv(env_name));
        add_to_log(log_buffer);
    } else {
        puts("Invalid option!");
        return;
    }
}

void logs_handler() {
    char option[CMD_SIZE];
    printf("Choose option: ");
    ssize_t nbytes = read_into_buffer(option, CMD_SIZE);
    

    if (!strncmp(option, "gen", 3)) {        
        puts("Not implemented yet!");
        return;
    } else if (!strncmp(option, "view", 4)) {
        FILE* fp = fopen(LOG_PATH, "r");
        char* line = NULL;
        int nbytes = 0;
        int out_sz = 0;

        while ((nbytes = getline(&line, &out_sz, fp)) != -1) {
            char* time_s = line;
            char* time_e = strstr(line, "-");
            size_t time_sz = time_e - time_s - 1;

            char* time_str = (char*) malloc(time_sz);
            memset(time_str, 0x0, time_sz);
            memcpy(time_str, time_s, time_sz);

            struct tm* tmp = getdate(time_str);

            if (tmp != NULL) {
                tmp->tm_hour += 3;
                printf("%d:%d:%d %s", tmp->tm_hour, tmp->tm_min, tmp->tm_sec, time_e);
            } else {
                printf(line);
            }

            free(line);
            line = NULL;
            free(time_str);
        }

        puts("");
        fclose(fp);
    } else {
        puts("Invalid option!");
        return;
    }
}

int main() {
    setup();
    add_to_log("cli running!");

    while (1) {
        printf("# ");
        char cmd[CMD_SIZE];
        memset(cmd, 0x0, CMD_SIZE);
        ssize_t nbytes = read_into_buffer(cmd, CMD_SIZE);
        
        if (nbytes > 0) {
            if (cmd[nbytes - 1] == '\n')
                cmd[nbytes - 1] = '\0';
        }

        if (!strcmp(cmd, "ls")) {
            ls_cur_dir();
        } else if (!strcmp(cmd, "env")) {
            env_handler();
        } else if (!strcmp(cmd, "logs")) {
            logs_handler();
        }
    }

    return 0;
}