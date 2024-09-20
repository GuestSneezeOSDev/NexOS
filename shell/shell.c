#include "assert.h"
#include "buildin_cmd.h"
#include "debug.h"
#include "file.h"
#include "fs.h"
#include "global.h"
#include "stdint.h"
#include "stdio.h"
#include "stdio_kernel.h"
#include "string.h"
#include "syscall.h"
#include "thread.h"

#define MAX_ARG_NR 16

static char cmd_line[MAX_PATH_LEN] = {0};
char final_path[MAX_PATH_LEN] = {0};
char cwd_buf[MAX_PATH_LEN] = {0};

void print_prompt() { printf("[core@nexos %s]$ ", cwd_buf); }

static void readline(char *buf, int32_t count) {
  assert(buf != NULL && count > 0);
  char *pos = buf;
  while (read(STDIN_NO, pos, 1) != -1 && (pos - buf) < count) {
    switch (*pos) {
    case '\n':
    case '\r':
      *pos = 0;
      putchar('\n');
      return;
    case '\b':
      if (buf[0] != '\b') {
        --pos;
        putchar('\b');
      }
      break;
    case 'l' - 'a':
      *pos = 0;
      clear();
      print_prompt();
      printf("%s", buf);
      break;
    case 'u' - 'a':
      while (buf != pos) {
        putchar('\b');
        *(pos--) = 0;
      }
      break;
    default:
      putchar(*pos);
      pos++;
    }
  }
  printf("readline: can't find enter_key in the cmd_line, max num of char is "
         "128\n");
}

static int32_t cmd_parse(char *cmd_str, char **argv, char token) {
  assert(cmd_str != NULL);

  int32_t arg_idx = 0;
  while (arg_idx < MAX_ARG_NR) {
    argv[arg_idx] = NULL;
    arg_idx++;
  }

  char *next = cmd_str;
  int32_t argc = 0;
  while (*next) {
    while (*next == token) {
      next++;
    }

    if (*next == 0) {
      break;
    }

    argv[argc] = next;

    while (*next && *next != token) {
      next++;
    }

    if (*next == token) {
      *next++ = 0;
    }

    if (argc > MAX_ARG_NR) {
      return -1;
    }
    argc++;
  }
  return argc;
}

char *argv[MAX_ARG_NR];
int32_t argc = -1;

void zx_shell() {
  cwd_buf[0] = '/';
  while (1) {
    print_prompt();
    memset(final_path, 0, MAX_PATH_LEN);
    memset(cmd_line, 0, MAX_PATH_LEN);
    readline(cmd_line, MAX_PATH_LEN);
    if (cmd_line[0] == 0) {
      continue;
    }
    argc = -1;
    argc = cmd_parse(cmd_line, argv, ' ');
    if (argc == -1) {
      printf("Nexshell: number of parameters exceeds maximum allowed (%d) \n",
             MAX_ARG_NR);
      continue;
    }
    if (!strcmp("ls", argv[0])) {
      buildin_ls(argc, argv);
    } else if (!strcmp("cd", argv[0])) {
      if (buildin_cd(argc, argv) != NULL) {
        memset(cwd_buf, 0, MAX_PATH_LEN);
        strcpy(cwd_buf, final_path);
      }
    } else if (!strcmp("pwd", argv[0])) {
      buildin_pwd(argc, argv);
    } else if (!strcmp("ps", argv[0])) {
      buildin_ps(argc, argv);
    } else if (!strcmp("clear", argv[0])) {
      buildin_clear(argc, argv);
    } else if (!strcmp("mkdir", argv[0])) {
      buildin_mkdir(argc, argv);
    } else if (!strcmp("rmdir", argv[0])) {
      buildin_rmdir(argc, argv);
    } else if (!strcmp("rm", argv[0])) {
      buildin_rm(argc, argv);
    } else {
      
      int32_t pid = fork();
      if (pid) {
        while (1)
          ;
      } else {
        make_clear_abs_path(argv[0], final_path);
        argv[0] = final_path;
        struct stat file_stat;
        memset(&file_stat, 0, sizeof(struct stat));
        if (stat(argv[0], &file_stat) == -1) {
          printf("Nex shell: command not found: %s\n", argv[0]);
        } else {
          execv(argv[0], argv);
        }
        /** while (1) */
        /**   ; */
      }
    }
    int32_t arg_idx = 0;
    while (arg_idx < MAX_ARG_NR) {
      argv[arg_idx] = NULL;
      arg_idx++;
    }
  }
  panic("Nex shell: you should't be here :‑( !");
}
