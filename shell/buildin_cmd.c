#include "buildin_cmd.h"
#include "assert.h"
#include "debug.h"
#include "dir.h"
#include "fs.h"
#include "global.h"
#include "stdint.h"
#include "stdio.h"
#include "string.h"
#include "syscall.h"

extern char final_path[MAX_PATH_LEN];

static void convert_path(char *old_asb_path, char *new_abs_path) {
  assert(old_asb_path[0] == '/');

  char name_buf[MAX_FILE_NAME_LEN] = {0};
  char *sub_path = old_asb_path;
  sub_path = path_parse(old_asb_path, name_buf);

  if (name_buf[0] == 0) {
    new_abs_path[0] = '/';
    new_abs_path[1] = 0;
    return;
  }

  new_abs_path[0] = 0;
  strcat(new_abs_path, "/");
  while (name_buf[0] != 0) {
    if (!strcmp("..", name_buf)) {
      char *slash_ptr = strrchr(new_abs_path, '/');
      if (slash_ptr != new_abs_path) {
        *slash_ptr = 0;
      } else {
        *(slash_ptr + 1) = 0;
      }
    } else if (strcmp(".", name_buf)) {
      if (strcmp(new_abs_path, "/")) {
        strcat(new_abs_path, "/");
      }
      strcat(new_abs_path, name_buf);
    } else {
    }
    memset(name_buf, 0, MAX_FILE_NAME_LEN);
    if (sub_path) {
      sub_path = path_parse(sub_path, name_buf);
    }
  }
}


void make_clear_abs_path(char *path, char *final_path) {
  char abs_path[MAX_PATH_LEN] = {0};

  if (path[0] != '/') {
    memset(abs_path, 0, MAX_PATH_LEN);
    if (getcwd(abs_path, MAX_PATH_LEN) != NULL) {
      if (!((abs_path[0] == '/') && (abs_path[1] == 0))) {
        strcat(abs_path, "/");
      }
    }
  }
  strcat(abs_path, path);

  convert_path(abs_path, final_path);
}

void buildin_pwd(uint32_t argc, char **argv UNUSED) {
  if (argc != 1) {
    printf("pwd: too many arguments!\n");
    return;
  } else {
    if (getcwd(final_path, MAX_PATH_LEN) != NULL) {
      printf("%s\n", final_path);
    } else {
      printf("pwd: get current working directory failed\n");
    }
  }
}

char *buildin_cd(uint32_t argc, char **argv) {
  if (argc > 2) {
    printf("cd: too many arguments!\n");
    return NULL;
  }

  if (argc == 1) {
    final_path[0] = '/';
    final_path[1] = 0;
  } else {
    make_clear_abs_path(argv[1], final_path);
  }

  if (chdir(final_path) == -1) {
    printf("cd: no such directory: %s\n", final_path);
    return NULL;
  }
  return final_path;
}

void buildin_ls(uint32_t argc, char **argv) {
  char *pathname = NULL;
  struct stat file_stat;
  memset(&file_stat, 0, sizeof(struct stat));

  uint32_t arg_path_nr = 0;
  bool long_info = false;
  uint32_t arg_idx = 1;
  while (arg_idx < argc) {
    if (argv[arg_idx][0] == '-') {
      if (!strcmp(argv[arg_idx], "-l")) {
        long_info = true;
      } else if (!strcmp(argv[arg_idx], "--help")) {
        printf("Usage: ls [OPTION]... [FILE]...\nlist all files in the "
               "current directory if no option\n\n  -l            list all all "
               "information\n  --help        for help\n");
        return;
      } else {
        printf("ls: invalid option %s\nMore info with: 'ls --help'.\n",
               argv[arg_idx]);
        return;
      }
    } else {
      if (arg_path_nr == 0) {
        pathname = argv[arg_idx];
        arg_path_nr = 1;
      } else {
        printf("ls: too many arguments\n");
        return;
      }
    }
    arg_idx++;
  }

  if (pathname == NULL) {
    if (getcwd(final_path, MAX_PATH_LEN) != NULL) {
      pathname = final_path;
    } else {
      printf("ls: getcwd for default path failed\n");
      return;
    }
  } else {
    make_clear_abs_path(pathname, final_path);
    pathname = final_path;
  }

  if (stat(pathname, &file_stat) == -1) {
    printf("ls: Specified path '%s' doesn't exist.\n", pathname);
    return;
  }

  if (file_stat.st_filetype == FT_DIRECTORY) {
    struct dir *dir = opendir(pathname);
    struct dir_entry *dir_e = NULL;
    char sub_pathname[MAX_PATH_LEN] = {0};
    uint32_t pathname_len = strlen(pathname);
    uint32_t last_char_idx = pathname_len - 1;
    memcpy(sub_pathname, pathname, pathname_len);

    if (sub_pathname[last_char_idx] != '/') {
      sub_pathname[pathname_len] = '/';
      pathname_len++;
    }

    rewinddir(dir);

    if (long_info) {
      char f_type;
      printf("total: %d\n", file_stat.st_size);
      while ((dir_e = readdir(dir))) {
        f_type = 'd';
        if (dir_e->f_type == FT_REGULAR) {
          f_type = '-';
        }
        sub_pathname[pathname_len] = 0;
        strcat(sub_pathname, dir_e->filename);
        memset(&file_stat, 0, sizeof(struct stat));
        if (stat(sub_pathname, &file_stat) == -1) {
          printf("ls: Specified path '%s' doesn't exist.\n", dir_e->filename);
          return;
        }
        printf("%c %d %d %s\n", f_type, dir_e->i_NO, file_stat.st_size,
               dir_e->filename);
      }
    } else {
      while ((dir_e = readdir(dir))) {
        printf("%s ", dir_e->filename);
      }
      printf("\n");
    }
    closedir(dir);
  } else {
    if (long_info) {
      printf("- %d %d %s\n", file_stat.st_ino, file_stat.st_size, pathname);
    } else {
      printf("%s\n", pathname);
    }
  }
}

void buildin_ps(uint32_t argc, char **argv UNUSED) {
  if (argc != 1) {
    printf("ps: too many arguments\n");
    return;
  }
  ps();
}
void buildin_clear(uint32_t argc, char **argv UNUSED) {
  if (argc != 1) {
    printf("clear: too many arguments\n");
    return;
  }
  clear();
}

int32_t buildin_mkdir(uint32_t argc, char **argv) {
  int32_t ret_val = -1;
  if (argc != 2) {
    printf("mkdir: too many arguments\n");
  } else {
    make_clear_abs_path(argv[1], final_path);
    if (strcmp("/", final_path)) {
      if (mkdir(final_path) == 0) {
        ret_val = 0;
      } else {
        printf("mkdir: create directory %s failed.\n", argv[1]);
      }
    }
  }
  return ret_val;
}

int32_t buildin_rmdir(uint32_t argc, char **argv) {
  int32_t ret_val = -1;
  if (argc != 2) {
    printf("rmdir: too many arguments\n");
  } else {
    make_clear_abs_path(argv[1], final_path);
    if (strcmp("/", final_path)) {
      if (rmdir(final_path) == 0) {
        ret_val = 0;
      } else {
        printf("rmdir: remove directory %s failed.\n", argv[1]);
      }
    }
  }
  return ret_val;
}

int32_t buildin_rm(uint32_t argc, char **argv) {
  int32_t ret_val = -1;
  if (argc != 2) {
    printf("rm: too many arguments\n");
  } else {
    make_clear_abs_path(argv[1], final_path);
    if (strcmp("/", final_path)) {
      if (unlink(final_path) == 0) {
        ret_val = 0;
      } else {
        printf("rm: delete %s failed.\n", argv[1]);
      }
    }
  }
  return ret_val;
}
