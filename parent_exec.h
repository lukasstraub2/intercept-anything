#pragma once

#include "parent.h"

#include <spawn.h>

def_parent(int, execve, const char *pathname, char *const argv[], char *const envp[])
def_parent(int, execveat, int dirfd, const char *pathname, char *const argv[], char *const envp[], int flags)

def_parent(int, posix_spawn, pid_t *restrict pid, const char *restrict path,
                       const posix_spawn_file_actions_t *restrict file_actions,
                       const posix_spawnattr_t *restrict attrp,
                       char *const argv[restrict],
                       char *const envp[restrict])
def_parent(int, posix_spawnp, pid_t *restrict pid, const char *restrict file,
                       const posix_spawn_file_actions_t *restrict file_actions,
                       const posix_spawnattr_t *restrict attrp,
                       char *const argv[restrict],
                       char *const envp[restrict])
