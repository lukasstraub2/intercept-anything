#pragma once

void _execve_here(const char* pathname,
                  char** argv,
                  char** envp,
                  unsigned long* auxv,
                  void (*cb)(void*),
                  void* data);
void execve_here(const char* pathname,
                 char** argv,
                 char** envp,
                 void (*cb)(void*),
                 void* data);
void execve_thread(const char* pathname, char** argv, char** envp);