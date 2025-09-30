#pragma once

void _execve_here(const char* pathname,
                  const char* const* argv,
                  const char* const* envp,
                  unsigned long* auxv,
                  void (*cb)(void*),
                  void* data);
void execve_here(const char* pathname,
                 const char* const* argv,
                 const char* const* envp,
                 void (*cb)(void*),
                 void* data);
void execve_thread(const char* pathname,
                   const char* const* argv,
                   const char* const* envp);
