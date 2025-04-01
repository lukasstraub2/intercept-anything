cmake_minimum_required(VERSION 3.13)

project("intercept-anything"
    VERSION 1.0
    LANGUAGES C ASM
    HOMEPAGE_URL "https://github.com/lukasstraub2/intercept-anything")

if(${CMAKE_SYSTEM_NAME} STREQUAL "Android")
    add_library(Threads INTERFACE)
    add_library(JNI INTERFACE)
else()
    set(THREADS_PREFER_PTHREAD_FLAG ON)
    include(FindThreads)
    if(TARGET Threads::Threads)
        add_library(Threads ALIAS Threads::Threads)
    endif()

    set(JAVA_AWT_LIBRARY NotNeeded)
    set(JAVA_JVM_LIBRARY NotNeeded)
    set(JAVA_AWT_INCLUDE_PATH NotNeeded)
    include(FindJNI)
    if(TARGET JNI::JNI)
        add_library(JNI ALIAS JNI::JNI)
    endif()
endif()

include(CheckCCompilerFlag)

if(${CMAKE_SYSTEM_PROCESSOR} MATCHES "^aarch64.*|^armv8.*")
    set(ARCH "aarch64")
elseif(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64")
    set(ARCH "x86_64")
else()
    message(FATAL_ERROR "Architecture not supported: ${CMAKE_SYSTEM_PROCESSOR}")
endif()

check_c_compiler_flag(-lgcc USE_LIBGCC)
if(${USE_LIBGCC})
    set(LIBGCC -lgcc)
else()
    set(LIBGCC -lcompiler_rt)
endif()

add_compile_options(-g -O1 -pipe -Wall -Wextra -Wno-unused-parameter -fno-stack-protector)
set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
include_directories(include)
set_property(GLOBAL PROPERTY C_STANDARD 11)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(FREESTANDING_CFLAGS -nostdinc)
set(FREESTANDING_LDFLAGS -nostartfiles -nodefaultlibs -nostdlib ${LIBGCC})
set(FREESTANDING_INCLUDE include/nolibc "include/linux-headers/${ARCH}/include")

add_library(freestanding STATIC
    loader.c mylock.c rmap.c tls.c intercept_seccomp.c util.c signalmanager.c workarounds.c execve_here.c stubs.c)
target_compile_options(freestanding PRIVATE ${FREESTANDING_CFLAGS})
target_include_directories(freestanding PRIVATE ${FREESTANDING_INCLUDE})

add_library(tools INTERFACE)
target_compile_options(tools INTERFACE ${FREESTANDING_CFLAGS})
target_include_directories(tools INTERFACE ${FREESTANDING_INCLUDE})
target_link_libraries(tools INTERFACE ${FREESTANDING_LDFLAGS})
target_link_libraries(tools INTERFACE freestanding)

add_library(static_tools STATIC loader_main.c)
target_link_libraries(static_tools PUBLIC -Wl,--no-relax -Wl,-Ttext-segment,0xA0000000 -static)
target_link_libraries(static_tools PUBLIC tools)

add_library(androidislinux_tools STATIC
    androidislinux_tool/androidislinux.c
    androidislinux_tool/noxattrs.c
    androidislinux_tool/rootshim.c
    androidislinux_tool/hardlinkshim.c
    androidislinux_tool/rootlink.c)
target_link_libraries(androidislinux_tools PUBLIC static_tools)

add_executable(androidislinux androidislinux_tool/main.c)
target_link_libraries(androidislinux PUBLIC androidislinux_tools)

add_executable(norootlink androidislinux_tool/norootlink.c)
target_link_libraries(norootlink PUBLIC androidislinux_tools)

add_executable(emulate_swap
    emulate_swap_tool/emulate_swap.c
    emulate_swap_tool/emulate_swap_main.c)
target_link_libraries(emulate_swap PUBLIC static_tools)

add_library(execve_thread SHARED libexecve_thread.c)
target_link_libraries(execve_thread PRIVATE freestanding Threads)

if(TARGET JNI)
    add_library(execve_thread_jni SHARED libexecve_thread.c libexecve_thread_jni.c)
    target_link_libraries(execve_thread_jni PRIVATE freestanding Threads JNI)
endif()

add_executable(mylock_test mylock_test.c)
target_link_libraries(mylock_test PRIVATE tools)

add_executable(rwlock_test rwlock_test.c)
target_link_libraries(rwlock_test PRIVATE tools)

add_executable(execve_here_test execve_here_test.c)
target_link_libraries(execve_here_test PRIVATE tools)

add_executable(execve_thread_test execve_thread_test.c)
target_link_libraries(execve_thread_test PRIVATE execve_thread)

enable_testing()
add_test(NAME mylock_test COMMAND mylock_test)
add_test(NAME rwlock_test COMMAND rwlock_test)
add_test(NAME execve_here_test COMMAND execve_here_test)
add_test(NAME execve_thread_test COMMAND execve_thread_test)
