cmake_minimum_required(VERSION 3.13)

project("intercept-anything"
    VERSION 1.0
    LANGUAGES CXX
    HOMEPAGE_URL "https://github.com/lukasstraub2/intercept-anything")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

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

add_subdirectory(libs/musl)

if(${CMAKE_SYSTEM_PROCESSOR} MATCHES "^aarch64.*|^armv8.*")
    set(ARCH "aarch64")
elseif(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64")
    set(ARCH "x86_64")
else()
    message(FATAL_ERROR "Architecture not supported: ${CMAKE_SYSTEM_PROCESSOR}")
endif()

set(FREESTANDING_CFLAGS -nostdinc)
set(FREESTANDING_LDFLAGS -nostartfiles -nodefaultlibs -nostdlib ${LIBGCC})
set(FREESTANDING_INCLUDE include/nolibc "include/linux-headers/${ARCH}/include")

include_directories(include include/nolibc "include/linux-headers/${ARCH}/include")
add_compile_definitions(_GNU_SOURCE)
add_compile_options(-O1 -pipe -fPIE)

add_library(freestanding OBJECT
    loader.cpp mylock.cpp rmap.cpp tls.cpp intercept_seccomp.cpp util.cpp signalmanager.cpp workarounds.cpp execve_here.cpp)
target_link_libraries(freestanding PRIVATE c)

set(TOOLS_OBJS tools freestanding)
add_library(tools INTERFACE)
target_link_libraries(tools INTERFACE c)

add_library(loader_main OBJECT loader_main.cpp)
target_link_libraries(loader_main PRIVATE tools)

set(STATIC_TOOLS_OBJS static_tools ${TOOLS_OBJS} loader_main crt_pie)
add_library(static_tools INTERFACE)
target_link_libraries(static_tools INTERFACE -Wl,-z,relro,-z,now -Wl,-Ttext-segment,0xA0000000 -static-pie)
target_link_libraries(static_tools INTERFACE tools)

add_library(androidislinux_tool OBJECT
    androidislinux_tool/androidislinux.cpp
    androidislinux_tool/noxattrs.cpp
    androidislinux_tool/rootshim.cpp
    androidislinux_tool/hardlinkshim.cpp
    androidislinux_tool/rootlink.cpp)
target_link_libraries(androidislinux_tool PRIVATE tools)

add_executable(androidislinux androidislinux_tool/main.cpp)
target_link_libraries(androidislinux PUBLIC androidislinux_tool ${STATIC_TOOLS_OBJS})

add_executable(norootlink androidislinux_tool/norootlink.cpp)
target_link_libraries(norootlink PUBLIC androidislinux_tool ${STATIC_TOOLS_OBJS})

add_executable(emulate_swap
    emulate_swap_tool/emulate_swap.cpp
    emulate_swap_tool/emulate_swap_main.cpp)
target_link_libraries(emulate_swap PUBLIC ${STATIC_TOOLS_OBJS})

add_library(execve_thread SHARED libexecve_thread.cpp stubs.cpp)
target_link_libraries(execve_thread PRIVATE freestanding Threads)

if(TARGET JNI)
    add_library(execve_thread_jni SHARED libexecve_thread.cpp libexecve_thread_jni.cpp stubs.cpp)
    target_link_libraries(execve_thread_jni PRIVATE freestanding Threads JNI)
endif()

add_executable(mylock_test mylock_test.cpp stubs.cpp)
target_link_libraries(mylock_test PRIVATE ${TOOLS_OBJS})

add_executable(rwlock_test rwlock_test.cpp stubs.cpp)
target_link_libraries(rwlock_test PRIVATE ${TOOLS_OBJS})

add_executable(execve_here_test execve_here_test.cpp stubs.cpp)
target_link_libraries(execve_here_test PRIVATE ${TOOLS_OBJS})

add_executable(execve_thread_test execve_thread_test.cpp)
target_link_libraries(execve_thread_test PRIVATE execve_thread)

enable_testing()
add_test(NAME mylock_test COMMAND mylock_test)
add_test(NAME rwlock_test COMMAND rwlock_test)
add_test(NAME execve_here_test COMMAND execve_here_test)
add_test(NAME execve_thread_test COMMAND execve_thread_test)
