cmake_minimum_required(VERSION 3.13)

project("intercept-anything"
    VERSION 1.0
    LANGUAGES C CXX
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

string(REPLACE "-DNDEBUG" "" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
string(REPLACE "-DNDEBUG" "" CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}")
string(REPLACE "-DNDEBUG" "" CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO}")
string(REPLACE "-DNDEBUG" "" CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO}")
string(REPLACE "-DNDEBUG" "" CMAKE_CXX_FLAGS_MINSIZEREL "${CMAKE_CXX_FLAGS_MINSIZEREL}")
string(REPLACE "-DNDEBUG" "" CMAKE_C_FLAGS_MINSIZEREL "${CMAKE_C_FLAGS_MINSIZEREL}")

add_subdirectory(libs/musl)

if(${CMAKE_SYSTEM_PROCESSOR} MATCHES "^aarch64.*|^armv8.*")
    set(ARCH "aarch64")
elseif(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64")
    set(ARCH "x86_64")
else()
    message(FATAL_ERROR "Architecture not supported: ${CMAKE_SYSTEM_PROCESSOR}")
endif()

include(CheckLinkerFlag)
check_linker_flag(CXX "-Wl,-Ttext-segment,0xA0000000" USE_TEXT_SEGMENT)
if(USE_TEXT_SEGMENT)
    set(TEXT_SEGMENT -Wl,-Ttext-segment,0xA0000000)
else()
    set(TEXT_SEGMENT -Wl,--image-base,0xA0000000)
endif()

check_linker_flag(CXX "-lgcc_eh" USE_LIBGCC_UNWIND)
if(USE_LIBGCC_UNWIND)
    set(LIBUNWIND -lgcc_eh)
else()
    set(LIBUNWIND -lunwind)
endif()

check_linker_flag(CXX "-lsupc++" USE_LIBSUPCXX)
if(USE_LIBSUPCXX)
    set(LIBSUPCXX -lsupc++)
else()
    set(LIBSUPCXX -lc++abi)
endif()

target_link_libraries(c INTERFACE -Wl,-z,muldefs "$<LINK_GROUP:RESCAN,libc,${LIBUNWIND}>")

include_directories(include include/nolibc)
add_compile_definitions(_GNU_SOURCE)
add_compile_options(-g -O1 -pipe -fPIE -Wno-shift-op-parentheses -fno-exceptions)

add_library(freestanding OBJECT
    loader.cpp mylock.cpp rmap.cpp tls.cpp intercept_seccomp.cpp syscalls_a.cpp syscalls_b.cpp syscalls_c.cpp syscalls_exec.cpp util.cpp signalmanager.cpp workarounds.cpp execve_here.cpp syscall_trampo.cpp cxxcompat.c)
target_link_libraries(freestanding PRIVATE c)
target_include_directories(freestanding PUBLIC "include/linux-headers/${ARCH}/include")

set(TOOLS_OBJS tools freestanding crt_pie)
add_library(tools INTERFACE)
target_link_libraries(tools INTERFACE -Wl,-z,relro,-z,now -static-pie c ${LIBSUPCXX})

add_library(loader_main OBJECT loader_main.cpp)
target_link_libraries(loader_main PRIVATE ${TOOLS_OBJS})

set(STATIC_TOOLS_OBJS static_tools ${TOOLS_OBJS} loader_main)
add_library(static_tools INTERFACE)
target_link_libraries(static_tools INTERFACE ${TEXT_SEGMENT} tools)

add_library(androidislinux_tool OBJECT
    androidislinux_tool/androidislinux.cpp
    androidislinux_tool/noxattrs.cpp
    androidislinux_tool/rootshim.cpp
    androidislinux_tool/hardlinkshim.cpp
    androidislinux_tool/rootlink.cpp)
target_link_libraries(androidislinux_tool PRIVATE ${TOOLS_OBJS})

add_executable(androidislinux androidislinux_tool/main.cpp)
target_link_libraries(androidislinux PUBLIC androidislinux_tool ${STATIC_TOOLS_OBJS})

add_executable(norootlink androidislinux_tool/norootlink.cpp)
target_link_libraries(norootlink PUBLIC androidislinux_tool ${STATIC_TOOLS_OBJS})

add_executable(emulate_swap
    emulate_swap_tool/emulate_swap.cpp
    emulate_swap_tool/emulate_swap_main.cpp)
target_link_libraries(emulate_swap PUBLIC ${STATIC_TOOLS_OBJS})

add_library(execve_thread_obj OBJECT libexecve_thread.cpp execve_here.cpp loader.cpp loader_open_stub.cpp)
target_compile_options(execve_thread_obj PUBLIC -fPIC)

add_library(execve_thread SHARED)
target_link_libraries(execve_thread PRIVATE execve_thread_obj Threads)

if(TARGET JNI)
    add_library(execve_thread_jni SHARED libexecve_thread_jni.cpp)
    target_link_libraries(execve_thread_jni PRIVATE execve_thread_obj Threads JNI)
endif()

add_library(stubs OBJECT stubs.cpp)

add_executable(mylock_test mylock_test.cpp)
target_link_libraries(mylock_test PRIVATE ${TOOLS_OBJS} stubs)

add_executable(rwlock_test rwlock_test.cpp)
target_link_libraries(rwlock_test PRIVATE ${TOOLS_OBJS} stubs)

add_executable(execve_here_test execve_here_test.cpp)
target_link_libraries(execve_here_test PRIVATE ${TOOLS_OBJS} stubs)

add_executable(execve_thread_test execve_thread_test.cpp)
target_link_libraries(execve_thread_test PRIVATE execve_thread)

add_executable(signal_tests signal_tests.c)

add_executable(libc_tls_test libc_tls_test.c libc_tls_test2.c)
target_link_libraries(libc_tls_test PRIVATE c -static-pie crt_pie)

add_executable(libc_tls_stresstest libc_tls_stresstest.c)
target_link_libraries(libc_tls_stresstest PRIVATE c -static-pie crt_pie)

add_executable(libc_external_thread_test libc_external_thread_test.c)
target_link_libraries(libc_external_thread_test PRIVATE c -static-pie crt_pie)

add_executable(tls_stresstest tls_stresstest.c)

add_executable(tls_thread_join_test tls_thread_join_test.c)

enable_testing()
add_test(NAME mylock_test COMMAND mylock_test)
add_test(NAME rwlock_test COMMAND rwlock_test)
add_test(NAME execve_here_test COMMAND execve_here_test)
add_test(NAME execve_thread_test COMMAND execve_thread_test)
add_test(NAME signal_tests COMMAND emulate_swap signal_tests)
add_test(NAME tls_stresstest COMMAND emulate_swap tls_stresstest)
add_test(NAME tls_thread_join_test COMMAND emulate_swap tls_thread_join_test)

add_test(NAME libc_tls_test COMMAND libc_tls_test)
add_test(NAME libc_tls_stresstest COMMAND libc_tls_stresstest)
add_test(NAME libc_external_thread_test COMMAND libc_external_thread_test)