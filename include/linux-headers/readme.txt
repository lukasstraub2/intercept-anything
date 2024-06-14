
Do not modify, the linux headers are installed from the linux kernel source
tree like this:

make headers_install ARCH=x86_64 INSTALL_HDR_PATH=/path/to/elf/src/include/linux-headers/x86_64
make headers_install ARCH=i386 INSTALL_HDR_PATH=/path/to/elf/src/include/linux-headers/i386
make headers_install ARCH=arm64 INSTALL_HDR_PATH=/path/to/elf/src/include/linux-headers/aarch64
make headers_install ARCH=arm INSTALL_HDR_PATH=/path/to/elf/src/include/linux-headers/arm
