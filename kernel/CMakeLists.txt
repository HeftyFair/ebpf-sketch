project(kernel)



add_custom_command(OUTPUT kernel.o
                   COMMAND clang -g -I${CMAKE_CURRENT_SOURCE_DIR} -I/usr/include/x86_64-linux-gnu/ -O2 -target bpf -c ${CMAKE_CURRENT_SOURCE_DIR}/main.c -o kernel.o
                         #-Wall
                         #-Wno-unused-value
                         #-Wno-pointer-sign
                         #-Wno-compare-distinct-pointer-types
                         #-Werror
                   DEPENDS main.c murmur3.h)


add_custom_target(build_bpf_program ALL DEPENDS kernel.o)