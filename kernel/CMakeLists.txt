project(kernel)


# for each .c, add custom  command

file(GLOB_RECURSE SOURCES *.c)

set(TARGETS)

foreach(SRC ${SOURCES})
      get_filename_component(SRC_NAME ${SRC} NAME_WE)
      add_custom_command(OUTPUT ${SRC_NAME}.o
      COMMAND clang -g -I${CMAKE_CURRENT_SOURCE_DIR} -I/usr/include/x86_64-linux-gnu/ -O2 -target bpf -c ${CMAKE_CURRENT_SOURCE_DIR}/${SRC_NAME}.c -o ${SRC_NAME}.o  -fsave-optimization-record -mllvm -enable-load-pre=false 
            #-Wall
            #-Wno-unused-value
            #-Wno-pointer-sign
            #-Wno-compare-distinct-pointer-types
            #-Werror
      DEPENDS ${SRC_NAME}.c)
      list(APPEND TARGETS ${SRC_NAME}.o)
endforeach()


add_custom_target(build_bpf ALL DEPENDS ${TARGETS})



add_custom_command(OUTPUT kernel
                   COMMAND clang -g -I${CMAKE_CURRENT_SOURCE_DIR} -I/usr/include/x86_64-linux-gnu/ -O2 -target bpf -c ${CMAKE_CURRENT_SOURCE_DIR}/main.c -o kernel.o 

                         #-Wall
                         #-Wno-unused-value
                         #-Wno-pointer-sign
                         #-Wno-compare-distinct-pointer-types
                         #-Werror
                   DEPENDS main.c)


add_custom_command(OUTPUT univ_opt
                  COMMAND clang -g -I${CMAKE_CURRENT_SOURCE_DIR} -I/usr/include/x86_64-linux-gnu/ -O2 -target bpf -c ${CMAKE_CURRENT_SOURCE_DIR}/univ_opt.c -o univ_opt.o -fsave-optimization-record -mllvm -enable-load-pre=false
                        #-Wall
                        #-Wno-unused-value
                        #-Wno-pointer-sign
                        #-Wno-compare-distinct-pointer-types
                        #-Werror
                  DEPENDS univ_opt.c)

add_custom_command(OUTPUT univ_opt.s
                  COMMAND clang -g -I${CMAKE_CURRENT_SOURCE_DIR} -I/usr/include/x86_64-linux-gnu/ -O2 -target bpf -c ${CMAKE_CURRENT_SOURCE_DIR}/univ_opt.c -S -o univ_opt.s
                  #-Wall
                  #-Wno-unused-value
                  #-Wno-pointer-sign
                  #-Wno-compare-distinct-pointer-types
                  #-Werror
                  DEPENDS univ_opt.c)

add_custom_command(OUTPUT univ_opt.l
                  COMMAND clang -g -I${CMAKE_CURRENT_SOURCE_DIR} -I/usr/include/x86_64-linux-gnu/ -O2 -target bpf -c ${CMAKE_CURRENT_SOURCE_DIR}/univ_opt.c -S -emit-llvm -o univ_opt.l
                  #-Wall
                  #-Wno-unused-value
                  #-Wno-pointer-sign
                  #-Wno-compare-distinct-pointer-types
                  #-Werror
                  DEPENDS univ_opt.c)


#add_custom_target(build_bpf_program ALL DEPENDS kernel.o univ_opt.o univ_opt.s univ_opt.l)