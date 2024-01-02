project(kernel)


# for each .c, add custom  command

file(GLOB_RECURSE SOURCES *.c)

set(TARGETS)

foreach(SRC ${SOURCES})
      get_filename_component(SRC_NAME ${SRC} NAME_WE)
      add_custom_command(OUTPUT ${SRC_NAME}.o
      COMMAND clang -g -I${CMAKE_CURRENT_SOURCE_DIR} -I/usr/include/x86_64-linux-gnu/ -O3 -target bpf -c ${CMAKE_CURRENT_SOURCE_DIR}/${SRC_NAME}.c -o ${SRC_NAME}.o  -fsave-optimization-record -mllvm -enable-load-pre=false
            #-Wall
            #-Wno-unused-value
            #-Wno-pointer-sign
            #-Wno-compare-distinct-pointer-types
            #-Werror
      DEPENDS ${SRC_NAME}.c)
      add_custom_command(OUTPUT ${SRC_NAME}.l
      COMMAND clang -emit-llvm -S -g -I${CMAKE_CURRENT_SOURCE_DIR} -I/usr/include/x86_64-linux-gnu/ -O3 -target bpf -c ${CMAKE_CURRENT_SOURCE_DIR}/${SRC_NAME}.c -o ${SRC_NAME}.l -mllvm -enable-load-pre=false
            #-Wall
            #-Wno-unused-value
            #-Wno-pointer-sign
            #-Wno-compare-distinct-pointer-types
            #-Werror
      DEPENDS ${SRC_NAME}.c)
      add_custom_command(OUTPUT ${SRC_NAME}.s
      COMMAND clang -S -g -I${CMAKE_CURRENT_SOURCE_DIR} -I/usr/include/x86_64-linux-gnu/ -O3 -target bpf -c ${CMAKE_CURRENT_SOURCE_DIR}/${SRC_NAME}.c -o ${SRC_NAME}.s -mllvm -enable-load-pre=false
            #-Wall
            #-Wno-unused-value
            #-Wno-pointer-sign
            #-Wno-compare-distinct-pointer-types
            #-Werror
      DEPENDS ${SRC_NAME}.c)
      list(APPEND TARGETS ${SRC_NAME}.o)
      list(APPEND TARGETS ${SRC_NAME}.l)
      list(APPEND TARGETS ${SRC_NAME}.s)
endforeach()


add_custom_target(build_bpf ALL DEPENDS ${TARGETS})






#add_custom_target(build_bpf_program ALL DEPENDS kernel.o univ_opt.o univ_opt.s univ_opt.l)