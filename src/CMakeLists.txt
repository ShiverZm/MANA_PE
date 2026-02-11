# 包含目录
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# 收集库源文件（排除 main.cpp）
file(GLOB LIB_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/*.h"
)

# 从库源文件中排除 main.cpp
list(FILTER LIB_SOURCES EXCLUDE REGEX "main\\.cpp$")

# 创建静态库
add_library(mana_pe_lib STATIC ${LIB_SOURCES})

# 设置库的编译选项
if(MSVC)
    target_compile_options(mana_pe_lib PRIVATE
        /W4           # 警告级别 4
        /WX-          # 不将警告视为错误
        /permissive-  # 符合标准模式
    )
else()
    target_compile_options(mana_pe_lib PRIVATE
        -Wall
        -Wextra
        -Wpedantic
    )
endif()

# 创建可执行文件
add_executable(${PROJECT_NAME} main.cpp)

# 链接库到可执行文件
target_link_libraries(${PROJECT_NAME} PRIVATE mana_pe_lib)

# 设置可执行文件的编译选项
if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE
        /W4           # 警告级别 4
        /WX-          # 不将警告视为错误
        /permissive-  # 符合标准模式
    )
else()
    target_compile_options(${PROJECT_NAME} PRIVATE
        -Wall
        -Wextra
        -Wpedantic
    )
endif()

# Windows 特定链接库
if(WIN32)
    # Windows API 库（通常不需要显式链接）
    # 如果需要特定库，可以在这里添加
endif()

# 安装规则
install(TARGETS ${PROJECT_NAME} mana_pe_lib
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

