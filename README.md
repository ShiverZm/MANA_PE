# MANA_PE

一个用于解析和分析 Windows PE (Portable Executable) 文件格式的 C++ 库。

## 项目简介

MANA_PE 是一个功能完整的 PE 文件解析库，可以解析和分析 Windows 可执行文件的各种结构，包括：

- DOS 头
- PE 头
- 可选头（Image Optional Header）
- 节表（Section Table）
- 导入表（Import Table）
- 延迟导入表（Delayed Import Table）
- 导出表（Export Table）
- 资源表（Resource Table）
- 调试信息（Debug Information）
- 重定位表（Relocation Table）
- TLS（Thread Local Storage）
- 加载配置（Load Configuration）
- 证书（Certificates）

## 功能特性

- ✅ 完整的 PE 文件结构解析
- ✅ 支持 x86 和 x64 架构
- ✅ 灵活的解析选项（可按需解析特定部分）
- ✅ 资源提取和分析
- ✅ 导入/导出函数列表
- ✅ UTF-8 编码支持
- ✅ 易于使用的 C++ API

## 系统要求

- **操作系统**: Windows（Windows 7 或更高版本）
- **编译器**: 
  - MSVC 2015 或更高版本
  - MinGW-w64
  - 或其他支持 C++11 的编译器
- **CMake**: 3.10 或更高版本
- **C++ 标准**: C++11

## 构建说明

### 使用 CMake 构建

1. **创建构建目录**：
   ```bash
   mkdir build
   cd build
   ```

2. **配置项目**：
   ```bash
   cmake ..
   ```
   
   或者指定生成器（Visual Studio）：
   ```bash
   cmake -G "Visual Studio 16 2019" ..
   ```

3. **编译项目**：
   ```bash
   cmake --build . --config Release
   ```
   
   或者使用 Visual Studio：
   ```bash
   cmake --build . --config Debug
   ```

4. **运行程序**：
   ```bash
   bin\MANA_PE.exe
   ```

### 构建产物说明

构建完成后，会在以下目录生成文件：

- **可执行文件**: `build/bin/MANA_PE.exe` - 主程序
- **静态库**: `build/lib/mana_pe_lib.lib` - PE 解析库（可在其他项目中使用）

### 使用 Visual Studio

1. 打开 Visual Studio
2. 选择 "打开文件夹" 或 "打开 CMake 项目"
3. 选择项目根目录
4. Visual Studio 会自动检测 CMakeLists.txt 并配置项目
5. 按 F5 运行或 Ctrl+Shift+B 构建

## 使用示例

```cpp
#include "mana_pe.h"
#include "resources.h"

int main() {
    // 创建 PE 解析器实例
    mana::MANA_PE_EXT win_pe;
    
    // 指定要解析的 PE 文件路径
    std::wstring file_path = L"path/to/your/file.exe";
    
    // 解析 PE 文件（指定要解析的部分）
    if (!win_pe.parse_pe(file_path,
                         MANA_PE_PARSE_DOS_HEADER | 
                         MANA_PE_PARSE_PE_HEADER |
                         MANA_PE_PARSE_IO_HEADER |
                         MANA_PE_PARSE_SECTION_TABLE |
                         MANA_PE_PARSE_IMPORTS | 
                         MANA_PE_PARSE_RESOURCES)) {
        // 解析失败，检查错误信息
        std::cout << "Error: " << win_pe.get_err_string() << std::endl;
        return 1;
    }
    
    // 获取 PE 头信息
    mana::pe_header pe_header = win_pe.get_pe_header();
    
    // 获取导入表
    std::vector<mana::image_import_descriptor> imports = win_pe.get_imports();
    
    // 获取资源列表
    std::vector<mana::Resource> resources = win_pe.get_resources();
    
    // 遍历资源
    for (const auto& resource : resources) {
        if (resource.get_type() == "RT_MANIFEST") {
            printf("Found manifest resource, ID: %u\n", resource.get_id());
        }
    }
    
    return 0;
}
```

## 解析选项

可以使用以下标志来控制解析哪些部分：

- `MANA_PE_PARSE_DOS_HEADER` - 解析 DOS 头
- `MANA_PE_PARSE_PE_HEADER` - 解析 PE 头
- `MANA_PE_PARSE_IO_HEADER` - 解析可选头
- `MANA_PE_PARSE_SECTION_TABLE` - 解析节表
- `MANA_PE_PARSE_IMPORTS` - 解析导入表
- `MANA_PE_PARSE_DELAYED_IMPORTS` - 解析延迟导入表
- `MANA_PE_PARSE_EXPORTS` - 解析导出表
- `MANA_PE_PARSE_RESOURCES` - 解析资源表
- `MANA_PE_PARSE_DEBUG` - 解析调试信息
- `MANA_PE_PARSE_RELOCATIONS` - 解析重定位表
- `MANA_PE_PARSE_TLS` - 解析 TLS
- `MANA_PE_PARSE_CONFIG` - 解析加载配置
- `MANA_PE_PARSE_CERTIFICATES` - 解析证书
- `MANA_PE_PARSE_ALL` - 解析所有部分

可以组合多个标志使用位或运算符（`|`）。

## 项目结构

```
MANA_PE/
├── CMakeLists.txt          # 根目录 CMake 配置文件（项目配置）
├── README.md               # 项目说明文档
└── src/                    # 源代码目录
    ├── CMakeLists.txt      # 源代码目录 CMake 配置（构建逻辑）
    ├── main.cpp            # 主程序入口
    ├── mana_pe.h/cpp       # PE 解析器核心类
    ├── PE_structs.h        # PE 结构定义
    ├── imports.h/cpp       # 导入表处理
    ├── resources.h/cpp     # 资源处理
    ├── pe_dump.h/cpp       # PE 转储功能
    ├── pe_utils.cpp        # PE 工具函数
    ├── nt_values.h/cpp     # NT 值定义和转换
    ├── utils.h             # 通用工具函数
    ├── utf8.h              # UTF-8 编码支持
    ├── core.h              # 核心工具
    └── checked.h           # 检查工具
```

### 构建产物

项目构建后会生成以下产物：

- **静态库**: `lib/mana_pe_lib.lib` (Windows) 或 `lib/libmana_pe_lib.a` (Unix)
- **可执行文件**: `bin/MANA_PE.exe` (Windows) 或 `bin/MANA_PE` (Unix)

## API 文档

### MANA_PE 类

主要的 PE 解析类，提供以下主要方法：

- `parse_pe(path, flags)` - 解析 PE 文件
- `get_dos_header()` - 获取 DOS 头
- `get_pe_header()` - 获取 PE 头
- `get_image_optional_header()` - 获取可选头
- `get_sections()` - 获取节表
- `get_imports()` - 获取导入表
- `get_exports()` - 获取导出表
- `get_resources()` - 获取资源列表
- `get_architecture()` - 获取架构（x86/x64）
- `get_err_string()` - 获取错误信息

### MANA_PE_EXT 类

扩展的 PE 解析类，继承自 `MANA_PE`，提供更灵活的解析接口。

## 作为库使用

本项目构建后会生成静态库 `mana_pe_lib`，可以在其他 CMake 项目中使用：

### 在其他 CMake 项目中使用

1. **将 MANA_PE 作为子模块添加到你的项目**：
   ```cmake
   add_subdirectory(path/to/MANA_PE)
   ```

2. **链接库到你的目标**：
   ```cmake
   target_link_libraries(your_target PRIVATE mana_pe_lib)
   ```

3. **包含头文件**：
   ```cpp
   #include "mana_pe.h"
   #include "resources.h"
   // 其他需要的头文件
   ```

### 手动集成

如果不想使用 CMake，也可以手动链接：

1. 将 `src/` 目录下的所有 `.h` 和 `.cpp` 文件（除 `main.cpp` 外）添加到你的项目
2. 将 `src/` 目录添加到包含路径
3. 链接生成的静态库文件

## 贡献

欢迎提交 Issue 和 Pull Request！

## 更新日志

### Version 1.0.0
- 初始版本
- 支持基本的 PE 文件解析功能
- 支持导入表、导出表、资源表等解析
- 模块化 CMake 项目结构（库和可执行文件分离）

