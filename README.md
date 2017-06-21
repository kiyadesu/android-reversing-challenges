
为代表性的 crackme 总结相关知识点。
一緒に頑張りましょう！

[TOC]

# [mobicrackNDK.apk](https://github.com/kiya-z/android-reversing-challenges/tree/master/apks/mobicrackNDK.apk)

## JNI_Onload 中通过 RegisterNatives 动态注册 jni 函数

**相关函数**：

```
signed int __fastcall JNI_OnLoad(_JavaVM *a1)

((int (__fastcall *)(_JavaVM *, _JNIEnv **, signed int))v1->functions->GetEnv)(v1, &v8, 65540)  
    /*  v1:JavaVM  v8:JniEnv  65540:jni version */

((int (__fastcall *)(_JNIEnv *, char *))v3->functions->FindClass)(v3, v4)   
    /*  v3:JNIEnv  v4:类名    */

((int (__fastcall *)(_JNIEnv *, int, char **, signed int))v3->functions->RegisterNatives)(v3, v5, off_400C, 2)
    /*  v3:JniEnv  v5:FindClass得到的jclass对象  off_400C:要注册的methods  2:注册的methods个数
        method的格式为：函数名 函数描述(smali格式) 函数指针
        例如(in ida)：
            DCD aHello              ; "hello"
            DCD aLjavaLangStr_1     ; "()Ljava/lang/String;"
            DCD native_hello+1
    */
```

## .init_array

根据 linker 源码, section 的执行顺序为 `.preinit_array` -> `.init` -> `.init_array` 。但 so 是不会执行 `.preinit_array` 的, 可以忽略。

`.init_array` 是一个函数指针数组。编写代码时在函数声明时加上 `__attribute__((constructor))` 使之成为共享构造函数，即可使该函数出现在 `.init_array` section 中。

IDA 动态调试时 'ctrl+s' 查看 section 信息即可定位这两个 setction，特别的，对于 `.init_array`，可通过搜索 `Calling %s @ %p for '%s'` 定位。

**部分源码**:

```
void soinfo::CallConstructors() {
    ...
    // DT_INIT should be called before DT_INIT_ARRAY if both are present.
    CallFunction("DT_INIT", init_func);
    CallArray("DT_INIT_ARRAY", init_array, init_array_count, false);    // CallArray 中也会调用 CallFunction 函数
}

void soinfo::CallFunction(const char* function_name UNUSED, linker_function_t function) {
  if (function == NULL || reinterpret_cast<uintptr_t>(function) == static_cast<uintptr_t>(-1)) {
    return;
  }

  TRACE("[ Calling %s @ %p for '%s' ]", function_name, function, name);
  function();
  TRACE("[ Done calling %s @ %p for '%s' ]", function_name, function, name);

  // The function may have called dlopen(3) or dlclose(3), so we need to ensure our data structures
  // are still writable. This happens with our debug malloc (see http://b/7941716).
  set_soinfo_pool_protection(PROT_READ | PROT_WRITE);
}
```

# [misc.apk](https://github.com/kiya-z/android-reversing-challenges/tree/master/apks/misc.apk)

## dex 结构（修复dex）

快速简记：

|结构|单位结构体占字节|共计字节|
|---|---|---|
|DexHeader|-|0x70h|
|String Table|4|-|
|Type Table|4|-|
|Proto Table|12|-|
|Field Table|8|-|
|Method Table|8|-|
|Class Def Table|32|-|
|Data Section(含Map Section)|-|-|

# [simple.apk](https://github.com/kiya-z/android-reversing-challenges/tree/master/apks/simple.apk)

## hook 系统函数

常规方法静态分析

## dump 内存搜索 flag

### 1. 利用 ddms 的 `dump HPROF file` 功能 (带箭头的油桶图标)

搜索：`strings easyre.sjl.gossip.easyre.hprof | grep 0ctf`

### 2. 利用 gore

gdb 附加进程后直接执行 `gcore` dump，搜索：`strings core.7967 | grep 0ctf`


# reference

[CTF-Mobile](https://github.com/toToCW/CTF-Mobile)
[write-ups-2015](https://github.com/ctfs/write-ups-2015)


