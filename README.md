
为代表性的 crackme 总结相关知识点。一緒に頑張りましょう！

[TOC]

# 工具列表

|name|How to get|
|-|-|
|jadx|https://github.com/skylot/jadx/releases|
|Hopper|https://down.52pojie.cn/Tools/Disassemblers/|
|jeb|https://down.52pojie.cn/Tools/Android_Tools/|
|Ida|https://down.52pojie.cn/Tools/Disassemblers/|
|JD-GUI|https://github.com/java-decompiler/jd-gui/releases|
|ARM ⇌ Hex|http://armconverter.com/|
|010 Editor|https://down.52pojie.cn/Tools/Editors/|
|010 templates|http://www.sweetscape.com/010editor/templates/|
|Charles|https://down.52pojie.cn/Tools/Network_Analyzer/|
|aapt|in sdk build-tools|
|Google signapk|https://github.com/kiya-z/Android/tree/master/tools/signapk|
|xposed|http://repo.xposed.info/module/de.robv.android.xposed.installer|
|frida|https://www.frida.re/|
|Android Device Monitor|in sdk tools|
|gdb|in ndk toolchains (ndk <= r10)|
|gdbserver|in ndk prebuilt (ndk <= r10)|
|Android Studio|https://developer.android.com/studio|
|ShakaApktool|https://github.com/rover12421/ShakaApktool|
|smalidea|https://bitbucket.org/JesusFreke/smali/downloads/|
|smali|https://bitbucket.org/JesusFreke/smali/downloads/|
|baksmali|https://bitbucket.org/JesusFreke/smali/downloads/|
|axmlprinter|https://github.com/rednaga/axmlprinter/releases|
|javassist|https://github.com/jboss-javassist/javassist/releases|
|unluac|https://sourceforge.net/projects/unluac/|
|sqlcipher|https://github.com/sqlcipher/sqlcipher|
|android-backup-extractor|https://github.com/nelenkov/android-backup-extractor|


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

# [EasyRe.apk](https://github.com/kiya-z/android-reversing-challenges/tree/master/apks/EasyRe.apk)

## hook 系统函数

常规方法静态分析

## dump 内存搜索 flag

### 1. 利用 ddms 的 `dump HPROF file` 功能 (带箭头的油桶图标)

搜索：`strings easyre.sjl.gossip.easyre.hprof | grep 0ctf`

### 2. 利用 gore

gdb 附加进程后直接执行 `gcore` dump，搜索：`strings core.7967 | grep 0ctf`

# [Timer.apk](https://github.com/kiya-z/android-reversing-challenges/tree/master/apks/Timer.apk)

## 修改 smali 代码

指令参考这里👉[dalvik bytecode](https://source.android.com/devices/tech/dalvik/dalvik-bytecode)

# [LoopAndLoop.apk](https://github.com/kiya-z/android-reversing-challenges/tree/master/apks/LoopAndLoop.apk)

## ARM 的参数传递规则

R0、R1、R2、R3， 在调用函数时，用来存放前4个函数参数；如果函数的参数多于 4 个，则多余参数存放在堆栈当中；
低于32位的函数返回值存于 R0。

## ARM 的寄存器规则

|寄存器|作用|
|-|-|
|R0 ~ R3|调用函数时，用来存放前4个函数参数|
|R0|函数返回时，存放低于32位的函数返回值|
|R4 ~ R11|保存局部变量。进入函数时必须保存所用到的局部变量寄存器的值，在返回前必须恢复这些寄存器的值；对于函数中没有用到的寄存器则不必进行这些操作。<br>在Thumb中，通常只能使用寄存器 R4~R7来保存局部变量，<br>所以函数内部通用的入栈出栈代码可以为：<br>STMFD sp!,\{r4-r11,lr\}<br>// body of ASM code<br>LDMFD sp!,\{r4-r11,pc\}|
|R12|用作 IP，内部调用暂时寄存器|
|R13|用作 SP，栈指针，sp 中存放的值在退出被调用函数时必须与进入时的值相同。|
|R14|用作 LR，链接寄存器，保存函数的返回地址；如果在函数中保存了返回地址，寄存器R14 则可以用作其他用途|
|R15|用作 PC，程序计数器|
|R16|CPSR，状态寄存器|


# reference

[CTF-Mobile](https://github.com/toToCW/CTF-Mobile)

[write-ups-2015](https://github.com/ctfs/write-ups-2015)

[write-ups-2016](https://github.com/ctfs/write-ups-2016)

