
为代表性的 crackme 总结相关知识点。一緒に頑張りましょう！

[TOC]

# 工具列表

|function|name|How to get|
|-|-|-|
|apk 分析|jadx|https://github.com/skylot/jadx/releases|
|逆向工具|Hopper|https://down.52pojie.cn/Tools/Disassemblers/|
|逆向工具|jeb|https://down.52pojie.cn/Tools/Android_Tools/|
|逆向工具|Ida|https://down.52pojie.cn/Tools/Disassemblers/|
|逆向工具|radare2|https://github.com/radare/radare2|
|jar 包查看|JD-GUI|https://github.com/java-decompiler/jd-gui/releases|
|汇编字节码|ARM ⇌ Hex|http://armconverter.com/|
|汇编框架|keystone|http://www.keystone-engine.org/|
|二进制查看|010 Editor|https://down.52pojie.cn/Tools/Editors/|
|文件格式模板|010 templates|http://www.sweetscape.com/010editor/templates/|
|抓包|Charles|https://down.52pojie.cn/Tools/Network_Analyzer/|
|操作 apk|aapt|in sdk build-tools|
|apk 签名|Google signapk|https://github.com/kiya-z/Android/tree/master/tools/signapk|
|hook 框架|xposed|http://repo.xposed.info/module/de.robv.android.xposed.installer|
|hook 框架|frida|https://www.frida.re/|
|DDMS|Android Device Monitor|in sdk tools|
|gdb 调试|gdb|in ndk toolchains (ndk <= r10)|
|gdb 调试|gdbserver|in ndk prebuilt (ndk <= r10)|
|开发工具|Android Studio|https://developer.android.com/studio|
|反编译 apk|ShakaApktool|https://github.com/rover12421/ShakaApktool|
|调试 smali|smalidea|https://bitbucket.org/JesusFreke/smali/downloads/|
|smali -> dex|smali|https://bitbucket.org/JesusFreke/smali/downloads/|
|dex -> smali|baksmali|https://bitbucket.org/JesusFreke/smali/downloads/|
|解析 android manifest|axmlprinter|https://github.com/rednaga/axmlprinter/releases|
|帮助修改 java 字节码|javassist|https://github.com/jboss-javassist/javassist/releases|
|luac 反编译|unluac|https://sourceforge.net/projects/unluac/|
|sql 加解密|sqlcipher|https://github.com/sqlcipher/sqlcipher|
|ab 文件解压|android-backup-extractor|https://github.com/nelenkov/android-backup-extractor|
|llvm 混淆|o-llvm|https://github.com/obfuscator-llvm/obfuscator/|
|逆向框架|Miasm|https://github.com/cea-sec/miasm|
|符号执行|angr|https://github.com/angr/angr|
|符号执行|trigon|https://github.com/JonathanSalwan/Triton|
|二进制分析|barf|https://github.com/programa-stic/barf-project|

# [mobicrackNDK.apk](https://github.com/kiya-z/android-reversing-challenges/tree/master/apks/mobicrackNDK.apk)

>来自福建海峡两岸CTF 2015。

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

>来自 RCTF 2015。

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

>来自 0CTF 2015。

## hook 系统函数

常规方法静态分析

## dump 内存搜索 flag

### 1. 利用 ddms 的 `dump HPROF file` 功能 (带箭头的油桶图标)

搜索：`strings easyre.sjl.gossip.easyre.hprof | grep 0ctf`

### 2. 利用 gore

gdb 附加进程后直接执行 `gcore` dump，搜索：`strings core.7967 | grep 0ctf`

# [Timer.apk](https://github.com/kiya-z/android-reversing-challenges/tree/master/apks/Timer.apk)

>来自 AliCTF 2016。

## 修改 smali 代码

指令参考这里👉[dalvik bytecode](https://source.android.com/devices/tech/dalvik/dalvik-bytecode)

# [LoopAndLoop.apk](https://github.com/kiya-z/android-reversing-challenges/tree/master/apks/LoopAndLoop.apk)

>来自 AliCTF 2016。

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


# [KXCTF.apk](https://github.com/kiya-z/android-reversing-challenges/tree/master/apks/KXCTF.apk)

>来自 看雪CTF 2017。

## dex 校验

SHA1 值。

## 反调试

1. 读取 /proc/pid/status 的 State 是否为 t
2. 读取 /proc/pid/status 的 TracerPid 是否不为0
3. 读取 /proc/pid/wchan 是否有 ptrace_stop

## DES 加密

对称性加密，典型的 DES 以`64 位二进制为分组`对数据加密。
如果明文不是 64 位（16个16进制位）的整数倍，则加密前，这段文本必须`在尾部补充一些额外的字节`。
在运算时需要根据`特定的表格`以 64 位为单位对明文和秘钥分别进行`置换操作`。

## RC6 加密

对称性加密。主要操作是`异或和循环左移`。

```
// Encryption/Decryption with RC6-w/r/b
//
// Input:   Plaintext stored in four w-bit input registers A, B, C & D
//  r is the number of rounds
//  w-bit round keys S[0, ... , 2r + 3]
//
// Output: Ciphertext stored in A, B, C, D
//
// '''Encryption Procedure:'''

  B = B + S[0]
  D = D + S[1]
  for i = 1 to r do
  {
    t = (B*(2B + 1)) <<< lg w
    u = (D*(2D + 1)) <<< lg w
    A = ((A ⊕ t) <<< u) + S[2i]
    C = ((C ⊕ u) <<< t) + S[2i + 1]
                (A, B, C, D)  =  (B, C, D, A)
  }
  A = A + S[2r + 2]
  C = C + S[2r + 3]
```

# [rfchen.apk](https://github.com/kiya-z/android-reversing-challenges/tree/master/apks/rfchen.apk)

>来自 看雪CTF 2017。


## 花指令

本例中的花指令有以下几种：

```
B               loc_XXXX
```

```
PUSH            {R0,R4,R5,R7,LR}
SUB             SP, SP, #8
MOV             R2, R2
ADD             SP, SP, #8
ADD.W           R0, R0, #1
SUB.W           R0, R0, #1
MOV             R3, R3
POP.W           {R0,R4,R5,R7,LR}
ADD.W           R1, R1, #1
SUB.W           R1, R1, #1
```

```
PUSH.W          {R4-R10,LR}
POP.W           {R4-R10,LR}
```

去花即将规律的花指令 nop 掉并修复跳转，ida 中的去花脚本编写可参考 IDA 的 idc 或 idapython API。

为了使 IDA 识别某个函数X，需要在 Functions Window **统统删除**之前函数X中误将 junk code 识别为函数的垃圾函数，手动**设置函数X的结尾**（Edit - Functions - set function end）。

**函数尾部特征：**

1. `BLX   __stack_chk_fail`  -> 堆栈保护
2. `POP   {R4-R7,PC} (与函数头 PUSH {R4-R7,LR} 对应)`  -> 堆栈平衡

本例去花可参考：[1（ HideArea 方便分析）](http://bbs.pediy.com/thread-217889.htm)、[2（ NOP并修改跳转 ）](http://bbs.pediy.com/thread-218432.htm)

## RC4 加密

对称性加密。由`伪随机数生成器和异或运算`组成。密钥长度范围是[1,255]。
RC4一个字节一个字节地加解密。给定一个密钥，伪随机数生成器接受密钥并产生一个S盒。S盒用来加密数据，而且在加密过程中S盒会变化。

*伪代码：*

```
 for i from 0 to 255
     S[i] := i
 endfor
 j := 0
 for( i=0 ; i<256 ; i++)
     j := (j + S[i] + key[i mod keylength]) % 256
     swap values of S[i] and S[j]
 endfor

 i := 0
 j := 0
 while GeneratingOutput:
     i := (i + 1) mod 256   //a
     j := (j + S[i]) mod 256 //b
     swap values of S[i] and S[j]  //c
     k := inputByte ^ S[(S[i] + S[j]) % 256]
     output K
 endwhile
```

# [WantAShell.apk](https://github.com/kiya-z/android-reversing-challenges/tree/master/apks/WantAShell.apk)

>来自 LCTF 2016.

## SMC (self-modifying code) - 运行时自篡改代码

在自身应用中，Java 代码在被执行时权限为只读，SMC 只会发生在 NDK 层。一般步骤如下：

1. 通过搜索 DEX 特征码来找到 DEX 的起始地址；
2. 解析 dex 格式定位到具体的类以及方法，找到要修改的 dalvik 字节码；
3. 重新映射内存段，修改内存。

**对于本例**：(只对 dalvik 有效)

读取 self maps 文件找到 odex 的内存地址 -> 解析dex -> 遍历 classDefs 找到两个函数地址 -> mprotect 修改内存属性 -> 函数替换 -> 将内存属性改回。

>论文参考：**《基于 SMC 的 Android 软件保护研究与实现》**

# [AN.apk](https://github.com/kiya-z/android-reversing-challenges/tree/master/apks/AN.apk)

>来自 NJCTF 2017.

## NativeActivity

NativeActivity 是 android SDK 自带的一个 activity，本例将其作为主 activity，使得 dex 中没有 Java 代码。

NativeActivity 所在的 so 在 manifest 中有注册，固定格式：

```
<meta-data android:name="android.app.lib_name" android:value="SONAME" />
```

入口函数是 `android_main()`。可以这样找到它：

1. 函数 `ANativeActivity_onCreate`
2. `j_j_pthread_create((pthread_t *)v4 + 20, &attr, (void *(*)(void *))sub_XXX, v4);`
3. 进入 sub_XXX ，即可看到 `android_main(v1);`

关于 NativeActivity 原理，参考[这里](http://blog.csdn.net/ldpxxx/article/details/9253369)。

## ollvm

# reference

[CTF-Mobile](https://github.com/toToCW/CTF-Mobile)

[write-ups-2015](https://github.com/ctfs/write-ups-2015)

[write-ups-2016](https://github.com/ctfs/write-ups-2016)

[看雪论坛](http://bbs.pediy.com/)

