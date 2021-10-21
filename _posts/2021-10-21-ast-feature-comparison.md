---
title: Decompiled code matching via AST features
author: Fernando Dominguez
date: 2021-10-21 18:00:00 +0200
categories: [analysis, r2diaphora]
tags: [r2diaphora, bindiff, code-parsing, radare2]
---

This article is about a particular function matching technique implemented in [diaphora](https://github.com/joxeankoret/diaphora) and how it was ported to [r2diaphora](https://github.com/FernandoDoming/r2diaphora).

## Initial problem

Matching decompiled pseudocode can be tricky, as decompilers can output seemingly very different code that in fact is functionally identical. As an example, take the following function in 2 different binaries:

||SHA256|Type|
|---|----|----|
|File 1|`17c62e0cf77dc4341809afceb1c8395d67ca75b2a2c020bddf39cca629222161`|ELF 32-bit LSB executable, ARM, EABI4 version 1 (SYSV)|
|File 2|`6ce1739788b286cc539a9f24ef8c6488e11f42606189a7aa267742db90f7b18d`|ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV)|

![r2diaphora output - Pseudocode diff detail](/assets/img/blog/r2ghidra-diff.png)

The above screenshot is part of the results that r2diaphora generated when comparing the aforementioned files. The decompiled code was obtained by using r2ghidra.

It is easy to note that the function `getPortz` is present in both files. The function match was generated due to both functions referencing the same constants (for some reason the left pseudocode could not resolve the string pointers passed to `access()`, however, r2diaphora did resolve them correctly and generated a match based on those strings).

If we, however, take a look at the r2ghidra decompiler output we can see how they are quite different. This is to be expected as decompiler output meant to aid reverse engineering, not to be consistent across different files. In this case the decompiler generated diffent variable and function names, different types and, for some reason, the left pseudocode did not resolve the string pointers. It is also notable that despite these differences both functions are identical in behaviour.

As it can be expected, if you attempt to match these two functions using a fuzzy-hash algorith you won't have much luck.

Here you can see a quick test using ssdeep.
```
~  $ cat pseudo1.c
char * sym.getPortz(void)
{
    int32_t iVar1;
    char *var_bp_4h;

    iVar1 = flirt._access("/usr/bin/python", 0);
    if (iVar1 == -1) {
        iVar1 = flirt._access("/usr/bin/python3", 0);
        if (iVar1 == -1) {
            iVar1 = flirt._access("/usr/bin/perl", 0);
            if (iVar1 == -1) {
                iVar1 = flirt._access("/usr/sbin/telnetd", 0);
                if (iVar1 == -1) {
                    var_bp_4h = "Unknown Port";
                }
                else {
                    var_bp_4h = (char *)0x8054cd0;
                }
            }
            else {
                var_bp_4h = (char *)0x8054cd0;
            }
        }
        else {
            var_bp_4h = (char *)0x8054cd0;
        }
    }
    else {
        var_bp_4h = (char *)0x8054cd0;
    }
    return var_bp_4h;
}

~  $ cat pseudo2.c
undefined4 sym.getPortz(void)
{
    int32_t iVar1;
    undefined4 uStack20;
    char *var_10h;

    iVar1 = sym.access(*(char **)0xc9b8);
    if (iVar1 == -1) {
        iVar1 = sym.access(*(char **)0xc9c0);
        if (iVar1 == -1) {
            iVar1 = sym.access(*(char **)0xc9c4);
            if (iVar1 == -1) {
                iVar1 = sym.access(*(char **)0xc9c8);
                if (iVar1 == -1) {
                    uStack20 = *(undefined4 *)0xc9cc;
                }
                else {
                    uStack20 = *(undefined4 *)0xc9bc;
                }
            }
            else {
                uStack20 = *(undefined4 *)0xc9bc;
            }
        }
        else {
            uStack20 = *(undefined4 *)0xc9bc;
        }
    }
    else {
        uStack20 = *(undefined4 *)0xc9bc;
    }
    return uStack20;
}

~  $ python
>>> import ssdeep
>>> h1 = ssdeep.hash_from_file('pseudo1.c')
>>> h2 = ssdeep.hash_from_file('pseudo2.c')
>>> h1
'24:AW5Slrlv/prwZrIJrNgR7q7iCLiybiiriQEa:AWyzaieJq7iCLiybiiriQP'
>>> h2
'24:8D+5v7+QpgVwhBtjS7Vtk/SCLltk/Cyb1tk/yirFtk/iQp:i+Z7nGKZS7USCLkCyb0yirEiQp'
>>> ssdeep.compare(h1, h2)
0
```

## Comparing pseudocode behaviour

Instead of comparing the decompiler output text we can attempt to compare the behaviours that this code represents. [Diaphora](https://github.com/joxeankoret/diaphora) already does this by creating a hash with the information from the AST provided by the HexRays decompiler. In order to do this in r2diaphora we would need to reconstruct an AST from the decompiled code, as r2ghidra nor pdc offer access to the AST. I'll be using [pycparser](https://github.com/eliben/pycparser) for this task.

Pycparser needs to receive preprocessed (`gcc -E`) code as input, so we would need to perform some modifications to the raw functions in order for `gcc` to be able to preprocess them. Namely:

* Pycparser's fake stdlib needs to be included, as including the default `stdlib` will result in parse errors. This can be done with `-nostdinc -I/path/to/fakelib` arguments for `gcc`.
* Function names can not have `.` characters in them. By default radare2 includes a `.` in every function name (e.g: `fcn.400200`, `sym.myfunc`, etc). This needs to be transformed to remove the `.` character. The following code piece should do the trick:

```python
def clean_pseudocode(self, code):
    lines = code.split("\n")
    code = [line for line in lines if not line.strip().startswith("//")]
    code = "\n".join(code)

    return code.replace("sym.imp.", "")\
                .replace("sym.", "")\
                .replace("fcn.", "fcn_")\
                .replace("flirt.", "")\
                .replace("obj.", "")
```

* Ghidra likes assigning made-up types to some variables (e.g: `undefined4 iVar1`, `unkbyte7 uStack20`, etc). We need to add `typedef`s for said types in the `_fake_typedefs.h` header file included with pycparser. The same can be applied to function specifications like `__noreturn` in `_fake_defines.h`.

```c
/* GHIDRA typedefs */
typedef void* undefined;
typedef void* undefined1;
typedef void* undefined2;
typedef void* undefined3;
typedef void* undefined4;
typedef void* undefined5;
typedef void* undefined6;
typedef void* undefined7;
typedef void* undefined8;
typedef void* undefined9;
typedef void* code;

typedef short unkbyte1;
typedef short unkbyte2;
typedef short unkbyte3;
typedef short unkbyte4;
typedef short unkbyte5;
typedef short unkbyte6;
typedef short unkbyte7;
typedef short unkbyte8;
typedef short unkbyte9;
```

* The function needs to be embedded in a body with the neccesary include headers and the function itself.

```python
def build_ast(self):
    pseudo = f"""
    #include <stdlib.h>

    {self.cfunc}
    """
    dirname = os.path.dirname(__file__)
    libdir  = os.path.abspath(
        os.path.join(dirname, "..", "pycparser", "fake_libc_include")
    )
    parser = CParser()

    try:
        p = Popen(
            ["gcc", "-nostdinc", "-E", f"-I{libdir}", "-xc", "-"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = p.communicate(bytes(pseudo, "utf-8"))
        self.ast = parser.parse(stdout.decode("utf-8"))
        return True

    except Exception:
        log.exception(f"Could not obtain AST for {pseudo}")
        return False
```

There are other potential issues that makes the code unprocessable by `gcc`, like when Ghidra uses an struct without declaring it first. These cases are less common and harder to fix, so we will ignore them for now.

After building the AST the hash needs to be generated. For this task diaphora implements an AST tree visitor class (named `CASTVisitor`) that visits every expression and statement in the source code. For each visited expression a prime number is selected based on the expression index. That prime is then multiplied by an accumulator that starts in `1` (for the first expression). Once all the expressions have been visited the accumulator value is the final hash value. You can read the described implementation yourself [here](https://github.com/joxeankoret/diaphora/blob/55e7822322e72c2caa3b9cbf4f382f0542c6757e/diaphora_ida.py#L2676-L2696). A list containing all the expression indexes can also be found [here](https://gist.github.com/trietptm/54b490e8c8997e934182d7939ae1881e).

With the previous expression index list and implementation reference we can begin porting the code to r2diaphora. Luckily enough, pycparser also provides an API to build AST tree visitors, although, of course, the `visit_xxxx` methods differ from HexRays' API. We just need to adapt the `visit_xxx` methods to generate a similar value. The current implementation of the `CASTVisitor` class in r2diaphora can be found [here](https://github.com/FernandoDoming/r2diaphora/blob/master/r2diaphora/idaapi/idaapi_to_r2.py#L116-L276).

Once implemented, the previous test that compared the `getPortz` function in different binaries can be repeated, this time using the generated pseudocode hash value.

```bash
# Regenerate diaphora databases
r2diaphora -f 17c62e0cf77dc4341809afceb1c8395d67ca75b2a2c020bddf39cca629222161
r2diaphora -f 6ce1739788b286cc539a9f24ef8c6488e11f42606189a7aa267742db90f7b18d
```

After having regenerated diaphora databases for both samples we can check the values with:
```
MariaDB [(none)]> select
    -> `6ce1739788b286cc539a9f24ef8c6488e11f42606189a7aa267742db90f7b18d`.functions.name,
    -> `6ce1739788b286cc539a9f24ef8c6488e11f42606189a7aa267742db90f7b18d`.functions.pseudocode_hash1,
    -> `6ce1739788b286cc539a9f24ef8c6488e11f42606189a7aa267742db90f7b18d`.functions.pseudocode_hash2,
    -> `6ce1739788b286cc539a9f24ef8c6488e11f42606189a7aa267742db90f7b18d`.functions.pseudocode_hash3,
    -> `6ce1739788b286cc539a9f24ef8c6488e11f42606189a7aa267742db90f7b18d`.functions.`pseudocode_primes`,
    -> `17c62e0cf77dc4341809afceb1c8395d67ca75b2a2c020bddf39cca629222161`.functions.name,
    -> `17c62e0cf77dc4341809afceb1c8395d67ca75b2a2c020bddf39cca629222161`.functions.pseudocode_hash1,
    -> `17c62e0cf77dc4341809afceb1c8395d67ca75b2a2c020bddf39cca629222161`.functions.pseudocode_hash2,
    -> `17c62e0cf77dc4341809afceb1c8395d67ca75b2a2c020bddf39cca629222161`.functions.pseudocode_hash3,
    -> `17c62e0cf77dc4341809afceb1c8395d67ca75b2a2c020bddf39cca629222161`.functions.`pseudocode_primes`
    -> from
    -> `6ce1739788b286cc539a9f24ef8c6488e11f42606189a7aa267742db90f7b18d`.functions,
    -> `17c62e0cf77dc4341809afceb1c8395d67ca75b2a2c020bddf39cca629222161`.functions
    -> where
    -> `6ce1739788b286cc539a9f24ef8c6488e11f42606189a7aa267742db90f7b18d`.functions.name = "sym.getPortz" and
    -> `17c62e0cf77dc4341809afceb1c8395d67ca75b2a2c020bddf39cca629222161`.functions.name = "sym.getPortz";
+--------------+----------------------------------+------------------+------------------+-------------------+--------------+----------------------------------+------------------+------------------+-------------------+
| name         | pseudocode_hash1                 | pseudocode_hash2 | pseudocode_hash3 | pseudocode_primes | name         | pseudocode_hash1                 | pseudocode_hash2 | pseudocode_hash3 | pseudocode_primes |
+--------------+----------------------------------+------------------+------------------+-------------------+--------------+----------------------------------+------------------+------------------+-------------------+
| sym.getPortz | wpbClsK3wrfCt8K3ISEhIcKvwq/Cr8Kv | NULL             | NULL             | 781435            | sym.getPortz | IiJMTExMMjIyMiAgICAaGhoaY2NjY8Op | NULL             | NULL             | 781435            |
+--------------+----------------------------------+------------------+------------------+-------------------+--------------+----------------------------------+------------------+------------------+-------------------+
1 row in set (0.003 sec)
```

As it can be seen the pseudocode fuzzy-hash (`pseudocode_hash[1-3]`) still differs but the values for the AST behaviour hash (`pseudocode_primes`) are identical.

This feature can be found in r2diaphora version `0.1.6` and higher.

