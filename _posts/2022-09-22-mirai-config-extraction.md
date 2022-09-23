---
title: Configuration extraction in Mirai samples
author: Fernando Dominguez
date: 2022-09-26 18:00:00 +0200
categories: [analysis, config-extraction, mirai]
tags: [radare2, mirai, config-extraction, malware-analysis]
---

Over the years all the public Mirai configuration extractors that I have come across either:
1. Rely on bruteforcing the encryption key and apply the guessed key to the complete binary, a process that is slow and does not provide good contextual results
2. Work with fixed addresses or offsets, so they only work for samples that share those offsets

As such, I decided to build my own config extractor for Mirai in the most architecture-agnostic way possible. The architecture agnosticism is, of course, in order to use and maintain the minimum possible amount of static signatures or hard-coded offsets, as they tend to break with different architectures / variants.

## Identifying key functions

There are several function that we need to identify in order to extract Mirai's configuration. I have opted to perform this identification based in the function features (number of basic blocks, function signature, number of cross-references, etc) as this approach is architecture-agnostic and the key functions are easily identifiable by their features. Namely, these functions are:

* `table_unlock_val` / `table_lock_val` ([ref](https://github.com/jgamblin/Mirai-Source-Code/blob/3273043e1ef9c0bb41bd9fcdc5317f7b797a2a94/mirai/bot/table.c#L78)): The functions responsible for string decryption / encryption. The default cipher algorith for Mirai is a single-byte XOR (the effective length of the key is 1 byte, even though the key length is 4 bytes). As the cipher is XOR-based the functions for encrypting and decrypting are identical, which is going to be one of our identification mechanisms. Other prominent features are a high number of calls to this function through the binary (large indegree), a relatively small function body with a single loop and a function signature containing receiving a single argument with `int` type (the table index).

* `table_init` ([ref](https://github.com/jgamblin/Mirai-Source-Code/blob/3273043e1ef9c0bb41bd9fcdc5317f7b797a2a94/mirai/bot/table.c#L16)): `table_init` loads the encrypted strings in the proper memory offsets and as such contains all the encrypted strings. The features that make this function identifiable are:
    1. Does not contain `if`s nor loops (number of basic blocks == 1 and cyclomatic complexity == 0)
    2. Is only called once (indegree == 1)
    3. Contains a large amount of function calls in its body (elevated outdegree)
    4. Does not receive any arguments

In the leaked Mirai code the CnC domain and port are the elements with index 0 and 1 in the strings table, so these functions should suffice to extract the configuration in that case. However, in most of the Mirai samples distributed in the wild (all of the observed samples in my case) the CnC IP / domain has been moved from the strings table to the `resolve_cnc_addr` ([ref](https://github.com/jgamblin/Mirai-Source-Code/blob/3273043e1ef9c0bb41bd9fcdc5317f7b797a2a94/mirai/bot/main.c#L358)), so we should also identify said function. An easy way to identify this function unequivocally is to follow the flow of `main` function and attempt to find a call to `signal(5 (SIGTRAP), <handler>)` ([ref](https://github.com/jgamblin/Mirai-Source-Code/blob/3273043e1ef9c0bb41bd9fcdc5317f7b797a2a94/mirai/bot/main.c#L68)), as `resolve_cnc_addr` is registered as the handler for SIGTRAP as an anti-debugging trick. Of course this technique is architecture-dependant but I found it to be easier and more reliable than using the function features.

Of course, to accomplish this we would need a disassembler that provides us with the mentioned information. As radare2 accomplishes this task while also being free open-source software, I'll be using it.

## Performing the extraction

Here we have 2 options: parsing the assembly from the identified functions until we reach the data or rely on some sort of emulation. Emulation may seem the most architecture-independant option but it is not completely independant as registers need to be manipulated, the memory has to be intialized with the data that functions expect to find, etcetera. As such, I feel that emulation adds more problems than it solves, so I opted for the classic option of parsing the assembly.

### X86

We will now write the x86 architecture specific code to extract the values from the binary.

As it can be seen in the image below, the key is referenced in the first `mov <reg>, dword [<ptr>]` found in either of the encryption functions.

![String decryption routine for X86 Mirai sample](/assets/img/blog/str-decrypt-x86.png)

Hence, we can extract it like so:

```python
def extract_enc_values_x86(r2, enc_fn):
    key = None
    # Obtain function body as a list of instructions
    instrs = r2.cmdj(f"aoj {enc_fn['ninstrs']} @ {enc_fn['offset']}")
    # Iterate instructions
    for i in instrs:
        if (
            i["mnemonic"] == "mov" and
            len(i["opex"]["operands"]) == 2 and
            i["opex"]["operands"][1]["type"] == "mem" and
            ", dword [0x" in i["opcode"]
        ):
            key_addr = i["opex"]["operands"][1]["disp"]
            key = bytes(r2.cmdj(f"pxj 4 @ {key_addr}"))
            # Interpret bytes as little-endian unsigned int
            key = struct.unpack("<I", key)[0]
            break

    return key
```

In a similar fashion we can extract the encrypted strings from `table_init`. In this case we need to look for `push` instructions with a value larger than the base address of the binary (a valid memory reference); that is our string pointer. As the strings are encrypted they may not end in `\x00` but luckily the length is encoded in the `push` instruction above to the one referencing the string, as it can be seen in the following screenshot.

![table_init function](/assets/img/blog/init-table-x86.png)

In python code it would look something like this:

```python
def decrypt_table_x86(r2, tableinit_fn, key):
    strings = []
    instrs = r2.cmdj(f"aoj {tableinit_fn['ninstrs']} @ {tableinit_fn['offset']}")
    baddr = r2.cmdj("ij").get("bin", {}).get("baddr")

    last_instr = None
    for i in instrs:
        if (
            i["mnemonic"] == "push" and
            i["opex"]["operands"][0]["type"] == "imm" and
            i["opex"]["operands"][0]["value"] >= baddr
        ):
            str_addr = i["opex"]["operands"][0]["value"]
            str_len = last_instr["opex"]["operands"][0]["value"]
            enc_str = bytes(r2.cmdj(f"pxj {str_len} @ {str_addr}"))
            log.debug(
                "Got a encoded string. Str: %s, len: %d, addr: %x",
                enc_str, str_len, str_addr
            )
            dec_str = decode(key, enc_str)
            strings.append(dec_str)
            log.debug("Decrypted string: %s", dec_str)

        last_instr = i
    return strings

# Reconstruction of Mirai's default encryption algorithm in python
def decode(key: int, enc_str: bytes):
    k1 = key & 0xFF
    k2 = (key>>8) & 0xFF
    k3 = (key>>16) & 0xFF
    k4 = (key>>24) & 0xFF
    output = ""
    for n in enc_str:
        c = chr(n)
        output += chr(ord(c)^k4^k3^k2^k1)
    return output
```

Finally, the only thing left is extracting the CnC by parsing `main` until we find the signal handler for `SIGTRAP` (signal number 5). In all the observed samples were the CnC address was removed from the string table, the CnC address could be found in the `SIGTRAP` handler, either as a string or a 4-byte integer.

In the below image an example can be seen of a Mirai sample containing the CnC address encoded as a string in the `resolve_cnc_addr` function.

![The CnC address is stored in clear-text](/assets/img/blog/cnc-in-resolv.png)

With the above information we can extract the CnC like so:

```python
def extract_cnc_x86(r2):
    cnc = None
    baddr = r2.cmdj("ij").get("bin", {}).get("baddr")
    instrs = r2.cmdj("aoj 100 @ main")
    last_instr = None
    for i in instrs:
        if (
            i["mnemonic"] == "push" and
            i["opex"]["operands"][0]["type"] == "imm" and
            i["opex"]["operands"][0]["value"] == 5 and
            last_instr["mnemonic"] == "push" and
            last_instr["opex"]["operands"][0]["type"] == "imm" and
            last_instr["opex"]["operands"][0]["value"] >= baddr
        ):
            anti_gdb_entry      = last_instr["opex"]["operands"][0]["value"]
            resolve_cnc_mov     = r2.cmdj(f"aoj 1 @ {anti_gdb_entry}")[0]
            resolve_cnc_fn_addr = resolve_cnc_mov["opex"]["operands"][1]["value"]
            resolve_cnc_instrs  = r2.cmdj(f"aoj 20 @ {resolve_cnc_fn_addr}")
            for _i in resolve_cnc_instrs:
                if (
                    _i["mnemonic"] == "mov" and
                    _i["opex"]["operands"][0]["type"] == "mem" and
                    _i["opex"]["operands"][1]["type"] == "imm" and
                    _i["opex"]["operands"][1]["value"] >= baddr
                ):
                    cnc_addr = _i["opex"]["operands"][1]["value"]
                    cnc = r2.cmd(f"ps @ {cnc_addr}").strip()
                    break
        last_instr = i
    return cnc
```

As this code is specific to the x86 architecture and Mirai is usually distributed in x64, arm32, arm64, renesas, powerpc, mips and more architectures; similar code would need to be produced for the architectures that are desired to support.

An extractor currently supporting x86 and arm32 (more to be supported in the future) can be found [in my github repository](https://github.com/FernandoDoming/miraicfg). It can also be installed via `pip install miraicfg`.

Running said package over a small sample yields the following results:

```
$ miraicfg 079bc88b4c8972666a5d97885d211d9c897779f532aebb3f3cc44f805c844a08 3cece358fecfc8fbe2e86a1b2c6ae3a0f34d9648cd2306cd734bc717216a728e 79c3d3b25aba02959ecf734e93b8c162851c11abe81bd7207a16d496ebfa6ab5

{
    "e089ec65606494ecb0eb133fb96292a0009239fc0c5aea4cdc078cbd1c6d915e": {
        "cnc": "92.87.6.205",
        "key": 3735928559,
        "strings_table": [
            "\u000e\u00c2",
            "%S",
            "lzrd cock fest\u0000\"/proc/\u0000\"/exe\u0000",
            "/proc/\u0000",
            "/exe\u0000",
            "/fd\u0000",
            "/maps\u0000",
            "/status\u0000",
            "/proc/net/tcp\u0000",
            "/cmdline\u0000",
            "tmp/\u0000",
            "data/local\u0000",
            "qtxbot\u0000",
            ".\u0000",
            "arc\u0000",
            "arm\u0000",
            "arm5\u0000",
            "arm6\u0000",
            "arm7\u0000",
            "x86\u0000",
            "x86_64\u0000",
            "sh4\u0000",
            "mips\u0000",
            "mpsl\u0000",
            "ppc\u0000",
            "sda\u0000",
            "mtd\u0000",
            "bot]\n",
            "hakai\u0000",
            "shell\u0000",
            "enable\u0000",
            "system\u0000",
            "sh\u0000",
            "linuxshell\u0000",
            "/bin/busybox LZRD\u0000",
            "LZRD: applet not found\u0000",
            "ncorrect\u0000",
            "ogin\u0000",
            "assword\u0000",
            "enter\u0000",
            "bah\u0000",
            "start\u0000",
            "TSource Engine Query\u0000",
            "/etc/resolv.conf\u0000",
            "nameserver \u0000",
            "/dev/watchdog\u0000",
            "/dev/misc/watchdog\u0000",
            "/sbin/watchdog\u0000",
            "/bin/watchdog\u0000",
            "/dev/FTWDT101_watchdog\u0000",
            "/dev/FTWDT101/watchdog\u0000",
            "/dev/watchdog0\u0000",
            "/etc/default/watchdog\u0000",
            "/etc/watchdog\u0000",
            "dkaowjfirhiad1j3edjkai\u0000",
            "eIHHCEROIH\u001c\u0006MCCV\u000bGJOPC&",
            "gEECVR\u001c\u0006RC^R\tNRKJ\nGVVJOEGROIH\t^NRKJ\r^KJ\nGVVJOEGROIH\t^KJ\u001dW\u001b\u0016\b\u001f\nOKGAC\tQCDV\n\f\t\f\u001dW\u001b\u0016\b\u001e&",
            "gEECVR\u000bjGHASGAC\u001c\u0006CH\u000bsu\nCH\u001dW\u001b\u0016\b\u001e&",
            "eIHRCHR\u000br_VC\u001c\u0006GVVJOEGROIH\t^\u000bQQQ\u000b@ITK\u000bSTJCHEIBCB&",
            "UCReIIMOC\u000e\u0001&",
            "TC@TCUN\u001c&",
            "JIEGROIH\u001c&",
            "UCR\u000bEIIMOC\u001c&",
            "EIHRCHR\u000bJCHARN\u001c&",
            "RTGHU@CT\u000bCHEIBOHA\u001c&",
            "ENSHMCB&",
            "MCCV\u000bGJOPC&",
            "EIHHCEROIH\u001c&",
            "UCTPCT\u001c\u0006BIUGTTCUR&",
            "UCTPCT\u001c\u0006EJISB@JGTC\u000bHAOH^&",
            "kI\\OJJG\t\u0013\b\u0016\u0006\u000eqOHBIQU\u0006hr\u0006\u0017\u0016\b\u0016\u001d\u0006qiq\u0010\u0012\u000f\u0006gVVJCqCDmOR\t\u0013\u0015\u0011\b\u0015\u0010\u0006\u000emnrkj\n\u0006JOMC\u0006aCEMI\u000f\u0006eNTIKC\t\u0013\u0017\b\u0016\b\u0014\u0011\u0016\u0012\b\u0017\u0016\u0015\u0006uG@GTO\t\u0013\u0015\u0011\b\u0015\u0010&",
            "kI\\OJJG\t\u0013\b\u0016\u0006\u000eqOHBIQU\u0006hr\u0006\u0017\u0016\b\u0016\u001d\u0006qiq\u0010\u0012\u000f\u0006gVVJCqCDmOR\t\u0013\u0015\u0011\b\u0015\u0010\u0006\u000emnrkj\n\u0006JOMC\u0006aCEMI\u000f\u0006eNTIKC\t\u0013\u0014\b\u0016\b\u0014\u0011\u0012\u0015\b\u0017\u0017\u0010\u0006uG@GTO\t\u0013\u0015\u0011\b\u0015\u0010&",
            "kI\\OJJG\t\u0013\b\u0016\u0006\u000eqOHBIQU\u0006hr\u0006\u0010\b\u0017\u001d\u0006qiq\u0010\u0012\u000f\u0006gVVJCqCDmOR\t\u0013\u0015\u0011\b\u0015\u0010\u0006\u000emnrkj\n\u0006JOMC\u0006aCEMI\u000f\u0006eNTIKC\t\u0013\u0017\b\u0016\b\u0014\u0011\u0016\u0012\b\u0017\u0016\u0015\u0006uG@GTO\t\u0013\u0015\u0011\b\u0015\u0010&",
            "kI\\OJJG\t\u0013\b\u0016\u0006\u000eqOHBIQU\u0006hr\u0006\u0010\b\u0017\u001d\u0006qiq\u0010\u0012\u000f\u0006gVVJCqCDmOR\t\u0013\u0015\u0011\b\u0015\u0010\u0006\u000emnrkj\n\u0006JOMC\u0006aCEMI\u000f\u0006eNTIKC\t\u0013\u0014\b\u0016\b\u0014\u0011\u0012\u0015\b\u0017\u0017\u0010\u0006uG@GTO\t\u0013\u0015\u0011\b\u0015\u0010&",
            "kI\\OJJG\t\u0013\b\u0016\u0006\u000ekGEOHRIUN\u001d\u0006oHRCJ\u0006kGE\u0006iu\u0006~\u0006\u0017\u0016y\u0017\u0017y\u0010\u000f\u0006gVVJCqCDmOR\t\u0010\u0016\u0017\b\u0011\b\u0011\u0006\u000emnrkj\n\u0006JOMC\u0006aCEMI\u000f\u0006pCTUOIH\t\u001f\b\u0017\b\u0014\u0006uG@GTO\t\u0010\u0016\u0017\b\u0011\b\u0011&",
            "kI\\OJJG\t\u0012\b\u0016\u0006\u000eEIKVGRODJC\u001d\u0006kuoc\u0006\u001f\b\u0016\u001d\u0006qOHBIQU\u0006hr\u0006\u0013\b\u0017\u001d\u0006rTOBCHR\t\u0013\b\u0016\u000f&",
            "kI\\OJJG\t\u0012\b\u0016\u0006\u000eEIKVGRODJC\u001d\u0006kuoc\u0006\u001f\b\u0016\u001d\u0006qOHBIQU\u0006hr\u0006\u0010\b\u0016\u001d\u0006rTOBCHR\t\u0012\b\u0016\u001d\u0006ard\u0011\b\u0012\u001d\u0006oH@IvGRN\b\u0015\u001d\u0006up\u0017\u001d\u0006\bhcr\u0006ejt\u0006\u0015\b\u0012\b\u0013\u0015\u0015\u0010\u0016\u001d\u0006qiq\u0010\u0012\u001d\u0006CH\u000bsu\u000f&",
            "kI\\OJJG\t\u0012\b\u0016\u0006\u000eEIKVGRODJC\u001d\u0006kuoc\u0006\u001f\b\u0016\u001d\u0006qOHBIQU\u0006hr\u0006\u0010\b\u0017\u001d\u0006rTOBCHR\t\u0012\b\u0016\u001d\u0006`bk\u001d\u0006kuoceTGQJCT\u001d\u0006kCBOG\u0006eCHRCT\u0006ve\u0006\u0013\b\u0016\u000f&",
            "kI\\OJJG\t\u0012\b\u0016\u0006\u000eEIKVGRODJC\u001d\u0006kuoc\u0006\u001f\b\u0016\u001d\u0006qOHBIQU\u0006hr\u0006\u0010\b\u0017\u001d\u0006rTOBCHR\t\u0012\b\u0016\u001d\u0006ard\u0011\b\u0012\u001d\u0006oH@IvGRN\b\u0014\u001d\u0006up\u0017\u001d\u0006\bhcr\u0006ejt\u0006\u0012\b\u0012\b\u0013\u001e\u0011\u001f\u001f\u001d\u0006qiq\u0010\u0012\u001d\u0006CH\u000bsu\u000f&",
            "kI\\OJJG\t\u0012\b\u0016\u0006\u000eEIKVGRODJC\u001d\u0006kuoc\u0006\u001f\b\u0016\u001d\u0006qOHBIQU\u0006hr\u0006\u0010\b\u0017\u001d\u0006rTOBCHR\t\u0013\b\u0016\u001d\u0006`SHqCDvTIBSERU\u000f&",
            "kI\\OJJG\t\u0013\b\u0016\u0006\u000ekGEOHRIUN\u001d\u0006oHRCJ\u0006kGE\u0006iu\u0006~\u0006\u0017\u0016\b\u0010\u001d\u0006TP\u001c\u0014\u0013\b\u0016\u000f\u0006aCEMI\t\u0014\u0016\u0017\u0016\u0016\u0017\u0016\u0017\u0006`OTC@I^\t\u0014\u0013\b\u0016&",
            "kI\\OJJG\t\u0013\b\u0016\u0006\u000ekGEOHRIUN\u001d\u0006oHRCJ\u0006kGE\u0006iu\u0006~\u0006\u0017\u0016\b\u001e\u001d\u0006TP\u001c\u0014\u0017\b\u0016\u000f\u0006aCEMI\t\u0014\u0016\u0017\u0016\u0016\u0017\u0016\u0017\u0006`OTC@I^\t\u0014\u0017\b\u0016&",
            "kI\\OJJG\t\u0013\b\u0016\u0006\u000ekGEOHRIUN\u001d\u0006oHRCJ\u0006kGE\u0006iu\u0006~\u0006\u0017\u0016\b\u001e\u001d\u0006TP\u001c\u0014\u0012\b\u0016\u000f\u0006aCEMI\t\u0014\u0016\u0017\u0016\u0016\u0017\u0016\u0017\u0006`OTC@I^\t\u0014\u0012\b\u0016&",
            "kI\\OJJG\t\u0013\b\u0016\u0006\u000ekGEOHRIUN\u001d\u0006oHRCJ\u0006kGE\u0006iu\u0006~\u0006\u0017\u0016y\u0017\u0016\u001d\u0006TP\u001c\u0015\u0015\b\u0016\u000f\u0006aCEMI\t\u0014\u0016\u0017\u0016\u0016\u0017\u0016\u0017\u0006`OTC@I^\t\u0015\u0015\b\u0016&",
            "kI\\OJJG\t\u0013\b\u0016\u0006\u000eqOHBIQU\u0006hr\u0006\u0017\u0016\b\u0016\u001d\u0006qOH\u0010\u0012\u001d\u0006^\u0010\u0012\u000f\u0006gVVJCqCDmOR\t\u0013\u0015\u0011\b\u0015\u0010\u0006\u000emnrkj\n\u0006JOMC\u0006aCEMI\u000f\u0006eNTIKC\t\u0010\u0014\b\u0016\b\u0015\u0014\u0016\u0014\b\u001f\u0012&"
        ],
        "botnet": "LZRD"
    },
    "3cece358fecfc8fbe2e86a1b2c6ae3a0f34d9648cd2306cd734bc717216a728e": {
        "cnc": "198.134.120.150",
        "key": 3739155375,
        "strings_table": [
            "\u00059",
            "\u0007\u00be",
            "DaddyL33T Infected Your Shit\u0000",
            "shell\u0000",
            "enable\u0000",
            "system\u0000",
            "sh\u0000",
            "/bin/busybox JOSHO\u0000",
            "JOSHO: applet not found\u0000",
            "ncorrect\u0000",
            "/bin/busybox ps\u0000",
            "/bin/busybox kill -9 \u0000",
            "/proc/\u0000",
            "/exe\u0000",
            "/fd\u0000",
            "/maps\u0000",
            "/proc/net/tcp\u0000",
            "/status\u0000",
            ".anime\u0000",
            "/proc/net/route\u0000",
            "assword\u0000",
            "TSource Engine Query\u0000",
            "/etc/resolv.conf\u0000",
            "nameserver \u0000",
            "/dev/watchdog\u0000",
            "/dev/misc/watchdog\u0000",
            "pbbf~cu\u0011",
            "ogin\u0000",
            "enter\u0000",
            "1gba4cdom53nhp12ei0kfj\u0000"
        ],
        "botnet": "JOSHO"
    },
    "79c3d3b25aba02959ecf734e93b8c162851c11abe81bd7207a16d496ebfa6ab5": {
        "cnc": null,
        "key": 3735928559,
        "strings_table": [
            "majikku.us\u0000",
            "\u0000\u0017",
            "majikku.us\u0000",
            "\u00bb\u00e5",
            "listening tun0\u0000",
            "https://youtu.be/dQw4w9WgXcQ\u0000",
            "/proc/\u0000",
            "/exe\u0000",
            " (deleted)\u0000",
            "/fd\u0000",
            ".anime\u0000",
            "/status\u0000",
            "REPORT %s:%s\u0000",
            "HTTPFLOOD\u0000",
            "LOLNOGTFO\u0000",
            "KILLATTK\u0000",
            "SCANNER\u0000",
            "INFECTION\u0000",
            "DESTROYMYAZZ\u0000",
            "KILLALL\u0000",
            "TRIGGERED\u0000",
            "CONNECTED\u0000",
            "ICMP\u0000",
            "UDP\u0000",
            "HTTP\u0000",
            "STD\u0000",
            "UKN\u0000",
            "TCP\u0000",
            "RANGE\u0000",
            "stop\u0000",
            "HOODASSSHIT\u0000",
            "SCANNER\u0000",
            "PHONE\u0000",
            "HTTP\u0000",
            "SCANNER\u0000",
            "NETIS\u0000",
            "KILLATTK\u0000",
            "LOLNOGTFO\u0000",
            "HOLD\u0000",
            "JUNK\u0000",
            "CNC\u0000",
            "COMBO\u0000",
            "GTFOFAG\u0000",
            "TELNET\u0000",
            "TCP\u0000",
            "STOP\u0000",
            "HELLNAH\u0000",
            "UDPFLOOD\u0000",
            "TCPFLOOD\u0000",
            "STDFLOOD\u0000",
            "UNKFLOOD\u0000",
            "CNCFLOOD\u0000",
            "UDPATTACK\u0000",
            "TCPATTA@K\u0000",
            "STDATTACK\u0000",
            "UNKATTACK\u0000",
            "CNCATTACK\u0000",
            "UDPATTK\u0000",
            "TCPATTK\u0000",
            "STDATTK\u0000",
            "UNKATTK\u0000",
            "CNCATTK\u0000",
            "NODDOS\u0000",
            "NODOS\u0000\"",
            "KILLDDOS\u0000",
            "KILLDOS\u0000",
            "NIGGER\u0000",
            "NIGGERS\u0000",
            "ASS\u0000",
            "ANAL\u0000",
            "TITS\u0000",
            "PUSSY\u0000",
            "GAY\u0000",
            "NO\u0000",
            "YES\u0000",
            "LOL\u0000",
            "LEL\u0000",
            "LMAO\u0000",
            "LMFAO\u0000",
            "REP\u0000",
            "REPPING\u0000",
            "SELFREP\u0000",
            "A\u0000",
            "B\u0000",
            "C\u0000",
            "D\u0000",
            "E\u0000",
            "F\u0000",
            "G\u0000",
            "H\u0000",
            "I\u0000",
            "J\u0000",
            "K\u0000",
            "L\u0000",
            "M\u0000",
            "N\u0000",
            "\u007f\u0000",
            "P\u0000",
            "Q\u0000",
            "R\u0000",
            "S\u0000",
            "T\u0000",
            "U\u0000",
            "V\u0000",
            "W\u0000",
            "X\u0000",
            "Y\u0000",
            "Z\u0000",
            "1\u0000",
            "2\u0000",
            "3\u0000",
            "4\u0000",
            "5\u0000",
            "6\u0000",
            "7\u0000",
            "8\u0000",
            "9\u0000",
            "10\u0000",
            "+std\u0000",
            "+stop\u0000",
            "+unknown\u0000",
            "-tcp\u0000",
            "-stop\u0000",
            "-udp\u0000",
            "-botkill\u0000",
            "-scanner\u0000",
            "-killdabot\u0000",
            "FUCKOFF\u0000",
            "SC\u0000",
            "ON\u0000",
            "OFF\u0000",
            "BOTKILL\u0000",
            "FASTLOAD\u0000",
            "SSH\u0000",
            "UPDATE\u0000",
            "ENABLE\u0000",
            "B_KILL\u0000",
            "KT\u0000",
            "LOAD\u0000",
            "PYTHON\u0000",
            "RANGE\u0000",
            "BOTKILLER\u0000",
            "SCAN\u0000",
            "SPOOF\u0000",
            "KILLSUB\u0000",
            "TABLE\u0000",
            "GETLOCALIP\u0000",
            "GETPUBLICIP\u0000",
            "\\x58\\x4D\\x4E\\x4E\\x43\\x50\\x46\\x22\u0000",
            "zollard\u0000",
            "GETLOCALIP\u0000",
            "MIRAI\u0000",
            "ECCHI\u0000",
            "KAMI\u0000",
            "FIN\u0000",
            "shell\u0000",
            "enable\u0000",
            "system\u0000",
            "sh\u0000",
            "/bin/busybox KIRA\u0000",
            "KIRA: applet not found\u0000",
            "ncorrect\u0000",
            "/bin/busybox ps\u0000",
            "/bin/busybox kill -9 \u0000",
            "TSource Engine Query\u0000",
            "/etc/resolv.conf\u0000",
            "nameserver \u0000",
            "Connection: keep-alive\u0000",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\u0000",
            "Accept-Language: en-US,en;q=0.8\u0000",
            "Content-Type: application/x-www-form-urlencoded\u0000",
            "setCookie('\u0000",
            "refresh:\u0000",
            "location:\u0000",
            "set-cookie:\u0000",
            "content-length:\u0000",
            "transfer-encoding:\u0000",
            "chunked\u0000",
            "keep-alive\u0000",
            "connection:\u0000",
            "server: dosarrest\u0000",
            "server: cloudflare-nginx\u0000",
            "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36\u0000",
            "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36\u0000",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36\u0000",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36\u0000",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/601.7.7 (KHTML, like Gecko) Version/9.1.2 Safari/601.7.7\u0000"
        ],
        "botnet": "KIRA"
    }
}
```