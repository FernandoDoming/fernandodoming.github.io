---
title: "radare2 r2pipe optimization quick tips"
author: Fernando Dominguez
date: 2021-10-19 18:00:00 +0200
categories: [radare2, scripting]
tags: [quick-tips, radare2, r2pipe]
---

Some quick tips on using radare2 from r2pipe python scripts to increase analysis performance.

## Using r2pipe native mode

By default, if you open a binary for analysis in r2pipe (`r2pipe.open("/path/to/bin")`), a new radare2 process will be created. The python process will then communicate with the newly created radare2 process by employing a pipe. If r2pipe is instructed to open the file in native mode (`r2pipe.open("ccall:///path/to/bin")`) instead of spawning a radare2 process the python process will open the core radare2 dynamic link library and perform C calls to the `r_core_cmd_str()` function. This is about 4 times faster than the default method using the pipe. The only real downside of using this method is that radare's native mode is less tested, so you may encounter more bugs.

## Using r2pipe cache

Starting from r2pipe version `1.6.4` there is now a cache for issued commands. If cache is enabled and the command has already been issued in the current session, the cached result will be returned.

To enable it, simply do:
```python
r2 = r2pipe.open("/path/to/bin")
r2.use_cache = True
```

Should you have the need to clear the cached command results, it can be done manually with the following line:

```python
r2.invalidate_cache()
```

If you want to stop using the cache, the `use_cache` attribute can be re-assigned at runtime.

## Avoiding `afi`

Certain commands like `afi` are slow to execute and thus you should avoid using them and obtain the same information from another, faster command. A faster alternative to `afi` that may be counterintuitive is to use `afll` / `aflj` and cache the returned array, either manually or using r2pipe's cache. You can then obtain the function information from the cached array.