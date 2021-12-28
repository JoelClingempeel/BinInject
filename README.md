# BinInject
A collection of small tools for modifying compiled binaries

This is a hobby project to learn more about some of the technologies behind binary instrumentation and malware.

* `InjectBasic` - Injects payload into gap between code and data segments and modifies control flow to execute payload followed by original code.
* `InjectTrampoline` - Injects payload into gap between code and data segments and hooks a function to be a wrapper for the payload.
* `InjectDataSeg` **in progress** - Injects payload into data segment.
* `BinPacker` - Creates a binary containing encrypted payload code. When run, the payload is decrypted, and control is transferred to it.
    - Contains an anti-debugging mechanism so the payload will not be decrypted if a debugger is attached.
