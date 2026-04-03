# CSOLoader

CSOLoader is a traceless and system linker independent SOTA custom linker for Android Linux.

## Features

- C99 compliant
- System linker independent (no dlopen)
- Dependency-less (no third-party dependency, except system ones)
- Near complete feature parity to AOSP linker

## Installation

### 1. Clone the repository

```shell
$ git clone https://github.com/ThePedroo/CSOLoader
$ cd CSOLoader
```

### 2. Connect your Android device

This is required to test CSOLoader capabilities. Before proceeding, connect your device and assure you can access `adb shell`.

### 3. Compile the project

```shell
$ make
```

### 4. Compile the shared library

```shell
$ cd shareds
$ make standalone
```

### 3. Run CSOLoader

```shell
$ adb shell su -c /data/local/tmp/csoloader /data/local/tmp/shared.so
```

## Usage

CSOLoader aims to provide a simple API to match the as-simple API that system linkers/libdl provides. Currently, there are only 4 user-facing APIs.

In [csoloader.c](./src/csoloader.c), in `STANDALONE_TEST` `#ifdef`, there is a basic usage of CSOLoader. Usage of CSOLoader's `csoloader_abandon` follows the same as `csoloader_unload`.

## Documentation

1. `bool csoloader_load(struct csoloader *lib, const char *lib_path)`

Loads and links the library into the process' memory, and load the info to the `csoloader` structure for future management. Returns false if operations fails, and performs cleanup automatically.

2. `bool csoloader_unload(struct csoloader *lib)`

Unloads the library from the process' memory from the `csoloader` structure. Returns false if operations fails, and will leak memory if that happens.

3. `bool csoloader_abandon(struct csoloader *lib)`

Frees all internal management handles while allowing it to still continue operation, however, without TLS available. Returns false if operations fails, and will leak memory if that happens.

4. `void *csoloader_get_symbol(struct csoloader *lib, const char *symbol_name)`

Gets the symbol address from the loaded library, won't work if the library has been abandoned. Returns NULL if operation failed.

5. `void csoloader_deinit(void)`
Deinitializes all internal global resources, such as TLS management. This is required to be called if you won't be using CSOLoader anymore, and want to leave no traces behind.

> [!IMPORTANT]
> You may also want to define `CSOLOADER_MAKE_LINKER_HOOKS` macro to make CSOLoader hook some functions that are commonly used by libraries, such as `dl_iterate_phdr`, `dlopen`, `dlclose`, and `dladdr`. However, doing so, will make so that CSOLoader must be kept loaded, since if CSOLoader is unloaded, it will call an unmapped address. However, even with it not defined, CSOLoader will still hook `__tls_get_addr` to provide TLS support, so it is better to not use TLS it if you want to use unload CSOLoader and have them work flawlessly.

## Features

- [x] Indirect symbol support 
- [x] Load and link library's dependencies
- [x] Full relocation support
- [x] Android-specific relocations support
- [x] Memory protection
- [x] Constructors/Deconstructors calling
- [x] `libdl` functions support (backtrace, dl_iterate_phdr, dladdr)
- [x] TLS support
- [x] (EH) Frame register
- [x] C++ exceptions support (testing)
- [ ] MTE (tagged-pointer) support
- [ ] Support be system linker
- [ ] `preinit` support (needed to be system linker)

The [testing file for Android](./shareds/cpp-shared.cpp) implements testing for almost all supported functionality.

## Support

Any question or issue related to CSOLoader or other PerformanC projects can be made in [PerformanC's Discord server](https://discord.gg/uPveNfTuCJ).

## Contribution

It is mandatory to follow the PerformanC's [contribution guidelines](https://github.com/PerformanC/contributing) to contribute to CSOLoader. Following its Security Policy, Code of Conduct and syntax standard.

## Projects using CSOLoader

- [ReZygisk](https://github.com/PerformanC/ReZygisk)

## License

CSOLoader is licensed under [GNU AGPLv3 License](LICENSE). You can read more about it on [Open Source Initiative](https://opensource.org/license/agpl-v3).

* This project is considered as: [leading standard](https://github.com/PerformanC/contributing?tab=readme-ov-file#project-information).
