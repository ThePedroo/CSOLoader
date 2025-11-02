# CSOLoader

CSOLoader is a traceless and system-linker-independent custom linker for Android Linux.

## Features

- C99 compliant
- System linker independent (no dlopen)
- Dependencyless (no third-party dependency, except system ones)

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
$ make
```

### 3. Run CSOLoader

```shell
$ adb shell su -c /data/local/tmp/csoloader /data/local/tmp/shared.so
```

## Usage

N/A

## Documentation

N/A

## Support

N/A

## Contribution

It is mandatory to follow the PerformanC's [contribution guidelines](https://github.com/PerformanC/contributing) to contribute to CSOLoader. Following its Security Policy, Code of Conduct and syntax standard.

## Projects using CSOLoader

None yet, soon [ReZygisk](https://github.com/PerformanC/ReZygisk).

## License

CSOLoader is licensed under [GNU AGPLv3 License](LICENSE). You can read more about it on [Open Source Initiative](https://opensource.org/license/agpl-v3).

* This project is considered as: [leading standard](https://github.com/PerformanC/contributing?tab=readme-ov-file#project-information).
