# Third-Party Notices

This project uses the following third-party components. Their source distributions are fetched during the build and are not included in this repository. The corresponding license texts are retained in [`licenses/`](licenses/).

- **Capstone 5.0.7** — BSD 3-Clause license. See [`licenses/Capstone-LICENSE.TXT`](licenses/Capstone-LICENSE.TXT). The Capstone distribution also contains LLVM-derived portions; see [`licenses/Capstone-LICENSE_LLVM.TXT`](licenses/Capstone-LICENSE_LLVM.TXT).
- **nlohmann/json 3.12.0** — MIT License. See [`licenses/JSON-LICENSE.MIT`](licenses/JSON-LICENSE.MIT).
- **LLVM-MinGW 20261104** (build toolchain) — optional when an existing toolchain is provided. The runtime components are covered by Apache License 2.0 with LLVM Exceptions; see [`licenses/LLVM-RUNTIME-LICENSE.TXT`](licenses/LLVM-RUNTIME-LICENSE.TXT). The LLVM-MinGW distribution contains additional components with their own license terms; consult the distribution's notices when redistributing its files.

The root [`LICENSE`](LICENSE) applies to this project's own source and does not replace third-party license terms. When redistributing a built application, include the applicable notices and license files supplied with the build output.
