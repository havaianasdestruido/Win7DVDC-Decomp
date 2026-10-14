# Reconstructed modules

No module subdirectories are present yet because the checkout contains no original binaries: `bin/` is absent and the initial tracked tree has only `LICENSE` and `README.md`. Creating pseudocode, APIs, structures, compatibility code, or a CMake target without target bytes would invent evidence.

When authorized original artifacts are added under `bin/`, create one `src/<original-module-name>/` directory per observed module and keep decompiler-generated pseudocode, manually reconstructed declarations, and independently implemented compatibility code clearly separated and labeled. Add `CMakeLists.txt` only for an actual, buildable compatibility implementation. See `analysis/report/progress.md` for the precise input and toolchain blockers.
