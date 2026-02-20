# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is PolyTracker?

PolyTracker is a Trail of Bits LLVM-based instrumentation tool for universal taint tracking, data-flow analysis, and tracing. It instruments programs via custom LLVM passes built on a fork of DataFlowSanitizer, tracking which input bytes flow through which functions. Results are stored in a binary TDAG (taint DAG) format. The Python package provides CLI tools and APIs for analyzing traces, extracting grammars from parsers, and visualizing data flow.

## Build & Development

**Everything runs inside Docker.** The C++ instrumentation core (LLVM passes, compiler-rt runtime, taintdag) requires a multi-stage Docker build with custom libc++ builds. You cannot build the C++ components natively on the host.

```bash
# Build the Docker image (required for C++ changes and running tests)
make docker
# Equivalent to: DOCKER_BUILDKIT=1 docker build -t trailofbits/polytracker -f Dockerfile .

# Run Python tests (inside Docker container)
make test
# Equivalent to: docker run --rm trailofbits/polytracker pytest /polytracker/tests

# Lint (runs on host, uses trunk)
make lint    # trunk check
make format  # trunk fmt
```

### Running a single Python test

```bash
docker run --rm trailofbits/polytracker pytest /polytracker/tests/test_taint_dag.py
docker run --rm trailofbits/polytracker pytest /polytracker/tests/test_taint_dag.py::test_name -v
```

### Running C++ unit tests (inside container)

```bash
docker run --rm trailofbits/polytracker /polytracker-build/unittests/src/taintdag/tests-taintdag
```

### Python package (host-side, no C++ components)

```bash
pip install -e .              # Editable install for Python-only work
pip install -e ".[dev]"       # With dev dependencies (pytest, mypy, black, flake8, Sphinx)
```

## Architecture

### Two-layer design: C++ instrumentation + Python analysis

**C++ layer** (runs at compile/runtime of target programs, inside Docker):
- `polytracker/src/compiler-rt/` — Fork of LLVM DataFlowSanitizer runtime. The core taint propagation engine.
- `polytracker/src/passes/` — LLVM instrumentation passes (taint tracking, function tracing, control-flow logging)
- `polytracker/src/taintdag/` — TDAG storage engine: manages taint labels, union operations, and the binary output format
- `polytracker/src/taint_sources/` — Hooks for taint introduction (file reads, stdin, argv, etc.)
- `polytracker/include/` — C++ headers for polytracker and taintdag

**Python layer** (`polytracker/` package, can run on host):
- `taint_dag.py` — `TDProgramTrace`: loads and queries TDAG binary files
- `tracing.py` — Abstract base classes for traces, taint regions, byte access types
- `grammars.py` — Grammar extraction from parser traces
- `parsing.py` — Binary format parsing utilities
- `build.py` — Build orchestration using [Blight](https://github.com/trailofbits/blight) for command recording
- `containerization.py` — Docker integration for `polytracker docker` commands
- `plugins.py` — Plugin/command system. Subclass `Command` to add CLI commands.
- `__main__.py` — CLI entry point; dispatches to plugin commands or launches REPL

### Build system

- **CMake** (C++20, ninja) builds the instrumentation libraries and LLVM passes
- **setuptools** (`setup.py`) packages the Python CLI/API; version derived from `polytracker/include/polytracker/polytracker.h`
- **Docker multi-stage build**: base (Ubuntu Jammy + clang-12) → LLVM 13 sources → clean libc++ → instrumented libc++ → final polytracker image
- Git submodules for third-party C++ deps: Catch2, indicators, spdlog. Run `git submodule update --init --recursive` after clone.

### Test structure

- `tests/` — Python pytest suite. Tests use fixtures from `conftest.py` that compile, instrument, and run C/C++ test programs inside the container. Test source files (`.c`, `.cpp`) live alongside the Python test files.
- `unittests/src/taintdag/` — C++ Catch2 unit tests for the taintdag engine
- CI builds Docker image first, then runs both test suites inside the container

### Key environment variables (inside Docker)

| Variable | Purpose |
|----------|---------|
| `POLYDB` | Output path for the TDAG trace database |
| `DFSAN_LIB_PATH` | Path to DataFlowSanitizer runtime library |
| `CXX_LIB_PATH` | Path to custom libc++ builds (clean and poly) |
| `COMPILER_DIR` | Path to polytracker compiler tools |
| `DFSAN_OPTIONS` | Runtime options (`strict_data_dependencies=0`) |

## Linting & Formatting

Trunk orchestrates all linters. Key tools:
- **Python**: ruff (line-length 127, target py38), black, flake8, mypy, isort, bandit
- **C++**: clang-format (LLVM style, line length 80)
- **Shell**: shellcheck, shfmt
- **Docker**: hadolint
- **GitHub Actions**: actionlint

Config files: `.ruff.toml`, `.clang-format`, `.mypy.ini`, `.trunk/trunk.yaml`

The `polytracker/src/compiler-rt/` directory is excluded from all linting (it's a vendored LLVM fork).

## CI

GitHub Actions (`build.yml`):
1. `build_linux` — Builds Docker image, uploads as artifact
2. `run_tests` — Loads image, runs `pytest /polytracker/tests`
3. `build_example` — Builds example Dockerfiles (mupdf, poppler, qpdf) in parallel

Linting runs separately via `lint.yml` using trunk.
