import os
import platform
import re
import sys
from setuptools import setup, find_packages
from typing import Optional, Tuple


PYTHON_REQUIRES = ">=3.7"
if sys.platform == "darwin":
    try:
        macos_major_version = int(platform.release().split(".")[0])
        if macos_major_version >= 20:
            # We are running macOS Big Sur or later.
            # The new shared cache on Big Sur breaks `ctypes.util.find_library`,
            # which is used by the `cxxfilt` dependency.
            # https://stackoverflow.com/questions/62587131/macos-big-sur-python-ctypes-find-library-does-not-find-libraries-ssl-corefou/63609524#63609524
            # https://github.com/python/cpython/pull/22855
            # This wasn't patched in CPython until version 3.9.1, so require that:
            PYTHON_REQUIRES = ">=3.9.1"
    except ValueError:
        pass

SETUP_DIR = os.path.dirname(os.path.realpath(__file__))
POLYTRACKER_HEADER = os.path.join(SETUP_DIR, 'polytracker', 'include', 'polytracker', 'polytracker.h')

if not os.path.exists(POLYTRACKER_HEADER):
    sys.stderr.write(f"Error loading polytracker.h!\nIt was expected to be here:\n{POLYTRACKER_HEADER}\n\n")
    exit(1)


def polytracker_version() -> Tuple[int, int, int, Optional[str]]:
    version_parts = {}
    with open(POLYTRACKER_HEADER, 'r') as f:
        for i, line in enumerate(f):
            m = re.match(r"\s*#define\s+POLYTRACKER_VERSION_([A-Za-z_0-9]+)\s+([^\s]+)\s*$", line)
            if m:
                if m[1] not in ('MAJOR', 'MINOR', 'REVISION', 'SUFFIX'):
                    sys.stderr.write(f"Warning: Ignoring unexpected #define for \"POLYTRACKER_VERSION_{m[1]}\" on line "
                                     f"{i + 1} of {POLYTRACKER_HEADER}\n")
                else:
                    version_parts[m[1]] = m[2]
    for required_part in ('MAJOR', 'MINOR', 'REVISION'):
        if required_part not in version_parts:
            sys.stderr.write(
                f"Error: #define POLYTRACKER_VERSION_{required_part} not found in {POLYTRACKER_HEADER}\n\n")
            sys.exit(1)
        try:
            version_parts[required_part] = int(version_parts[required_part])
        except ValueError:
            sys.stderr.write(
                f"Error: POLYTRACKER_VERSION_{required_part} in {POLYTRACKER_HEADER} is not an integer!\n\n")
            sys.exit(1)
    suffix = version_parts.get('SUFFIX', None)
    if suffix is not None:
        suffix = suffix.strip()
        if suffix.startswith('"') and suffix.endswith('"'):
            suffix = suffix[1:-1]
    return version_parts['MAJOR'], version_parts['MINOR'], version_parts['REVISION'], suffix


def polytracker_version_string() -> str:
    *primary, suffix = polytracker_version()
    primary = map(str, primary)
    if suffix is None:
        return '.'.join(primary)
    else:
        return f"{'.'.join(primary)}{suffix}"


CONSOLE_SCRIPTS = [
    'polytracker = polytracker.__main__:main',
    'polybuild = polytracker.build:main',
    'polybuild++ = polytracker.build:main_plus_plus'
]

setup(
    name='polytracker',
    description='API and Library for operating and interacting with PolyTracker',
    url='https://github.com/trailofbits/polytracker',
    author='Trail of Bits',
    version=polytracker_version_string(),
    packages=find_packages(),
    python_requires=PYTHON_REQUIRES,
    install_requires=[
        'cxxfilt~=0.2.2',
        'docker~=4.4.0',
        'graphviz~=0.14.1',
        'intervaltree~=3.0.2',
        'matplotlib~=3.3.0',
        'networkx~=2.4',
        'Pillow>=7.2.0',
        'prompt_toolkit~=3.0.8',
        'pygments~=2.7.3',
        'pydot~=1.4.1',
        'pygraphviz~=1.5',
        'sqlalchemy~=1.3.23',
        'tqdm>=4.59.0',  # We need at least this version to get the `delay` option
        'typing_extensions~=3.7.4.2'
    ],
    extras_require={
        "dev": ["black>=20.8b1", "mypy", "pytest", "flake8"]
    },
    entry_points={
        'console_scripts': CONSOLE_SCRIPTS
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: Utilities'
    ]
)
