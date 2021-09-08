import os
import platform
import subprocess
import sys
import sysconfig
from pathlib import Path

from setuptools import Extension, find_packages, setup
from setuptools.command.build_ext import build_ext

module_name = "extractor"

version = {}
with open("./poly-llvm/version.py") as f:
    exec(f.read(), version)

with open("README.md") as f:
    long_description = f.read()

with open("dev-requirements.txt") as f:
    dev_requirements = f.readlines()


def get_ext_filename_without_platform_suffix(filename):
    name, ext = os.path.splitext(filename)
    ext_suffix = sysconfig.get_config_var("EXT_SUFFIX")

    if ext_suffix == ext:
        return filename

    ext_suffix = ext_suffix.replace(ext, "")
    idx = name.find(ext_suffix)

    if idx == -1:
        return filename
    else:
        return name[:idx] + ext


class CMakeExtension(Extension):
    """
    This class defines a setup.py extension that stores the directory
    of the root CMake file

    """

    def __init__(self, name, cmake_lists_dir=None, **kwargs):
        Extension.__init__(self, name, sources=[], **kwargs)
        if cmake_lists_dir is None:
            self.sourcedir = os.path.dirname(os.path.abspath(__file__))
        else:
            self.sourcedir = os.path.dirname(os.path.abspath(cmake_lists_dir))


class CMakeBuild(build_ext):
    """
    This class defines a build extension
    get_ext_filename determines the expected output name of the library
    build_extension sets the appropriate cmake flags and invokes cmake to build the extension

    """

    def get_ext_filename(self, ext_name):
        filename = super().get_ext_filename(ext_name)
        return get_ext_filename_without_platform_suffix(filename)

    def _platform_cmake_args(self):
        args = []
        #if platform.system() == "Darwin":
        #    deps = {
        #        "LLVM 9": "/usr/local/opt/llvm@9",
        #    }

        #    for name, dir_ in deps.items():
        #        if not Path(dir_).is_dir():
        #            print(f"Error: Couldn't find a {name} installation at {dir_}", file=sys.stderr)
        #            sys.exit(1)

         #   prefix_path = ":".join(deps.values())
         #   args.append(f"-DCMAKE_PREFIX_PATH={prefix_path}")
        return args

    def build_extension(self, ext):
        extdir = os.path.abspath(os.path.dirname(self.get_ext_fullpath(ext.name)))

        cmake_args = []
        build_type = "Release"
        if os.getenv("DEBUG", None) is not None:
            cmake_args.append("-DCMAKE_VERBOSE_MAKEFILE=ON")
            build_type = "Debug"

        cmake_args += [
            f"-DCMAKE_BUILD_TYPE={build_type}",
            f"-DCMAKE_LIBRARY_OUTPUT_DIRECTORY={extdir}",
            f"-DPYTHON_MODULE_NAME={module_name}",
        ]
        cmake_args += self._platform_cmake_args()
        print(cmake_args)
        if not os.path.exists(self.build_temp):
            os.makedirs(self.build_temp)
        subprocess.check_call(["cmake", ext.sourcedir] + cmake_args, cwd=self.build_temp)
        subprocess.check_call(["cmake", "--build", "."], cwd=self.build_temp)


setup(
    name="poly-llvm",
    author="Carson Harmon",
    author_email="carson.harmon@trailofbits.com",
    python_requires=">=3.7",
    packages=find_packages(),
    version=version["__version__"],
    description="Syntax Guided Repair/Transformation Package",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="Apache-2.0",
    ext_package="poly-llvm",
    ext_modules=[CMakeExtension(module_name)],
    cmdclass={"build_ext": CMakeBuild},
    install_requires=["sqlalchemy ~= 1.3"],
    extras_require={"dev": dev_requirements},
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Science/Research",
        "Topic :: Software Development :: Code Generators",
    ],
)
