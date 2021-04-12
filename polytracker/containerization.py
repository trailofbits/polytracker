import json
import os
import platform
import re
import subprocess
import sys
from abc import ABC
from argparse import ArgumentParser
from pathlib import Path
from tqdm import tqdm
from typing import Dict, Iterable, List, Optional, Tuple, Union

import docker
from docker.errors import NotFound as ImageNotFound
from docker.models.images import Image

from .plugins import Command, Subcommand
from .polytracker import version as polytracker_version
from .repl import PolyTrackerREPL


IS_LINUX: bool = platform.system() == "Linux"
CAN_RUN_NATIVELY: bool = (
    IS_LINUX
    and os.getenv("POLYTRACKER_CAN_RUN_NATIVELY", "0") != "0"
    and os.getenv("POLYTRACKER_CAN_RUN_NATIVELY", "") != ""
)
PolyTrackerREPL.register_global("CAN_RUN_NATIVELY", CAN_RUN_NATIVELY)


class Dockerfile:
    def __init__(self, path: Path):
        self.path: Path = path
        self._len: Optional[int] = None
        self._line_offsets: Dict[int, int] = {}

    def exists(self) -> bool:
        return self.path.exists()

    def dir(self) -> Path:
        return self.path.parent

    def __len__(self) -> int:
        """Returns the number of lines in the file"""
        if self._len is None:
            self._len = 0
            self._line_offsets[0] = 0  # line 0 starts at offset 0
            offset = 0
            with open(self.path, "rb") as f:
                while True:
                    chunk = f.read(1)
                    if len(chunk) == 0:
                        break
                    elif chunk == b"\n":
                        self._len += 1
                        self._line_offsets[self._len] = offset + 1
                    offset += 1
        return self._len

    def get_line(self, step_command: str, starting_line: int = 0) -> Optional[int]:
        """Returns the line number of the associated step command"""
        if self._len is None:
            # we need to call __len__ to set self._line_offsets
            _ = len(self)
        if starting_line not in self._line_offsets:
            return None
        with open(self.path, "r") as f:
            f.seek(self._line_offsets[starting_line])
            line_offset = 0
            while True:
                line = f.readline()
                if line == "":
                    break
                elif line == step_command:
                    return starting_line + line_offset
                line_offset += 1
            return None


class DockerOutOfDateError(RuntimeError):
    """An error when the docker image is older than the PolyTracker source code"""

    def __init__(self, message: str, container: "DockerContainer"):
        super().__init__(message)
        self.container: DockerContainer = container


class DockerContainer:
    def __init__(
        self, image_name: str = "trailofbits/polytracker", tag: Optional[str] = None
    ):
        self.image_name: str = image_name
        if tag is None:
            self.tag: str = polytracker_version()
        else:
            self.tag = tag
        self._client: Optional[docker.DockerClient] = None
        self.dockerfile: Dockerfile = Dockerfile(
            Path(__file__).parent.parent / "Dockerfile"
        )
        self._out_of_date_sources: Optional[List[Path]] = None

    def out_of_date_sources(self) -> List[Path]:
        """Returns the PolyTracker source files that were modified after this container was built"""
        if self._out_of_date_sources is None:
            container_build_time = self.last_build_time()
            self._out_of_date_sources = []
            if container_build_time is None:
                # this container was never built!
                return self._out_of_date_sources
            root_dir = Path(__file__).parent.parent
            source_files: List[Path] = [root_dir / "Dockerfile", root_dir / "setup.py"]
            for f in source_files:
                if not f.exists():
                    # PolyTracker was not installed from source
                    return self._out_of_date_sources
            source_files.extend(
                p
                for p in (root_dir / "polytracker").glob("**/*")
                if "__pycache__" not in str(p) and not p.suffix == ".py"
            )
            for path in source_files:
                mtime = path.stat().st_mtime
                if mtime > container_build_time:
                    self._out_of_date_sources.append(path)
        return self._out_of_date_sources

    def last_build_time(self) -> Optional[int]:
        """Returns the last time this image was rebuilt as the number of seconds since the UNIX epoch,
        or None if the container has not yet been built"""

        image: Optional[Image] = self.exists()
        if image is None:
            return None

        time: Optional[int] = None

        for line in image.history():
            if "Created" in line:
                ctime: int = line["Created"]  # type: ignore
                if time is None or ctime > time:
                    time = ctime
        return time

    def run(
        self,
        *args: str,
        build_if_necessary: bool = True,
        check_if_docker_out_of_date: bool = True,
        remove: bool = True,
        interactive: bool = True,
        mounts: Optional[Iterable[Tuple[Union[str, Path], Union[str, Path]]]] = None,
        env: Optional[Dict[str, str]] = None,
        stdin=None,
        stdout=None,
        stderr=None,
        cwd=None,
    ) -> int:
        if not self.exists():
            if build_if_necessary:
                if self.dockerfile.exists():
                    self.rebuild(nocache=True)
                else:
                    self.pull()
                if not self.exists():
                    raise ValueError(f"{self.name} does not exist!")
            else:
                raise ValueError(
                    f"{self.name} does not exist! Re-run with `build_if_necessary=True` to automatically "
                    "build it."
                )
        elif check_if_docker_out_of_date and len(self.out_of_date_sources()) > 0:
            oods = [
                str(s.relative_to(self.dockerfile.path.parent))
                for s in self.out_of_date_sources()
            ]
            raise DockerOutOfDateError(
                f"Docker container {self.name} relies on the following source files "
                "that were modified after the container was last built: "
                f"{', '.join(oods)}",
                self,
            )
        if cwd is None:
            cwd = str(Path.cwd())

        if mounts is None:
            mounts = ((cwd, "/workdir"),)

        # Call out to the actual Docker command instead of the Python API because it has better support for interactive
        # TTYs

        if interactive and (
            stdin is not None or stdout is not None or stderr is not None
        ):
            raise ValueError(
                "if `interactive == True`, all of `stdin`, `stdout`, and `stderr` must be `None`"
            )

        cmd_args = ["/usr/bin/env", "docker", "run", "-w=/workdir"]

        if interactive:
            cmd_args.append("-it")

        if remove:
            cmd_args.append("--rm")

        for source, target in mounts:
            cmd_args.append("-v")
            cmd_args.append(f"{source!s}:{target!s}:cached")

        if env is not None:
            for k, v in env.items():
                cmd_args.append("-e")
                escaped_value = v.replace('"', '\\"')
                cmd_args.append(f"{k}={escaped_value}")

        cmd_args.append(self.name)

        cmd_args.extend(args)

        if interactive:
            return subprocess.call(cmd_args, cwd=cwd)
        else:
            return subprocess.run(
                cmd_args, stdin=stdin, stdout=stdout, stderr=stderr, cwd=cwd
            ).returncode

        # self.client.containers.run(self.name, args, remove=remove, mounts=[
        #     Mount(target=str(target), source=str(source), consistency="cached") for source, target in mounts
        # ])

    @property
    def name(self) -> str:
        return f"{self.image_name}:{self.tag}"

    @property
    def client(self) -> docker.DockerClient:
        if self._client is None:
            self._client = docker.from_env()
        return self._client

    def exists(self) -> Optional[Image]:
        for image in self.client.images.list():
            if self.name in image.tags:
                return image
        return None

    def pull(self, latest: bool = False) -> Image:
        # We could use the Python API to pull, like this:
        #     return self.client.images.pull(self.image_name, tag=[self.tag, None][latest])
        # However, that doesn't include progress bars. So call the `docker` command instead:
        name = f"{self.image_name}:{[self.tag, 'latest'][latest]}"
        try:
            subprocess.check_call(["docker", "pull", name])
            for image in self.client.images.list():
                if name in image.tags:
                    return image
        except subprocess.CalledProcessError:
            pass
        raise ImageNotFound(name)

    def rebuild(self, nocache: bool = False, tag_as_latest: bool = True):
        if not self.dockerfile.exists():
            raise ValueError(
                "Could not find the Dockerfile. This likely means PolyTracker was installed from PyPI "
                "rather than from a source install from GitHub."
            )
        # use the low-level APIClient so we can get streaming build status
        cli = docker.APIClient()
        with tqdm(
            desc="Archiving the build directory", unit=" steps", leave=False
        ) as t:
            last_line = 0
            last_step = None
            for raw_line in cli.build(
                path=str(self.dockerfile.dir()),
                rm=True,
                tag=self.name,
                nocache=nocache,
                forcerm=True,
            ):
                t.desc = f"Building {self.name}"
                for line in raw_line.split(b"\n"):
                    try:
                        line = json.loads(line)
                    except json.decoder.JSONDecodeError:
                        continue
                    if "stream" in line:
                        m = re.match(
                            r"^Step\s+(\d+)(/(\d+))?\s+:\s+(.+)$",
                            line["stream"],
                            re.MULTILINE,
                        )
                        if m:
                            if m.group(3):
                                # Docker told us the total number of steps!
                                total_steps = int(m.group(3))
                                current_step = int(m.group(1))
                                if last_step is None:
                                    t.total = total_steps
                                    last_step = 0
                                t.update(current_step - last_step)
                                last_step = current_step
                            else:
                                # Docker didn't tell us the total number of steps, so infer it from our line
                                # number in the Dockerfile
                                t.total = len(self.dockerfile)
                                new_line = self.dockerfile.get_line(
                                    m.group(4), starting_line=last_line
                                )
                                if new_line is not None:
                                    t.update(new_line - last_line)
                                    last_line = new_line
                        t.write(line["stream"].replace("\n", "").strip())
        if tag_as_latest:
            cli.tag(self.name, self.image_name, "latest")


class DockerCommand(Command):
    name = "docker"
    help = "commands for seamlessly running PolyTracker in a Docker container"
    parser: ArgumentParser
    container: DockerContainer

    def __init_arguments__(self, parser: ArgumentParser):
        self.parser = parser
        self.container = DockerContainer()

    def run(self, args):
        self.parser.print_help()


class DockerSubcommand(Subcommand[DockerCommand], ABC):
    parent_type = DockerCommand

    @property
    def container(self) -> DockerContainer:
        return self.parent_command.container


class DockerExists(DockerSubcommand):
    name = "exists"
    help = "checks whether the Docker container already exists"

    def __init_arguments__(self, parser: ArgumentParser):
        pass

    def run(self, args):
        image = self.container.exists()
        if image is None:
            sys.stderr.write(f"The docker image {self.container.name} does not exist\n")
        else:
            sys.stderr.write(f"{self.container.name} exists with ID ")
            sys.stderr.flush()
            print(image.id)


class DockerPull(DockerSubcommand):
    name = "pull"
    help = "pulls the latest PolyTracker Docker image from DockerHub"

    def __init_arguments__(self, parser: ArgumentParser):
        pass

    def run(self, args):
        try:
            self.container.pull()
            return 0
        except ImageNotFound:
            if self.container.exists():
                sys.stderr.write(
                    f"The docker image {self.container.name} was not found on DockerHub, "
                    "but it does already exist locally."
                )
                return 1
            pass
        sys.stderr.write(
            f"""The docker image {self.container.name} was not found on DockerHub!
This might happen if you are running a newer version of PolyTracker than the latest release
(e.g., if you installed PolyTracker from GitHub master rather than from PyPI,
or if you are doing local development on PolyTracker.)
If you are running PolyTracker from source, try using the `polytracker docker rebuild` command instead
of `polytracker docker pull` and it will rebuild from the local Dockerfile.

"""
        )
        while True:
            sys.stderr.write(
                "Would you like to pull the latest version from DockerHub and tag it as version "
                f"{self.container.tag}? [yN] "
            )
            sys.stderr.flush()
            try:
                result = input()
            except EOFError:
                break
            if result == "" or result.lower() == "n":
                break
            elif result.lower() == "y":
                image = self.container.pull(latest=True)
                if image.tag(self.container.image_name, self.container.tag):
                    sys.stderr.write(
                        f"\nTagged {self.container.image_name}:latest as {self.container.name}"
                    )
                    return 0
                else:
                    return 1
        return 1


class DockerRebuild(DockerSubcommand):
    name = "rebuild"
    help = "rebuilds the Docker container"

    def __init_arguments__(self, parser: ArgumentParser):
        parser.add_argument(
            "--no-cache",
            action="store_true",
            help="do not used cached Docker state when rebuilding",
        )
        parser.add_argument(
            "--no-tag-latest",
            action="store_true",
            help=f"by default, the rebuilt image will be tagged as both trailofbits/polytracker:{polytracker_version()}"
                 " as well as trailofbits/polytracker:latest. This option will only tag it by the version and not"
                 " tag it as :latest."
        )

    def run(self, args):
        if not self.container.dockerfile.exists():
            sys.stderr.write(
                """It looks like PolyTracker was installed from PyPI rather than from source.
Either reinstall PolyTracker from source like this:

    $ git clone https://github.com/trailofbits/polytracker
    $ cd polytracker
    $ pip3 install -e .

or download the latest prebuilt Docker image for your preexisting PolyTracker install from DockerHub by running:

    $ polytracker docker pull

"""
            )
            return 1
        self.container.rebuild(nocache=args.no_cache, tag_as_latest=not args.no_tag_latest)


class DockerRun(DockerSubcommand):
    name = "run"
    help = "runs the Docker container"

    def __init_arguments__(self, parser: ArgumentParser):
        parser.add_argument(
            "ARGS",
            nargs="*",
            help="command to run in the container (by default it will open a shell)",
        )
        parser.add_argument(
            "--notty",
            action="store_true",
            help="do not run the Docker container in interactive mode",
        )

    def run(self, args):
        return DockerRun.run_on(self.container, args.ARGS, notty=args.notty)

    @staticmethod
    @PolyTrackerREPL.register("docker_run", discardable=True)
    def run_on(
        container: Optional[DockerContainer] = None,
        args=(),
        interactive: Optional[bool] = None,
        notty: bool = False,
        **kwargs,
    ) -> int:
        """
        Runs PolyTracker inside Docker and returns the exit code.

        Running with no arguments will enter into an interactive Docker session,
        mounting the current working directory to `/workdir`.
        """
        if container is None:
            container = DockerContainer()
        if interactive is None:
            interactive = not notty
        try:
            return container.run(
                *args,
                interactive=interactive,
                check_if_docker_out_of_date=True,
                **kwargs,
            )
        except DockerOutOfDateError as e:
            out_of_date_error = e
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            raise out_of_date_error
        sys.stderr.write(str(out_of_date_error))
        while True:
            sys.stderr.write(
                "\nWould you like to rebuild the Docker image before running? [Yn] "
            )
            sys.stderr.flush()
            option = input()
            if option.lower() == "n":
                break
            elif option.lower() == "y" or option == "":
                sys.stderr.write(
                    f"By default, the new image will be tagged as trailofbits/polytracker:{polytracker_version()}."
                )
                while True:
                    sys.stderr.write(
                        "\nWould you like to also tag it as trailofbits/polytracker:latest? [Yn] "
                    )
                    sys.stderr.flush()
                    option = input()
                    if option.lower() == "n":
                        tag_as_latest = False
                        break
                    elif option.lower() == "y" or option == "":
                        tag_as_latest = True
                        break
                container.rebuild(nocache=True, tag_as_latest=tag_as_latest)
                break
        return container.run(
            *args, interactive=interactive, check_if_docker_out_of_date=False, **kwargs
        )
