import json
import re
import subprocess
import sys
from abc import ABC
from argparse import ArgumentParser
from pathlib import Path
from tqdm import tqdm
from typing import Dict, Optional

import docker
from docker.errors import NotFound as ImageNotFound
from docker.models.images import Image

from .plugins import Command, Subcommand
from .polytracker import version as polytracker_version


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
                    elif chunk == b'\n':
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


class DockerContainer:
    def __init__(self, image_name: str = "trailofbits/polytracker", tag: Optional[str] = None):
        self.image_name: str = image_name
        if tag is None:
            self.tag: str = polytracker_version()
        else:
            self.tag = tag
        self._client: Optional[docker.DockerClient] = None
        self.dockerfile: Dockerfile = Dockerfile(Path(__file__).parent.parent / "Dockerfile")

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

    def rebuild(self, nocache: bool = False):
        if not self.dockerfile.exists():
            raise ValueError("Could not find the Dockerfile. This likely means PolyTracker was installed from PyPI "
                             "rather than from a source install from GitHub.")
        # use the low-level APIClient so we can get streaming build status
        cli = docker.APIClient()
        with tqdm(desc=f"Archiving the build directory", unit=" steps", leave=False) as t:
            last_line = 0
            last_step = None
            for raw_line in cli.build(path=str(self.dockerfile.dir()), rm=True, tag=self.name, nocache=nocache, forcerm=True):
                t.desc = f"Building {self.name}"
                for line in raw_line.split(b"\n"):
                    try:
                        line = json.loads(line)
                    except json.decoder.JSONDecodeError:
                        continue
                    if "stream" in line:
                        m = re.match(r"^Step\s+(\d+)(/(\d+))?\s+:\s+(.+)$", line["stream"], re.MULTILINE)
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
                                new_line = self.dockerfile.get_line(m.group(4), starting_line=last_line)
                                if new_line is not None:
                                    t.update(new_line - last_line)
                                    last_line = new_line
                        t.write(line["stream"].replace("\n", "").strip())


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
                sys.stderr.write(f"The docker image {self.container.name} was not found on DockerHub, "
                                 "but it does already exist locally.")
                return 1
            pass
        sys.stderr.write(f"""The docker image {self.container.name} was not found on DockerHub!
This might happen if you are running a newer version of PolyTracker than the latest release
(e.g., if you installed PolyTracker from GitHub master rather than from PyPI,
or if you are doing local development on PolyTracker.)
If you are running PolyTracker from source, try using the `polytracker docker rebuild` command instead
of `polytracker docker pull` and it will rebuild from the local Dockerfile.

""")
        while True:
            sys.stderr.write("Would you like to pull the latest version from DockerHub and tag it as version "
                             f"{self.container.tag}? [yN] ")
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
                    sys.stderr.write(f"\nTagged {self.container.image_name}:latest as {self.container.name}")
                    return 0
                else:
                    return 1
        return 1


class DockerRebuild(DockerSubcommand):
    name = "rebuild"
    help = "rebuilds the Docker container"

    def __init_arguments__(self, parser: ArgumentParser):
        parser.add_argument("--no-cache", action="store_true", help="do not used cached Docker state when rebuilding")

    def run(self, args):
        if not self.container.dockerfile.exists():
            sys.stderr.write("""It looks like PolyTracker was installed from PyPI rather than from source.
Either reinstall PolyTracker from source like this:

    $ git clone https://github.com/trailofbits/polytracker
    $ cd polytracker
    $ pip3 install -e .

or download the latest prebuilt Docker image for your preexisting PolyTracker install from DockerHub by running:

    $ polytracker docker pull
 
""")
            return 1
        self.container.rebuild(nocache=args.no_cache)
