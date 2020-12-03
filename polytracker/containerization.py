import subprocess
import sys
from abc import ABC
from argparse import ArgumentParser
from typing import Optional

import docker
from docker.errors import NotFound as ImageNotFound
from docker.models.images import Image

from .plugins import Command, Subcommand
from .polytracker import version as polytracker_version


class DockerContainer:
    def __init__(self, image_name: str = "trailofbits/polytracker", tag: Optional[str] = None):
        self.image_name: str = image_name
        if tag is None:
            self.tag: str = polytracker_version()
        else:
            self.tag = tag
        self._client: Optional[docker.DockerClient] = None

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

    def rebuild(self):
        pass


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
    @property
    def container(self) -> DockerContainer:
        return self.parent_command.container


class DockerExists(DockerSubcommand):
    name = "exists"
    help = "checks whether the Docker container already exists"
    parent_type = DockerCommand

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
    parent_type = DockerCommand

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
