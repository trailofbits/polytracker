from abc import ABC, ABCMeta, abstractmethod
from argparse import ArgumentParser, Namespace
from inspect import isabstract
from typing import Any, cast, Dict, Generic, List, Optional, Tuple, Type, TypeVar


PLUGINS: Dict[str, Type["Plugin"]] = {}
COMMANDS: Dict[str, Type["Command"]] = {}


class PluginMeta(ABCMeta):
    parent_type: Optional[Type["Plugin"]] = None
    parent: Optional["Plugin"]

    def __init__(cls, name, bases, clsdict):
        super().__init__(name, bases, clsdict)
        if not isabstract(cls) and name not in ("Plugin", "Command"):
            if "name" not in clsdict:
                raise TypeError(f"PolyTracker plugin {name} does not define a name")
            elif clsdict["name"] in PLUGINS:
                raise TypeError(
                    f"Cannot instaitiate class {cls.__name__} because a plugin named {name} already exists,"
                    f" implemented by class {PLUGINS[clsdict['name']]}"
                )
            PLUGINS[clsdict["name"]] = cls
            if issubclass(cls, Command):
                if "help" not in clsdict:
                    raise TypeError(f"PolyTracker command {name} does not define a help string")
                COMMANDS[clsdict["name"]] = cls


class Plugin(ABC, metaclass=PluginMeta):
    name: str

    def __init__(self, parent: Optional["Plugin"] = None):
        self.parent = parent

    @property
    def full_name(self) -> str:
        stack = [self]
        while stack[-1].parent is not None:
            stack.append(stack[-1].parent)
        names = [p.name for p in reversed(stack)]
        return " ".join(names)


class AbstractCommand(Plugin):
    help: str
    parent_parsers: Tuple[ArgumentParser, ...] = ()
    extension_types: Optional[List[Type["CommandExtension"]]] = None
    subcommand_types: Optional[List[Type["Subcommand"]]] = None
    subparser: Optional[Any] = None

    def __init__(self, argument_parser: ArgumentParser, parent: Optional[Plugin] = None):
        super().__init__(parent)
        self.subcommands: List[Subcommand] = []
        if self.extension_types is not None:
            self.extensions: List[CommandExtension] = [et(parent=self) for et in self.extension_types]
        else:
            self.extensions = []
        if self.parent is None:
            self.__init_arguments__(argument_parser)
        if self.subcommand_types is not None:
            self.subparser = argument_parser.add_subparsers(
                title="subcommand",
                description=f"subcommands for {self.name}",
                help=f"run `polytracker {self.full_name} subcommand --help` for help on a specific subcommand",
            )
            for st in self.subcommand_types:
                p = self.subparser.add_parser(st.name, parents=st.parent_parsers, help=st.help)
                s = st(argument_parser=p, parent=self)
                self.subcommands.append(s)
                p.set_defaults(func=s.run)
                s.__init_arguments__(p)
        for e in self.extensions:
            e.__init_arguments__(argument_parser)

    def __init_arguments__(self, parser: ArgumentParser):
        pass

    def __getattribute__(self, item):
        if item == "run" and Plugin.__getattribute__(self, "extensions"):
            return Plugin.__getattribute__(self, "_run")
        else:
            return Plugin.__getattribute__(self, item)

    def _run(self, args: Namespace):
        Plugin.__getattribute__(self, "run")(args)
        for extension in self.extensions:
            extension.run(self, args)

    @abstractmethod
    def run(self, args: Namespace):
        raise NotImplementedError()


C = TypeVar("C", bound=AbstractCommand)


class Command(AbstractCommand, ABC):
    def __init__(self, argument_parser: ArgumentParser):
        super().__init__(argument_parser)


class CommandExtensionMeta(PluginMeta, Generic[C]):
    def __init__(cls, name, bases, clsdict):
        super().__init__(name, bases, clsdict)
        if not isabstract(cls) and name not in ("Plugin", "Command", "Subcommand", "CommandExtension"):
            basename = "".join(c.__name__ for c in bases)
            if "parent_type" not in clsdict or clsdict["parent_type"] is None:
                raise TypeError(f"{basename} {name} does not define its `parent_type`")
            elif isabstract(clsdict["parent_type"]):
                raise TypeError(
                    f"{basename} {cls.__name__} extends off of abstract command "
                    f"{cls.parent_type.__name__}; {basename}s must extend non-abstract Commands."
                )
            elif not issubclass(cls.parent_type, AbstractCommand):
                raise TypeError(
                    f"{basename} {cls.__name__}'s `parent_type` of {clsdict['parent_type']!r} does not "
                    "extend off of Command"
                )

    @property
    def parent_command_type(self) -> Type[C]:
        return cast(Type[C], self.parent_type)

    @property
    def parent_command(self) -> C:
        return cast(C, self.parent)


class CommandExtension(Plugin, Generic[C], ABC, metaclass=CommandExtensionMeta[C]):  # type: ignore
    parent_parsers: Tuple[ArgumentParser, ...] = ()

    def __init_subclass__(cls, **kwargs):
        if not isabstract(cls):
            if cls.parent_type is None:
                raise TypeError(
                    f"CommandExtension {cls.__name__} must define the type of the command it is extending in " "`parent_type`"
                )
            elif not issubclass(cls.parent_type, AbstractCommand):
                raise TypeError(
                    f"CommandExtension {cls.__name__} has a `parent_type` of {cls.parent_type.__name__} that does not "
                    "extend off of polytracker.plugins.Command"
                )
            elif cls.parent_command_type.extension_types is None:
                cls.parent_command_type.extension_types = []
            if cls in cls.parent_command_type.extension_types:
                raise TypeError(
                    f"CommandExtension {cls.__name__} is already registered to Command " f"{cls.parent_command_type.__name__}"
                )
            cls.parent_command_type.extension_types.append(cls)

    def __init_arguments__(self, parser: ArgumentParser):
        pass

    @abstractmethod
    def run(self, command: C, args: Namespace):
        raise NotImplementedError()


class Subcommand(Generic[C], AbstractCommand, ABC, metaclass=CommandExtensionMeta[C]):  # type: ignore
    def __init_subclass__(cls, **kwargs):
        if not isabstract(cls):
            if cls.parent_type is None:
                raise TypeError(f"Subcommand {cls.__name__} must define its parent command's type in `parent_type`")
            elif not issubclass(cls.parent_type, AbstractCommand):
                raise TypeError(
                    f"Subcommand {cls.__name__} has a `parent_type` of {cls.parent_type.__name__} that does not extend "
                    "off of polytracker.plugins.Command"
                )
            elif cls.parent_command_type.subcommand_types is None:
                cls.parent_command_type.subcommand_types = []
            if cls in cls.parent_command_type.subcommand_types:
                raise TypeError(
                    f"Subcommand {cls.__name__} is already registered to Command " f"{cls.parent_command_type.__name__}"
                )
            cls.parent_command_type.subcommand_types.append(cls)


def add_command_subparsers(parser: ArgumentParser):
    subparsers = parser.add_subparsers(
        title="command",
        description="valid PolyTracker commands",
        help="run `polytracker command --help` for help on a specific command",
    )
    for name, command_type in COMMANDS.items():
        p = subparsers.add_parser(name, parents=command_type.parent_parsers, help=command_type.help)
        p.set_defaults(func=command_type(p).run)
