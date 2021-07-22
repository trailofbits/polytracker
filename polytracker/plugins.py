"""A module containing base classes for implementing PolyTracker plugins and commands.

For extending the REPL, see :mod:`polytracker.repl`.


Examples:

    Let's say you want to implement a new command called ``foo`` that can be executed at the command line by running

    .. code-block:: console

        $ polytracker foo

    All you have to do is extend :class:`Command`::

        class Foo(Command):
            name = "foo"
            help = "This is the foo command!"

            def run(self, args: Namespace):
                print("Inside foo!")
                return 0

    Simply extending the :class:`Command` class will automatically register the command.

    .. code-block:: console

        $ polytracker foo --help
        usage: polytracker foo [-h]

        optional arguments:
          -h, --help  show this help message and exit
        $ polytracker foo
        Inside foo!

    To add additional command line arguments, extend the :meth:`Command.__init_arguments__` function::

        class Foo(Command):
            name = "foo"
            help = "This is the foo command!"

            def __init_arguments__(parser: ArgumentParser):
                parser.add_argument("--bar", type=str, help="baz")

            def run(self, args: Namespace):
                print(f"Inside foo: {bar!r}")
                return 0

    .. code-block:: console

        $ polytracker foo --bar baz
        Inside foo: "baz"

    Next, say you want to add a subcommand to ``foo`` called ``asdf``:

    .. code-block:: console

        $ polytracker foo asdf
        Do something completely different!

    You can do this by subclassing :class:`Subcommand`::

        class ASDF(Subcommand[Foo]):
            name = "asdf"
            help = "a subcommand of foo"
            parent_type = Foo

            def __init_arguments__(self, parser):
                parser.add_argument("QWERTY", type=str, help="another argument")

            def run(self, args: Namespace):
                print("Inside ASDF: {args.QWERTY!r}")

    The idea behind subcommands is that they allow you to programmatically extend *any* existing command without having
    to edit the code in which the parent command is implemented.

"""

from abc import ABC, ABCMeta, abstractmethod
from argparse import ArgumentParser, Namespace
from inspect import isabstract
from typing import (
    Any,
    cast,
    Dict,
    Generic,
    Iterable,
    List,
    Optional,
    Tuple,
    Type,
    TypeVar,
)


PLUGINS: Dict[str, Type["Plugin"]] = {}
"""A global dictionary mapping plugin names to their types."""
COMMANDS: Dict[str, Type["Command"]] = {}
"""A global dictionary mapping commands to their types."""


class PluginMeta(ABCMeta):
    """Metaclass for PolyTracker plugins."""

    parent_type: Optional[Type["Plugin"]] = None
    """The type of this plugin's parent plugin, in the case of sub-plugins."""

    def __init__(cls, name, bases, clsdict):
        super().__init__(name, bases, clsdict)
        if not isabstract(cls) and name not in ("Plugin", "Command"):
            if "plugin_name" in clsdict:
                plugin_name = clsdict["plugin_name"]
            elif "name" in clsdict:
                plugin_name = clsdict["name"]
            else:
                raise TypeError(f"PolyTracker plugin {name} does not define a name")
            if plugin_name in PLUGINS:
                raise TypeError(
                    f"Cannot instaitiate class {cls.__name__} because a plugin named {plugin_name} already exists,"
                    f" implemented by class {PLUGINS[plugin_name]}"
                )
            PLUGINS[plugin_name] = cls
            if issubclass(cls, Command):
                if "help" not in clsdict:
                    raise TypeError(f"PolyTracker command {name} does not define a help string")
                COMMANDS[clsdict["name"]] = cls


class Plugin(ABC, metaclass=PluginMeta):
    """Abstract base class for all PolyTracker plugins.

    At a minimum, a plugin must define a unique :attr:`name` class member.

    """

    name: str
    """The name of this plugin."""
    parent: Optional["Plugin"]
    """The parent of this plugin, if it is a sub-plugin."""

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
    """Abstract base class for PolyTracker commands.

    A PolyTracker command is exposed as a command line option.

    """

    help: str
    """Help string for this command."""
    parent_parsers: Tuple[ArgumentParser, ...] = ()
    """An optional sequence of parent argument parsers from which to parse options."""
    extension_types: Optional[List[Type["CommandExtension"]]] = None
    """An auto-populated list of eny extensions to this command."""
    subcommand_types: Optional[List[Type["Subcommand"]]] = None
    """An auto-populated list of subcommands of this command."""
    subparser: Optional[Any] = None
    """A subparser, auto-populated if subcommand_types is not ``None``."""

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
        """Initializes this command's argument parser.

        Subclasses should extend this function and add any necessary options to ``parser``.

        """
        pass

    def __getattribute__(self, item):
        if item == "run" and Plugin.__getattribute__(self, "extensions"):
            return Plugin.__getattribute__(self, "_run")
        else:
            return Plugin.__getattribute__(self, item)

    def _run(self, args: Namespace):
        Plugin.__getattribute__(self, "run")(args)
        # Fixme: Do extensions really need to be run every time?
        for extension in self.extensions:
            extension.run(self, args)

    @abstractmethod
    def run(self, args: Namespace):
        """Callback for when the command is run.

        Args:
            args: The result of parsing the commandline arguments set up by :meth:`Command.__init_arguments__`.

        """
        raise NotImplementedError()


C = TypeVar("C", bound=AbstractCommand)


class Command(AbstractCommand, ABC):
    """A base command class."""

    def __init__(self, argument_parser: ArgumentParser):
        super().__init__(argument_parser)


def _lookup_class_property(name: str, bases: Iterable[Type], clsdict: Dict[str, Any]) -> Any:
    if name in clsdict:
        return clsdict[name]
    for base in bases:
        try:
            return _lookup_class_property(name, (), base.__dict__)
        except KeyError:
            pass
    raise KeyError(name)


class CommandExtensionMeta(PluginMeta, Generic[C]):
    """A metaclass for command extensions."""

    def __init__(cls, name, bases, clsdict):
        if not isabstract(cls) and name not in (
            "Plugin",
            "Command",
            "Subcommand",
            "CommandExtension",
        ):
            basename = "".join(c.__name__ for c in bases)
            try:
                parent_type = _lookup_class_property("parent_type", bases, clsdict)
                has_parent_type = parent_type is not None
            except KeyError:
                parent_type = None
                has_parent_type = False
            if not has_parent_type:
                raise TypeError(f"{basename} {name} does not define its `parent_type`")
            elif isabstract(parent_type):
                raise TypeError(
                    f"{basename} {cls.__name__} extends off of abstract command "
                    f"{cls.parent_type.__name__}; {basename}s must extend non-abstract Commands."
                )
            elif not issubclass(cls.parent_type, AbstractCommand):
                raise TypeError(
                    f"{basename} {cls.__name__}'s `parent_type` of {clsdict['parent_type']!r} does not "
                    "extend off of Command"
                )
            if "plugin_name" not in clsdict:
                if hasattr(parent_type, "plugin_name"):
                    parent_plugin_name = parent_type.plugin_name
                else:
                    parent_plugin_name = parent_type.name
                clsdict["plugin_name"] = f"{parent_plugin_name}_{clsdict['name']}"
        super().__init__(name, bases, clsdict)

    @property
    def parent_command_type(self) -> Type[C]:
        """Returns the type of this command extension's parent command."""
        return cast(Type[C], self.parent_type)


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

    @property
    def parent_command(self) -> C:
        """Returns the parent command associated with this extension"""
        return cast(C, self.parent)

    @abstractmethod
    def run(self, command: C, args: Namespace):
        raise NotImplementedError()


class Subcommand(Generic[C], AbstractCommand, ABC, metaclass=CommandExtensionMeta[C]):  # type: ignore
    """An abstract class for PolyTracker subcommands."""

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

    @property
    def parent_command(self) -> C:
        """Returns the parent command associated with this subcommand."""
        return cast(C, self.parent)


def add_command_subparsers(parser: ArgumentParser):
    """Adds subparsers for all PolyTracker commands"""
    subparsers = parser.add_subparsers(
        title="command",
        description="valid PolyTracker commands",
        help="run `polytracker command --help` for help on a specific command",
    )
    for name, command_type in COMMANDS.items():
        p = subparsers.add_parser(name, parents=command_type.parent_parsers, help=command_type.help)
        p.set_defaults(func=command_type(p).run)
    return subparsers
