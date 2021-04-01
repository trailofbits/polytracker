from polytracker import plugins
import pytest
import logging

logger = logging.getLogger("test_plugins:")


#############################
#      Tests go here        #
#############################


def test_plugin_name_collision():
    class P1(plugins.Plugin):
        name = "foo"

    with pytest.raises(TypeError):

        class P2(plugins.Plugin):
            name = "foo"


def test_incomplete_command():
    with pytest.raises(
        TypeError, match="PolyTracker command MissingHelp does not define a help string"
    ):

        class MissingHelp(plugins.Command):
            name = "missinghelp"

            def __init_arguments__(self, parser):
                pass

            def run(self, args):
                pass

    class HasHelp(plugins.Command):
        name = "good"
        help = "help"

        def __init_arguments__(self, parser):
            pass

        def run(self, args):
            pass


def test_subcommand_assignment():
    class C1(plugins.Command):
        name = "command1"
        help = ""

        def __init_arguments__(self, parser):
            pass

        def run(self, args):
            pass

    with pytest.raises(
        TypeError,
        match="Subcommand MissingParent must define its parent command's type in `parent_type`",
    ):

        class MissingParent(plugins.Subcommand[C1]):
            name = "subcommand"
            help = ""

            def __init_arguments__(self, parser):
                pass

            def run(self, args):
                pass

    with pytest.raises(
        TypeError,
        match="Subcommand BadParent has a `parent_type` of Plugin that does not extend off of "
        "polytracker.plugins.Command",
    ):

        class BadParent(plugins.Subcommand[C1]):
            name = "subcommand"
            help = ""
            parent_type = (
                plugins.Plugin
            )  # This should actually be a subclass of Command

            def __init_arguments__(self, parser):
                pass

            def run(self, args):
                pass

    class GoodSubcommand(plugins.Subcommand[C1]):
        name = "subcommand"
        help = ""
        parent_type = C1

        def __init_arguments__(self, parser):
            pass

        def run(self, args):
            pass
