import argparse
import ast
import traceback
from datetime import datetime
from io import StringIO
from typing import Iterable, Set

from prompt_toolkit import HTML, print_formatted_text, PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.filters import Condition
from prompt_toolkit.formatted_text import PygmentsTokens
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.lexers import PygmentsLexer
from pygments import lex
from pygments.lexers.python import PythonLexer, PythonTracebackLexer

from .polytracker import version
from .plugins import add_command_subparsers, Command, COMMANDS


class Commands(Command):
    name = "commands"
    help = "print the PolyTracker commands"

    def run(self, args):
        longest_command = max(len(cmd_name) for cmd_name in COMMANDS)
        for command in COMMANDS.values():
            dots = "." * (longest_command - len(command.name) + 1)
            print_formatted_text(HTML(f'<b fg="ansiblue">{command.name}</b>{dots}<i> {command.help} </i>'))


class PolyTrackerCompleter(Completer):
    def __init__(self, repl: "PolyTrackerREPL"):
        self.repl: PolyTrackerREPL = repl

    @staticmethod
    def _get_completions(partial: str, options: Iterable[str], already_completed: Set[str], style: str = ""):
        for var in options:
            if var not in already_completed and var.startswith(partial) and var != partial:
                yield Completion(var, start_position=-len(partial), style=style)
                already_completed.add(var)

    def get_completions(self, document, complete_event):
        if self.repl.multi_line and document.text == "":
            # we are in a multi-line statement, and the user pressed TAB in order to indent
            return
        partial = document.text_before_cursor
        already_yielded = set()
        if partial == document.text:
            # we are at the start of the line, so complete for commands:
            yield from PolyTrackerCompleter._get_completions(partial, COMMANDS, already_yielded, "fg:ansiblue")
        yield from PolyTrackerCompleter._get_completions(
            partial, (var for var in self.repl.state if var not in self.repl.builtins), already_yielded
        )
        yield from PolyTrackerCompleter._get_completions(partial, self.repl.builtins, already_yielded, "fg:ansigreen")
        if "__builtins__" in self.repl.state:
            builtins = self.repl.state["__builtins__"]
        else:
            builtins = __builtins__
        yield from PolyTrackerCompleter._get_completions(partial, builtins, already_yielded, "fg:ansigreen")
        if "." in partial:
            portions = partial.split(".")
            varname = portions[-2]
            to_complete = portions[-1]
            if varname in self.repl.state:
                attr = self.repl.state[varname]
                yield from PolyTrackerCompleter._get_completions(
                    to_complete, (a for a in dir(attr) if not a.startswith("_")), already_yielded
                )


class PolyTrackerREPL:
    def __init__(self):
        self.session = PromptSession(lexer=PygmentsLexer(PythonLexer))
        self.state = {
            "copyright": f"Copyright (c) 2019-{datetime.today().year} Trail of Bits.\nAll Rights Reserved.",
            "credits": """    PolyTracker was developed by Carson Harmon, Evan Sultanik, and Brad Larsen at Trail of Bits.
    Thanks to Sergey Bratus of DARPA and Galois, Inc. for partially funding this work.
    Also thanks to the LLVM dfsan project for providing a framework off of which to build,
    as well as the Angora project for inspiration.
""",
        }
        self.builtins = set(self.state.keys())
        self.multi_line: bool = False

    def print_exc(self):
        buffer = StringIO()
        traceback.print_exc(file=buffer)
        tokens = lex(buffer.getvalue(), lexer=PythonTracebackLexer())
        print_formatted_text(PygmentsTokens(tokens))

    def run_python(self, command):
        continued_prompt = HTML("<b>... </b>")

        bindings = KeyBindings()

        @Condition
        def is_multi_line():
            return self.multi_line

        @bindings.add("c-h", filter=is_multi_line, eager=True)
        def _(event):
            buffer = event.app.current_buffer
            doc = buffer.document
            cursor_pos = doc.cursor_position_col
            if cursor_pos > 0 and cursor_pos % 4 == 0 and all(c == " " for c in doc.text[:cursor_pos]):
                # the user pressed BACKSPACE after an indent
                buffer.delete_before_cursor(4)
            else:
                buffer.delete_before_cursor(1)

        @bindings.add("c-i", filter=is_multi_line, eager=True)
        def _(event):
            buffer = event.app.current_buffer
            doc = buffer.document
            cursor_pos = doc.cursor_position_col
            if cursor_pos % 4 == 0 and all(c == " " for c in doc.text[:cursor_pos]):
                # the user pressed TAB intending to indent
                buffer.insert_text("    ")
            elif buffer.complete_state:
                buffer.complete_next()
            else:
                buffer.start_completion(select_first=False)

        self.multi_line = False

        try:
            while True:
                try:
                    parsed = ast.parse(command)
                    is_assignment = any(
                        isinstance(node, ast.Assign) or isinstance(node, ast.AnnAssign) or isinstance(node, ast.AugAssign)
                        for node in ast.walk(parsed)
                    )
                    break
                except IndentationError as e:
                    if e.msg.startswith("expected an indented block"):
                        self.multi_line = True
                    else:
                        raise e
                except SyntaxError as e:
                    if e.msg.startswith("unexpected EOF"):
                        self.multi_line = True
                    else:
                        raise e
                if self.multi_line:
                    next_line = self.session.prompt(
                        continued_prompt,
                        complete_while_typing=True,
                        auto_suggest=AutoSuggestFromHistory(),
                        completer=PolyTrackerCompleter(self),
                        key_bindings=bindings,
                    )
                    if len(next_line) == 0:
                        is_assignment = True
                        break
                    command = f"{command}\n{next_line}"

            if is_assignment or self.multi_line:
                exec(command, self.state)
            else:
                print(eval(command, self.state))
        finally:
            self.multi_line = False

    def run(self):
        argparser = argparse.ArgumentParser()
        add_command_subparsers(argparser)

        print_formatted_text(HTML(f"<b>PolyTracker</b> ({version()})"))
        print_formatted_text(HTML('<u fg="ansigray">https://github.com/trailofbits/polytracker</u>'))
        print_formatted_text(
            HTML(
                'Type "<span fg="ansigreen" bg="ansigray">help</span>" or "<span fg="ansiblue" bg="ansigray">commands</span>"'
            )
        )
        prompt = HTML("<b>&gt;&gt;&gt; </b>")
        error_prompt = HTML('<span fg="ansired" bg="ansiwhite">!</span><b>&gt;&gt; </b>')
        next_prompt = prompt
        while True:
            try:
                text = self.session.prompt(
                    next_prompt,
                    complete_while_typing=True,
                    auto_suggest=AutoSuggestFromHistory(),
                    completer=PolyTrackerCompleter(self),
                )
                next_prompt = prompt
            except KeyboardInterrupt:
                next_prompt = error_prompt
                continue
            except EOFError:
                break
            raw_args = text.split(" ")
            is_cmd = raw_args and raw_args[0] in COMMANDS
            if is_cmd:
                try:
                    try:
                        args = argparser.parse_args(raw_args)
                        if hasattr(args, "func"):
                            try:
                                retval = args.func(args)
                                if retval is not None and retval != 0:
                                    next_prompt = error_prompt
                            except KeyboardInterrupt:
                                next_prompt = error_prompt
                            except SystemExit:
                                next_prompt = error_prompt
                            except:
                                self.print_exc()
                                next_prompt = error_prompt
                    except SystemExit:
                        next_prompt = error_prompt
                except:
                    self.print_exc()
                    next_prompt = error_prompt
            else:
                # assume it is a Python command
                try:
                    self.run_python(text)
                except NameError as e:
                    print(str(e))
                    next_prompt = error_prompt
                except SystemExit:
                    break
                except:
                    self.print_exc()
                    next_prompt = error_prompt
        return 0
