from inspect import getmembers, isclass
from pkgutil import iter_modules
from importlib import import_module

from .database import DBProgramTrace as PolyTrackerTrace
from .polytracker import *

# All of the classes in SUBMODULES_TO_SUBSUME should really be in the top-level `polytracker` module.
# They are separated into submodules solely for making the Python file sizes more manageable.
# So the following code loops over those submodules and reassigns all of the classes to the top-level module.
SUBMODULES_TO_SUBSUME = (polytracker,)  # type: ignore
for module_to_subsume in SUBMODULES_TO_SUBSUME:
    for name, obj in getmembers(module_to_subsume):
        if hasattr(obj, "__module__") and obj.__module__ == module_to_subsume.__name__:
            obj.__module__ = "polytracker"
    del module_to_subsume


# Automatically load all modules in the `polytracker` package,
# so all PolyTracker plugins will auto-register themselves:
package_dir = Path(__file__).resolve().parent
for (_, module_name, _) in iter_modules([str(package_dir)]):  # type: ignore
    if module_name == "__main__":
        continue
    # import the module and iterate through its attributes
    module = import_module(f"{__name__}.{module_name}")
    for attribute_name in dir(module):
        attribute = getattr(module, attribute_name)

        if isclass(attribute):
            # Add the class to this package's variables
            globals()[attribute_name] = attribute

del SUBMODULES_TO_SUBSUME
