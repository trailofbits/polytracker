from inspect import isclass
from pkgutil import iter_modules
from importlib import import_module

from .database import DBProgramTrace as PolyTrackerTrace
from .polytracker import *

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
