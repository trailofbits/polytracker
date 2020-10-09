import logging
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Union

from .cfg import CFG, FunctionInfo
from .taint_forest import TaintForest

log = logging.getLogger("PolyTracker")

VersionElement = Union[int, str]


class ProgramTrace:
    def __init__(self, version: Tuple[VersionElement, ...], function_data: Iterable[FunctionInfo]):
        self.polytracker_version: Tuple[VersionElement, ...] = version
        self.functions: Dict[str, FunctionInfo] = {f.name: f for f in function_data}
        self._cfg: Optional[CFG] = None

    @property
    def cfg(self) -> CFG:
        if self._cfg is not None:
            return self._cfg
        self._cfg = CFG()
        self._cfg.add_nodes_from(self.functions.values())
        for f in list(self.functions.values()):
            for caller in f.called_from:
                if caller not in self.functions:
                    info = FunctionInfo(caller, {})
                    self.functions[caller] = info
                    self._cfg.add_node(info)
                    self._cfg.add_edge(info, f)
                else:
                    self._cfg.add_edge(self.functions[caller], f)
        return self._cfg

    def diff(self, trace: "ProgramTrace"):
        print(next(iter(self.functions.values())).input_bytes)

    def __repr__(self):
        return f"{self.__class__.__name__}(polytracker_version={self.polytracker_version!r}, function_data={list(self.functions.values())!r})"


POLYTRACKER_JSON_FORMATS: List[Tuple[Tuple[str, ...], Callable[[dict], ProgramTrace]]] = []


def normalize_version(*version: Iterable[VersionElement]) -> Tuple[Any, ...]:
    version = tuple(str(v) for v in version)
    version = tuple(version) + ("0",) * (3 - len(version))
    version = tuple(version) + ("",) * (4 - len(version))
    return version


def polytracker_version(*version):
    def wrapper(func):
        POLYTRACKER_JSON_FORMATS.append((normalize_version(*version), func))
        POLYTRACKER_JSON_FORMATS.sort(reverse=True)
        return func

    return wrapper


def parse(polytracker_json_obj: dict, polytracker_forest_path: Optional[str] = None) -> ProgramTrace:
    if "version" in polytracker_json_obj:
        version = normalize_version(*polytracker_json_obj["version"].split("."))
        if len(version) > 4:
            log.warning(f"Unexpectedly long PolyTracker version: {polytracker_json_obj['version']!r}")
        for i, (known_version, parser) in enumerate(POLYTRACKER_JSON_FORMATS):
            # POLYTRACKER_JSON_FORMATS is auto-sorted in decreasing order
            if version >= known_version:
                if i == 0 and version > known_version:
                    log.warning(
                        f"PolyTracker version {polytracker_json_obj['version']!r} "
                        "is newer than the latest supported by the polytracker Python module "
                        f"({'.'.join(known_version)})"
                    )
                if int(known_version[0]) >= 2 and int(known_version[1]) > 0:
                    if polytracker_forest_path is None:
                        raise ValueError("A polytracker taint forest binary is required for version "
                                         f"{'.'.join(map(str, known_version))} and above")
                    else:
                        return parser(polytracker_json_obj, polytracker_forest_path)
        raise ValueError(f"Unsupported PolyTracker version {polytracker_json_obj['version']!r}")
    for function_name, function_data in polytracker_json_obj.items():
        if isinstance(function_data, dict) and "called_from" in function_data:
            # this is the second version of the output format
            return parse_format_v2(polytracker_json_obj)
        else:
            return parse_format_v1(polytracker_json_obj)
    return parse_format_v1(polytracker_json_obj)


@polytracker_version(0, 0, 1, "")
def parse_format_v1(polytracker_json_obj: dict) -> ProgramTrace:
    return ProgramTrace(
        version=(0, 0, 1),
        function_data=[
            FunctionInfo(function_name, {"": taint_bytes}) for function_name, taint_bytes in polytracker_json_obj.items()
        ],
    )


@polytracker_version(0, 0, 1, "alpha2.1")
def parse_format_v2(polytracker_json_obj: dict) -> ProgramTrace:
    function_data = []
    for function_name, data in polytracker_json_obj.items():
        if "input_bytes" not in data:
            if "cmp_bytes" in data:
                input_bytes = data["cmp_bytes"]
            else:
                input_bytes = {}
        else:
            input_bytes = data["input_bytes"]
        if "cmp_bytes" in data:
            cmp_bytes = data["cmp_bytes"]
        else:
            cmp_bytes = input_bytes
        if "called_from" in data:
            called_from = data["called_from"]
        else:
            called_from = ()
        function_data.append(
            FunctionInfo(name=function_name, cmp_bytes=cmp_bytes, input_bytes=input_bytes, called_from=called_from)
        )
    return ProgramTrace(version=(0, 0, 1, "alpha2.1"), function_data=function_data)


@polytracker_version(2, 0, 1)
@polytracker_version(2, 0, 0)
@polytracker_version(1, 0, 1)
def parse_format_v3(polytracker_json_obj: dict) -> ProgramTrace:
    version = polytracker_json_obj["version"].split(".")
    function_data = []
    tainted_functions = set()
    for function_name, data in polytracker_json_obj["tainted_functions"].items():
        if "input_bytes" not in data:
            if "cmp_bytes" in data:
                input_bytes = data["cmp_bytes"]
            else:
                input_bytes = {}
        else:
            input_bytes = data["input_bytes"]
        if "cmp_bytes" in data:
            cmp_bytes = data["cmp_bytes"]
        else:
            cmp_bytes = input_bytes
        if function_name in polytracker_json_obj["runtime_cfg"]:
            called_from = frozenset(polytracker_json_obj["runtime_cfg"][function_name])
        else:
            called_from = frozenset()
        function_data.append(
            FunctionInfo(name=function_name, cmp_bytes=cmp_bytes, input_bytes=input_bytes, called_from=called_from)
        )
        tainted_functions.add(function_name)
    # Add any additional functions from the CFG that didn't operate on tainted bytes
    for function_name in polytracker_json_obj["runtime_cfg"].keys() - tainted_functions:
        function_data.append(
            FunctionInfo(name=function_name, cmp_bytes={}, called_from=polytracker_json_obj["runtime_cfg"][function_name])
        )
    return ProgramTrace(version=version, function_data=function_data)


class TaintForestFunctionInfo(FunctionInfo):
    def __init__(
        self,
        name: str,
        forest: TaintForest,
        cmp_byte_labels: Dict[str, List[int]],
        input_byte_labels: Optional[Dict[str, List[int]]] = None,
        called_from: Iterable[str] = (),
    ):
        super().__init__(name=name, cmp_bytes={}, called_from=called_from)
        self.forest: TaintForest = forest
        self.cmp_byte_labels: Dict[str, List[int]] = cmp_byte_labels
        if input_byte_labels is None:
            self.input_byte_labels: Dict[str, List[int]] = self.cmp_byte_labels
        else:
            self.input_byte_labels = input_byte_labels
        self._cached_input_bytes: Optional[Dict[str, List[int]]] = None
        self._cached_cmp_bytes: Optional[Dict[str, List[int]]] = None

    @property
    def input_bytes(self) -> Dict[str, List[int]]:
        if self._cached_input_bytes is None:
            self._cached_input_bytes = {
                source: sorted(self.forest.tainted_bytes(*labels)) for source, labels in self.input_byte_labels.items()
            }
        return self._cached_input_bytes

    @property
    def cmp_bytes(self) -> Dict[str, List[int]]:
        if self._cached_cmp_bytes is None:
            self._cached_cmp_bytes = {
                source: list(self.forest.tainted_bytes(*labels)) for source, labels in self.cmp_byte_labels.items()
            }
        return self._cached_cmp_bytes


@polytracker_version(2, 2, 0)
def parse_format_v4(polytracker_json_obj: dict, polytracker_forest_path: str) -> ProgramTrace:
    version = polytracker_json_obj["version"].split(".")
    function_data = []
    tainted_functions = set()
    sources = polytracker_json_obj['canonical_mapping'].keys()
    if len(sources) != 1:
        raise ValueError(f"Expected only a single taint source, but found {sources}")
    source = next(iter(sources))
    canonical_mapping: Dict[int, int] = dict(polytracker_json_obj['canonical_mapping'][source])
    forest = TaintForest(path=polytracker_forest_path, canonical_mapping=canonical_mapping)
    for function_name, data in polytracker_json_obj["tainted_functions"].items():
        if "input_bytes" not in data:
            if "cmp_bytes" in data:
                input_bytes = {source: data["cmp_bytes"]}
            else:
                input_bytes = {}
        else:
            input_bytes = {source: data["input_bytes"]}
        if "cmp_bytes" in data:
            cmp_bytes = {source: data["cmp_bytes"]}
        else:
            cmp_bytes = input_bytes
        if function_name in polytracker_json_obj["runtime_cfg"]:
            called_from = frozenset(polytracker_json_obj["runtime_cfg"][function_name])
        else:
            called_from = frozenset()
        function_data.append(
            TaintForestFunctionInfo(
                name=function_name,
                forest=forest,
                cmp_byte_labels=cmp_bytes,
                input_byte_labels=input_bytes,
                called_from=called_from
            )
        )
        tainted_functions.add(function_name)
    # Add any additional functions from the CFG that didn't operate on tainted bytes
    for function_name in polytracker_json_obj["runtime_cfg"].keys() - tainted_functions:
        function_data.append(
            FunctionInfo(name=function_name, cmp_bytes={}, called_from=polytracker_json_obj["runtime_cfg"][function_name])
        )
    return ProgramTrace(version=version, function_data=function_data)
