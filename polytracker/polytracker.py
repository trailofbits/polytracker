import logging
from typing import Dict, Iterable, List, Set, Tuple

from .cfg import CFG


log = logging.getLogger('PolyTracker')


class FunctionInfo:
    def __init__(self, name: str, cmp_bytes: Dict[str, List[int]], input_bytes: Dict[str, List[int]] = None, called_from: Iterable[str] = ()):
        self.name = name
        self.called_from = frozenset(called_from)
        self.cmp_bytes = cmp_bytes
        if input_bytes is None:
            self.input_bytes = cmp_bytes
        else:
            self.input_bytes = input_bytes

    @property
    def taint_sources(self) -> Set[str]:
        return self.input_bytes.keys()

    def __getitem__(self, input_source_name):
        return self.input_bytes[input_source_name]

    def __iter__(self):
        return self.taint_sources

    def items(self):
        return self.input_bytes.items()

    def __hash__(self):
        return hash(self.name)

    def __str__(self):
        return self.name

    def __repr__(self):
        return f"{self.__class__.__name__}(name={self.name!r}, cmp_bytes={self.cmp_bytes!r}, input_bytes={self.input_bytes!r}, called_from={self.called_from!r})"


class ProgramTrace:
    def __init__(self, polytracker_version: tuple, function_data: Iterable[FunctionInfo]):
        self.polytracker_version = polytracker_version
        self.functions: Dict[str, FunctionInfo] = {f.name: f for f in function_data}
        self._cfg = None

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

    def __repr__(self):
        return f"{self.__class__.__name__}(polytracker_version={self.polytracker_version!r}, function_data={list(self.functions.values())!r})"


POLYTRACKER_JSON_FORMATS = []


def normalize_version(*version) -> Tuple[str]:
    version = tuple(str(v) for v in version)
    version = tuple(version) + ('0',) * (3 - len(version))
    version = tuple(version) + ('',) * (4 - len(version))
    return version


def polytracker_version(*version):
    def wrapper(func):
        POLYTRACKER_JSON_FORMATS.append((normalize_version(*version), func))
        POLYTRACKER_JSON_FORMATS.sort(reverse=True)
        return func
    return wrapper


def parse(polytracker_json_obj: dict) -> ProgramTrace:
    if 'version' in polytracker_json_obj:
        version = normalize_version(*polytracker_json_obj['version'].split('.'))
        if len(version) > 4:
            log.warning(f"Unexpectedly long PolyTracker version: {polytracker_json_obj['version']!r}")
        for i, (known_version, parser) in enumerate(POLYTRACKER_JSON_FORMATS):
            # POLYTRACKER_JSON_FORMATS is auto-sorted in decreasing order
            if version >= known_version:
                if i == 0 and version > known_version:
                    log.warning(f"PolyTracker version {polytracker_json_obj['version']!r} "
                                "is newer than the latest supported by the polytracker Python module "
                                f"({'.'.join(known_version)})")
                return parser(polytracker_json_obj)
        raise ValueError(f"Unsupported PolyTracker version {polytracker_json_obj['version']!r}")
    for function_name, function_data in polytracker_json_obj.items():
        if isinstance(function_data, dict) and 'called_from' in function_data:
            # this is the second version of the output format
            return parse_format_v2(polytracker_json_obj)
        else:
            return parse_format_v1(polytracker_json_obj)


@polytracker_version(0, 0, 1, '')
def parse_format_v1(polytracker_json_obj: dict) -> ProgramTrace:
    return ProgramTrace(
        polytracker_version=(0, 0, 1),
        function_data=[FunctionInfo(
            function_name,
            {None: taint_bytes}
        ) for function_name, taint_bytes in polytracker_json_obj.items()
        ]
    )


@polytracker_version(0, 0, 1, 'alpha2.1')
def parse_format_v2(polytracker_json_obj: dict) -> ProgramTrace:
    function_data = []
    for function_name, data in polytracker_json_obj.items():
        if 'input_bytes' not in data:
            if 'cmp_bytes' in data:
                input_bytes = data['cmp_bytes']
            else:
                input_bytes = {}
        else:
            input_bytes = data['input_bytes']
        if 'cmp_bytes' in data:
            cmp_bytes = data['cmp_bytes']
        else:
            cmp_bytes = input_bytes
        if 'called_from' in data:
            called_from = data['called_from']
        else:
            called_from = ()
        function_data.append(FunctionInfo(
            name=function_name,
            cmp_bytes=cmp_bytes,
            input_bytes=input_bytes,
            called_from=called_from
        ))
    return ProgramTrace(
        polytracker_version=(0, 0, 1, 'alpha2.1'),
        function_data=function_data
    )


@polytracker_version(2, 0, 1)
@polytracker_version(2, 0, 0)
@polytracker_version(1, 0, 1)
def parse_format_v3(polytracker_json_obj: dict) -> ProgramTrace:
    version = polytracker_json_obj['version'].split('.')
    function_data = []
    tainted_functions = set()
    for function_name, data in polytracker_json_obj['tainted_functions'].items():
        if 'input_bytes' not in data:
            if 'cmp_bytes' in data:
                input_bytes = data['cmp_bytes']
            else:
                input_bytes = {}
        else:
            input_bytes = data['input_bytes']
        if 'cmp_bytes' in data:
            cmp_bytes = data['cmp_bytes']
        else:
            cmp_bytes = input_bytes
        if function_name in polytracker_json_obj['runtime_cfg']:
            called_from = frozenset(polytracker_json_obj['runtime_cfg'][function_name])
        else:
            called_from = frozenset()
        function_data.append(FunctionInfo(
            name=function_name,
            cmp_bytes=cmp_bytes,
            input_bytes=input_bytes,
            called_from=called_from
        ))
        tainted_functions.add(function_name)
    # Add any additional functions from the CFG that didn't operate on tainted bytes
    for function_name in polytracker_json_obj['runtime_cfg'].keys() - tainted_functions:
        function_data.append(FunctionInfo(
            name=function_name,
            cmp_bytes={},
            called_from=polytracker_json_obj['runtime_cfg'][function_name]
        ))
    return ProgramTrace(
        polytracker_version=version,
        function_data=function_data
    )
