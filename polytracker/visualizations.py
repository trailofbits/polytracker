import math
from typing import Callable, List, Optional

from PIL import Image, ImageEnhance
from tqdm import tqdm

from .tracing import Input, ProgramTrace


def file_diff(
    num_bytes: int,
    in_first: Callable[[int], bool],
    in_second: Callable[[int], bool],
    aspect_ratio: float = 1.61803398875,
) -> Image:
    height = max(int(math.ceil(math.sqrt(aspect_ratio) * math.sqrt(num_bytes))), 1)
    width = max(int(math.ceil(num_bytes / height)), 1)
    while width * height < num_bytes:
        height += 1
    image = Image.new(size=(width, height), mode="RGB", color=(255, 255, 255))
    for i in range(num_bytes):
        first = in_first(i)
        second = in_second(i)
        if not (first and second):
            row = i // width
            col = i % width
            if first:
                image.putpixel((col, row), (0, 0, 255))
            elif second:
                image.putpixel((col, row), (255, 0, 0))
            else:
                image.putpixel((col, row), (0, 0, 0))
    return image


def temporal_animation(
    output_path: str, trace: ProgramTrace, for_input: Optional[Input] = None, aspect_ratio: float = 1.61803398875
):
    if for_input is None:
        for_input = next(iter(trace.inputs))
    num_bytes = for_input.size
    height = max(int(math.ceil(math.sqrt(aspect_ratio) * math.sqrt(num_bytes))), 1)
    width = max(int(math.ceil(num_bytes / height)), 1)
    while width * height < num_bytes:
        height += 1
    images: List[Image] = []
    for access in tqdm(
        trace.access_sequence(),
        desc="building temporal animation",
        leave=False,
        unit=" frames",
        total=trace.num_accesses,
    ):
        if not images:
            image = Image.new(size=(width, height), mode="L", color=255)
        else:
            enhancer = ImageEnhance.Brightness(images[-1])
            image = enhancer.enhance(1.1)
        for offset in access.taints():
            row = offset.offset // width
            col = offset.offset % width
            image.putpixel((col, row), 0)
        images.append(image)
    images[0].save(
        output_path, save_all=True, append_images=images[1:], fps=100.0, loop=True
    )
