"""
External edits to svgwrite functionality
"""

from svgwrite import *
import svgwrite.utils as utils

# TODO: clear from localnamespace after registering
def attach(name, module):
    """attach a function to a loaded module"""
    def decorator(f):
        setattr(module, name, f)
        return f
    return decorator

# TODO: add relative positioning
@attach('centerpos', utils)
def centerpos(svg, pos):
    """
    Given an SVG element, and a position,
    return the absolute position of the element if it were
    centered at that spot.
    """
    h = svg['height']
    w = svg['width']
    x = pos[0] - 0.5*width
    y = pos[1] - 0.5*height
    return x, y
