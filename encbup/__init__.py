NUM_VERSION = (0, 1)
VERSION = ".".join(str(nv) for nv in NUM_VERSION)
__version__ = VERSION

try:
    from .encbup import (
        File,
        Key,
        Reader,
        Writer,
        main,
    )
except ImportError:
    # Ignore if dependencies haven't been satisfied yet (when setting up).
    pass
