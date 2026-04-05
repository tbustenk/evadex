import sys
import io

# Ensure stdout/stderr use UTF-8 on Windows so that Rich tables with Unicode
# box-drawing characters and arrows are rendered without codec errors.
if sys.stdout and hasattr(sys.stdout, "buffer") and sys.stdout.encoding != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if sys.stderr and hasattr(sys.stderr, "buffer") and sys.stderr.encoding != "utf-8":
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from evadex.cli.app import main
if __name__ == "__main__":
    main()
