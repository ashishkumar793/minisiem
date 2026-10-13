"""Base class that every log parser inherits from."""
import abc
from typing import Optional

from ..models import Event


class BaseParser(abc.ABC):
    name = "base"

    @abc.abstractmethod
    def parse_line(self, line: str) -> Optional[Event]:
        """Return an Event, or None if the line is not in this parser's format."""
