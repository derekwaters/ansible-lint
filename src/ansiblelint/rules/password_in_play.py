"""Implementation of password-in-play rule."""
from __future__ import annotations

import re
import sys
from typing import TYPE_CHECKING

from ansiblelint.rules import AnsibleLintRule
from ansiblelint.testing import RunFromText

# Copyright (c) 2018, Ansible Project


if TYPE_CHECKING:
    from typing import Any

    from ansiblelint.errors import MatchError
    from ansiblelint.file_utils import Lintable


class PasswordInPlayRule(AnsibleLintRule):
    """Password defined in a play must use a variable."""

    id = "password-in-play"
    description = (
        "Passwords defined in a play must use a variable."
    )
    severity = "HIGH"
    tags = ["security", "experimental"]
    version_added = "v4.0.0"

    VARIABLE_REGEXP = re.compile("^\\{\\{.+\\}\\}$")
    POTENTIAL_FIELDS = ["password", "proxy_password", "url_password"]

    def is_variable_password(self, value: str) -> bool:
        return self.VARIABLE_REGEXP.match(value)

    def matchtask(self, task: dict[str, Any], file: Any | None = None) -> bool | str:
        for potential_field in self.POTENTIAL_FIELDS:
            if potential_field in task["action"]:
                return not self.is_variable_password(task["action"][potential_field])
        return False


# testing code to be loaded only with pytest or when executed the rule file
if "pytest" in sys.modules:  # noqa: C901
    import pytest

    from ansiblelint.rules import RulesCollection  # pylint: disable=ungrouped-imports
    from ansiblelint.testing import RunFromText  # pylint: disable=ungrouped-imports

    @pytest.mark.parametrize(
        ("file", "expected"),
        (
            pytest.param(
                "examples/playbooks/rule-password-in-play-pass.yml",
                0,
                id="pass",
            ),
            pytest.param(
                "examples/playbooks/rule-password-in-play-fail.yml",
                1,
                id="fails",
            ),
        ),
    )
    def test_password_in_play(file: str, expected: int) -> None:
        """The ini_file module does not accept preserve mode."""
        collection = RulesCollection()
        collection.register(PasswordInPlayRule())
        runner = RunFromText(collection)
        results = runner.run(file)
        assert len(results) == expected
        for result in results:
            assert result.tag == "password-in-play"
