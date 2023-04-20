"""Implementation of password-in-command rule."""
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


class PasswordInCommandRule(AnsibleLintRule):
    """Password used in a command or shell play may leak unless no_log = true."""

    id = "password-in-command"
    description = (
        "Passwords used in command or shell should use "
        "no_log = true to prevent credential leakage."
    )
    severity = "HIGH"
    tags = ["opt-in", "security", "experimental"]
    version_added = "v4.0.0"

    PASSWORD_REGEXP = re.compile("\\b(password|pwd|pass)\\b")
    TASK_FILTER = ["shell", "command", "ansible.builtin.shell", "ansible.builtin.command"]

    def has_password(self, cmdline: str) -> bool:
        return not self.PASSWORD_REGEXP.search(cmdline) is None

    def matchtask(self, task: dict[str, Any], file: Any | None = None) -> bool | str:
        if task["action"]["__ansible_module__"] in self.TASK_FILTER:
            cmdline = None
            if "cmd" in task["action"]:
                cmdline = task["action"]["cmd"]
            elif "__ansible_arguments__" in task["action"]:
                cmdline = task["action"]["__ansible_arguments__"][0]
            elif "_raw_params" in task["action"]:
                cmdline = task["action"]["_raw_params"]

            if not cmdline is None and self.has_password(cmdline):
                if not "no_log" in task["action"] or not task["action"]["no_log"]:
                    return True
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
                "examples/playbooks/rule-password-in-command-pass.yml",
                0,
                id="pass",
            ),
            pytest.param(
                "examples/playbooks/rule-password-in-command-fail.yml",
                6,
                id="fails",
            ),
        ),
    )
    def test_password_in_command(file: str, expected: int) -> None:
        """The ini_file module does not accept preserve mode."""
        collection = RulesCollection()
        collection.register(PasswordInCommandRule())
        runner = RunFromText(collection)
        results = runner.run(file)
        assert len(results) == expected
        for result in results:
            assert result.tag == "password-in-command"
