"""Tests for src/observability — step logging + timeout."""

import time
from types import SimpleNamespace
from unittest.mock import Mock

from src.observability import make_step_logger


def _tc(name):
    """Create a tool-call-like object with a name attribute."""
    return SimpleNamespace(name=name)


class TestMakeStepLogger:

    def test_prints_step_info(self, capsys):
        """Callback prints step number, duration, tools."""
        callback = make_step_logger("Test")
        mock_step = Mock(
            step_number=1,
            timing=Mock(duration=2.5),
            tool_calls=[_tc("run_semgrep")],
            token_usage=Mock(input_tokens=500, output_tokens=200),
        )
        mock_agent = Mock(max_steps=3)
        callback(mock_step, agent=mock_agent)
        output = capsys.readouterr().out
        assert "[Test] Step 1/3" in output
        assert "2.5s" in output
        assert "run_semgrep" in output

    def test_timeout_sets_interrupt(self, capsys):
        """When elapsed > max_seconds, sets agent.interrupt_switch."""
        callback = make_step_logger("Test", max_seconds=0)
        mock_step = Mock(
            step_number=1,
            timing=Mock(duration=1.0),
            tool_calls=None,
            token_usage=None,
        )
        mock_agent = Mock(max_steps=3, interrupt_switch=False)
        time.sleep(0.01)
        callback(mock_step, agent=mock_agent)
        assert mock_agent.interrupt_switch is True
        assert "TIMEOUT" in capsys.readouterr().out

    def test_no_timeout_when_none(self):
        """When max_seconds=None, no timeout check."""
        callback = make_step_logger("Test", max_seconds=None)
        mock_step = Mock(
            step_number=1,
            timing=None,
            tool_calls=None,
            token_usage=None,
        )
        mock_agent = Mock(max_steps=3, interrupt_switch=False)
        callback(mock_step, agent=mock_agent)
        assert mock_agent.interrupt_switch is False

    def test_missing_attributes_no_crash(self, capsys):
        """Graceful when step attributes are missing."""
        callback = make_step_logger("Test")
        callback(object(), agent=None)
        output = capsys.readouterr().out
        assert "[Test]" in output

    def test_no_agent_kwarg_no_crash(self, capsys):
        """Works when agent kwarg is missing."""
        callback = make_step_logger("Test")
        mock_step = Mock(
            step_number=1,
            timing=None,
            tool_calls=None,
            token_usage=None,
        )
        callback(mock_step)
        output = capsys.readouterr().out
        assert "[Test] Step 1/?" in output

    def test_token_display_format(self, capsys):
        """Token count shown as 'Xk tok'."""
        callback = make_step_logger("Test")
        mock_step = Mock(
            step_number=1,
            timing=Mock(duration=1.0),
            tool_calls=None,
            token_usage=Mock(input_tokens=1500, output_tokens=500),
        )
        callback(mock_step, agent=Mock(max_steps=5))
        assert "2.0k tok" in capsys.readouterr().out

    def test_no_tools_shows_reasoning(self, capsys):
        """When no tool_calls, shows '(reasoning)'."""
        callback = make_step_logger("Test")
        mock_step = Mock(
            step_number=2,
            timing=Mock(duration=3.0),
            tool_calls=None,
            token_usage=None,
        )
        callback(mock_step, agent=Mock(max_steps=10))
        assert "(reasoning)" in capsys.readouterr().out

    def test_multiple_tool_calls(self, capsys):
        """Multiple tool calls shown comma-separated."""
        callback = make_step_logger("Test")
        mock_step = Mock(
            step_number=1,
            timing=Mock(duration=1.0),
            tool_calls=[_tc("fetch_pr_diff"), _tc("run_semgrep")],
            token_usage=None,
        )
        callback(mock_step, agent=Mock(max_steps=3))
        output = capsys.readouterr().out
        assert "fetch_pr_diff, run_semgrep" in output

    def test_zero_tokens_no_display(self, capsys):
        """When token count is 0, no 'tok' shown."""
        callback = make_step_logger("Test")
        mock_step = Mock(
            step_number=1,
            timing=Mock(duration=1.0),
            tool_calls=None,
            token_usage=Mock(input_tokens=0, output_tokens=0),
        )
        callback(mock_step, agent=Mock(max_steps=3))
        assert "tok" not in capsys.readouterr().out

    def test_timeout_message_includes_limit(self, capsys):
        """TIMEOUT message shows both elapsed and limit."""
        callback = make_step_logger("MyAgent", max_seconds=0)
        mock_step = Mock(
            step_number=1, timing=None,
            tool_calls=None, token_usage=None,
        )
        time.sleep(0.01)
        callback(mock_step, agent=Mock(max_steps=3))
        output = capsys.readouterr().out
        assert "TIMEOUT" in output
        assert "limit: 0s" in output
        assert "[MyAgent]" in output

    def test_agent_name_in_output(self, capsys):
        """Agent name label appears in output."""
        callback = make_step_logger("Triage")
        mock_step = Mock(
            step_number=1, timing=None,
            tool_calls=None, token_usage=None,
        )
        callback(mock_step, agent=Mock(max_steps=3))
        assert "[Triage]" in capsys.readouterr().out

    def test_timing_none_shows_zero(self, capsys):
        """When timing is None, duration shows 0.0s."""
        callback = make_step_logger("Test")
        mock_step = Mock(
            step_number=1,
            timing=None,
            tool_calls=None,
            token_usage=None,
        )
        callback(mock_step, agent=Mock(max_steps=3))
        assert "0.0s" in capsys.readouterr().out
