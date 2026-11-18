import io

from terracotta_general.sshshell import main, run_line


def collect():
    seen = []
    return seen, lambda argv: seen.append(argv)


def test_original_command_is_split_without_a_shell():
    seen, d = collect()
    assert main(d, env={"SSH_ORIGINAL_COMMAND": 'grant read "octo/my repo" 30m'}) == 0
    assert seen == [["grant", "read", "octo/my repo", "30m"]]


def test_only_operator_commands_are_dispatched():
    seen, d = collect()
    for bad in ("serve", "ssh-shell", "bash -c id", "; rm -rf /", "$(id)"):
        assert run_line(bad, d) == 2
    assert seen == []


def test_unbalanced_quote_is_a_usage_error_not_a_crash():
    seen, d = collect()
    assert run_line('grant read "oops', d) == 2 and seen == []


def test_interactive_prompt_loop():
    seen, d = collect()
    stdin = io.StringIO("status\nhelp\n\ngrant read o/r\nexit\nstatus\n")
    assert main(d, env={}, stdin=stdin) == 0
    assert seen == [["status"], ["grant", "read", "o/r"]]  # nothing after exit


def test_exit_code_of_last_failing_command_is_kept_in_prompt():
    def bad(_argv):
        import typer

        raise typer.Exit(1)

    assert main(bad, env={}, stdin=io.StringIO("status\n")) == 1
