import builtins


def test_console_without_ai_offers_local_commands(monkeypatch, capsys):
    from clawforge import native
    import llm

    monkeypatch.setattr(llm, "available", lambda: False)
    monkeypatch.setattr(native, "status", lambda: print("local status shown"))
    commands = iter(["status", "hello", "exit"])
    monkeypatch.setattr(builtins, "input", lambda prompt: next(commands))
    native.console()
    output = capsys.readouterr().out
    assert "local mode" in output
    assert "local status shown" in output
    assert "AI chat is not configured" in output
