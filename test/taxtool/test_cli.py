import pytest

from taxtool import VERSION
from taxtool.cli import main


async def test_no_arguments_succeeds() -> None:
    assert await main([]) == 0


async def test_version_prints_and_exits(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as info:
        await main(["--version"])
    assert info.value.code == 0
    assert capsys.readouterr().out.strip() == f"taxtool {VERSION}"
