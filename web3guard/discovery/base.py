    The format is normalized across engines; each engine subclass
    is responsible for translating its own output into this shape.
    """
    engine: str                 # "slither", "aderyn", "mythril", "echidna", ...
    target: str                 # the target URL or path
    file: str
    line: int = 0
    end_line: int = 0
    function: str = ""
    category: str = ""          # "reentrancy" | "access-control" | ...
    severity: str = "MEDIUM"    # CRITICAL | HIGH | MEDIUM | LOW | INFO
    title: str = ""
    description: str = ""
    swc_id: str = ""
    confidence: float = 0.5     # the engine's own confidence, 0-1
    raw: dict[str, Any] = field(default_factory=dict)


def safe_run_subprocess(
    cmd: list[str],
    *,
    cwd: Path,
    timeout: int,
    env_extra: dict[str, str] | None = None,
    policy: SandboxPolicy | None = None,
) -> tuple[int, str, str]:
    """Run a discovery subprocess through the same hardened runner as PoCs."""
    from web3guard.security.sandbox_guard import run_sandboxed
    try:
        return run_sandboxed(
            cmd, cwd=cwd, timeout=timeout, extra_env=env_extra, policy=policy,
        )
    except FileNotFoundError as e:
        return 127, "", f"command not found: {e}"
    except Exception as e:  # noqa: BLE001
        LOGGER.warning("discovery sandbox wrapper failed: %s", e)
        return 1, "", str(e)


class DiscoveryEngineBase(abc.ABC):
    """Protocol every discovery engine implements.

    Subclasses set ``name`` and ``binary``, and implement
    :meth:`run`. The scanner core calls ``run`` once per target
    with a configurable timeout.
    """

    name: str = "unknown"
    binary: str = ""            # executable name; "" means "no binary" (built-in)
    supported_languages: tuple[TargetLanguage, ...] = (TargetLanguage.SOLIDITY,)
    default_timeout: int = 300
    enabled_by_default: bool = True

    @abc.abstractmethod
    def run(self, target_path: Path, *, timeout: int = 0,
            extra_args: list[str] | None = None) -> list[DiscoveryResult]:
        """Run the engine against ``target_path`` and return a list of results."""

    def is_installed(self) -> bool:
        if not self.binary:
            return True
        import shutil
        return shutil.which(self.binary) is not None