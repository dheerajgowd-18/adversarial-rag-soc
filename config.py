"""
config.py — Centralized configuration loader for the entire project.

Every script in this project imports from here. Changing a path or model
in .env is reflected everywhere automatically. Never hardcode paths.

Usage:
    from config import cfg
    print(cfg.LLM_MODEL)
    print(cfg.CLEAN_ALERTS_PATH)
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# ── Load .env from the project root (works regardless of which subdirectory
#    the script is run from, as long as the project root contains .env) ──────
PROJECT_ROOT = Path(__file__).parent.resolve()
load_dotenv(PROJECT_ROOT / ".env")


class Config:
    """Single source of truth for all project configuration."""

    # ── Project root ────────────────────────────────────────────────────────
    ROOT: Path = PROJECT_ROOT

    # ── LLM ─────────────────────────────────────────────────────────────────
    LLM_MODEL: str = os.getenv("LLM_MODEL", "llama-3.1-8b-instant")
    LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "groq")

    DEFENSE_LLM_MODEL: str = os.getenv("DEFENSE_LLM_MODEL", "llama-3.1-8b-instant")
    DEFENSE_LLM_PROVIDER: str = os.getenv("DEFENSE_LLM_PROVIDER", "groq")

    # ── API Keys ─────────────────────────────────────────────────────────────
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    GROQ_API_KEY_2: str = os.getenv("GROQ_API_KEY_2", "")
    GROQ_API_KEY_3: str = os.getenv("GROQ_API_KEY_3", "")
    GROQ_API_KEY_4: str = os.getenv("GROQ_API_KEY_4", "")
    ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    OPENROUTER_API_KEY: str = os.getenv("OPENROUTER_API_KEY", "")

    # ── Data paths ───────────────────────────────────────────────────────────
    DATA_DIR: Path = ROOT / "data"
    RAW_DIR: Path = DATA_DIR / "raw"
    ALERTS_DIR: Path = DATA_DIR / "alerts"
    ATTACKED_DIR: Path = ALERTS_DIR / "attacked"
    KB_DIR: Path = DATA_DIR / "knowledge_base"
    SYNTHETIC_DIR: Path = KB_DIR / "synthetic_incidents"

    CLEAN_ALERTS_PATH: Path = ALERTS_DIR / os.getenv("CLEAN_ALERTS_PATH", "data/alerts/clean_alerts.json").split("/")[-1]
    SUSPICIOUS_QUEUE_PATH: Path = ALERTS_DIR / os.getenv("SUSPICIOUS_QUEUE_PATH", "data/alerts/suspicious_queue.json").split("/")[-1]
    EVAL_FIXED_SET_PATH: Path = ALERTS_DIR / os.getenv("EVAL_FIXED_SET_PATH", "data/alerts/eval_fixed_set.json").split("/")[-1]

    # ── ChromaDB paths ───────────────────────────────────────────────────────
    CHROMA_DIR: Path = ROOT / "chroma_db"
    CHROMA_COLLECTION: str = os.getenv("CHROMA_COLLECTION", "soc_threat_intel")
    KNOWLEDGE_BASE_DIR: Path = DATA_DIR / "knowledge_base"

    # Legacy paths (kept for backwards compatibility)
    CHROMA_CLEAN_PATH: Path = ROOT / os.getenv("CHROMA_CLEAN_PATH", "data/chroma_clean")
    CHROMA_POISONED_PATH: Path = ROOT / os.getenv("CHROMA_POISONED_PATH", "data/chroma_poisoned")

    # ── Eval paths ───────────────────────────────────────────────────────────
    EVAL_DIR: Path = ROOT / "eval"
    LOGS_DIR: Path = ROOT / "logs"

    # ── Pipeline config ──────────────────────────────────────────────────────
    MAX_ALERTS: int = int(os.getenv("MAX_ALERTS", "1000"))
    RETRIEVAL_TOP_K: int = int(os.getenv("RETRIEVAL_TOP_K", "3"))
    DEFENSE_ACTIVE: bool = os.getenv("DEFENSE_ACTIVE", "false").lower() == "true"

    # ── Embedding model ──────────────────────────────────────────────────────
    EMBEDDING_MODEL: str = "all-MiniLM-L6-v2"

    def validate(self) -> None:
        """
        Check that the minimum required config is present.
        Call this at the top of any script that needs the LLM.
        Raises EnvironmentError with a clear message if anything is missing.
        """
        errors = []

        if self.LLM_PROVIDER == "groq" and not self.GROQ_API_KEY:
            errors.append(
                "GROQ_API_KEY is not set. Add it to your .env file.\n"
                "  Get a free key at: https://console.groq.com/"
            )
        if self.LLM_PROVIDER == "anthropic" and not self.ANTHROPIC_API_KEY:
            errors.append(
                "ANTHROPIC_API_KEY is not set. Add it to your .env file.\n"
                "  Get a key at: https://console.anthropic.com/"
            )
        if self.LLM_PROVIDER == "openai" and not self.OPENAI_API_KEY:
            errors.append(
                "OPENAI_API_KEY is not set. Add it to your .env file.\n"
                "  Get a key at: https://platform.openai.com/"
            )
        if self.LLM_PROVIDER == "openrouter" and not self.OPENROUTER_API_KEY:
            errors.append(
                "OPENROUTER_API_KEY is not set. Add it to your .env file.\n"
                "  Get a key at: https://openrouter.ai/keys"
            )

        if errors:
            raise EnvironmentError(
                "\n\n[CONFIG ERROR] Missing required environment variables:\n"
                + "\n".join(f"  - {e}" for e in errors)
                + "\n\nCopy .env.example to .env and fill in your keys."
            )

    def __repr__(self) -> str:
        return (
            f"Config(\n"
            f"  LLM_PROVIDER={self.LLM_PROVIDER!r},\n"
            f"  LLM_MODEL={self.LLM_MODEL!r},\n"
            f"  MAX_ALERTS={self.MAX_ALERTS},\n"
            f"  RETRIEVAL_TOP_K={self.RETRIEVAL_TOP_K},\n"
            f"  DEFENSE_ACTIVE={self.DEFENSE_ACTIVE},\n"
            f"  CHROMA_CLEAN_PATH={self.CHROMA_CLEAN_PATH},\n"
            f")"
        )


# ── Singleton instance imported everywhere ───────────────────────────────────
cfg = Config()
