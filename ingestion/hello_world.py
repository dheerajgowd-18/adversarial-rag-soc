"""
ingestion/hello_world.py — Phase 0 verification script.

Purpose:
    Prove that the entire environment is working end-to-end:
    1. Config loads from .env
    2. LLM API key is valid
    3. A successful LLM call completes
    4. The response is logged to logs/hello_world.log

Run:
    python ingestion/hello_world.py

Expected output:
    [INFO] Config loaded — provider: groq, model: llama-3.1-8b-instant
    [INFO] Sending test prompt to LLM...
    [INFO] ✅ LLM responded successfully.
    [INFO] Response: { "status": "ok", "message": "SOC triage system operational" }
    [INFO] Full log written to: logs/hello_world.log
    [INFO] Phase 0 COMPLETE ✅
"""

import sys
import json
import logging
from datetime import datetime
from pathlib import Path

# ── Allow running from any directory inside the project ─────────────────────
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import cfg


# ── Set up logging — writes to BOTH console AND file ─────────────────────────
def setup_logging() -> logging.Logger:
    cfg.LOGS_DIR.mkdir(parents=True, exist_ok=True)
    log_file = cfg.LOGS_DIR / "hello_world.log"

    logger = logging.getLogger("hello_world")
    logger.setLevel(logging.DEBUG)

    # File handler — full detail
    fh = logging.FileHandler(log_file, mode="w", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S"
    ))

    # Console handler — info and above
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))

    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger


def build_llm_client():
    """
    Returns an LLM client based on the provider set in .env.
    Supports: groq, anthropic, openai
    """
    if cfg.LLM_PROVIDER == "groq":
        from langchain_groq import ChatGroq
        return ChatGroq(
            model=cfg.LLM_MODEL,
            api_key=cfg.GROQ_API_KEY,
            temperature=0,
            max_tokens=256,
        )
    elif cfg.LLM_PROVIDER == "anthropic":
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(
            model=cfg.LLM_MODEL,
            api_key=cfg.ANTHROPIC_API_KEY,
            temperature=0,
            max_tokens=256,
        )
    elif cfg.LLM_PROVIDER == "openai":
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            model=cfg.LLM_MODEL,
            api_key=cfg.OPENAI_API_KEY,
            temperature=0,
            max_tokens=256,
        )
    else:
        raise ValueError(f"Unknown LLM_PROVIDER: {cfg.LLM_PROVIDER!r}. Must be groq, anthropic, or openai.")


def run_hello_world(logger: logging.Logger) -> dict:
    """
    Makes one LLM call with a structured prompt that asks for JSON output.
    This tests the entire stack: config → API key → LLM → structured response.

    Returns:
        A dict with keys: success, provider, model, response, latency_ms, timestamp
    """
    # ── Step 1: Validate config ────────────────────────────────────────────
    logger.info(f"Config loaded — provider: {cfg.LLM_PROVIDER}, model: {cfg.LLM_MODEL}")
    cfg.validate()
    logger.debug(f"Full config: {cfg}")

    # ── Step 2: Build the LLM client ─────────────────────────────────────
    logger.info("Building LLM client...")
    llm = build_llm_client()

    # ── Step 3: Define the test prompt ───────────────────────────────────
    # This prompt mirrors the style of the actual triage prompt we'll use later.
    # It returns JSON — testing that the model can follow structured output instructions.
    test_prompt = (
        "You are an AI assistant for a cybersecurity SOC triage system. "
        "Respond ONLY with a valid JSON object — no markdown, no prose, just JSON.\n\n"
        "Respond with exactly this structure:\n"
        '{"status": "ok", "system": "adversarial-rag-soc", '
        '"message": "Phase 0 verification successful", '
        '"model_name": "<your model name here>"}'
    )

    # ── Step 4: Make the LLM call with latency timing ────────────────────
    logger.info("Sending test prompt to LLM...")
    t_start = datetime.now()

    from langchain_core.messages import HumanMessage
    response_msg = llm.invoke([HumanMessage(content=test_prompt)])
    response_text = response_msg.content.strip()

    t_end = datetime.now()
    latency_ms = int((t_end - t_start).total_seconds() * 1000)

    logger.debug(f"Raw LLM response: {response_text!r}")
    logger.info(f"✅ LLM responded successfully. Latency: {latency_ms}ms")

    # ── Step 5: Parse JSON response ───────────────────────────────────────
    try:
        parsed = json.loads(response_text)
        logger.info(f"Response: {json.dumps(parsed, indent=2)}")
    except json.JSONDecodeError:
        # Not fatal for hello world — model returned text instead of JSON
        logger.warning(
            f"Response was not valid JSON (model didn't follow instructions exactly). "
            f"Raw text: {response_text[:200]}"
        )
        parsed = {"raw_text": response_text}

    # ── Step 6: Assemble the full run record ─────────────────────────────
    run_record = {
        "phase": "Phase 0 — Hello World",
        "timestamp": t_start.isoformat(),
        "provider": cfg.LLM_PROVIDER,
        "model": cfg.LLM_MODEL,
        "prompt": test_prompt,
        "response_raw": response_text,
        "response_parsed": parsed,
        "latency_ms": latency_ms,
        "success": True,
    }

    return run_record


def write_log_record(record: dict, logger: logging.Logger) -> None:
    """Write the full run record to a JSON log file for reproducibility."""
    log_file = cfg.LOGS_DIR / "hello_world_record.json"
    with open(log_file, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2, default=str)
    logger.info(f"Full run record written to: {log_file}")


def main() -> None:
    logger = setup_logging()

    logger.info("=" * 60)
    logger.info("Phase 0 — Hello World LLM Verification")
    logger.info("=" * 60)

    try:
        record = run_hello_world(logger)
        write_log_record(record, logger)

        logger.info("")
        logger.info("=" * 60)
        logger.info("Phase 0 COMPLETE ✅")
        logger.info(f"  Provider : {record['provider']}")
        logger.info(f"  Model    : {record['model']}")
        logger.info(f"  Latency  : {record['latency_ms']}ms")
        logger.info(f"  Log file : {cfg.LOGS_DIR / 'hello_world.log'}")
        logger.info("=" * 60)
        sys.exit(0)

    except EnvironmentError as e:
        logger.error(str(e))
        logger.error("Phase 0 FAILED ❌ — Fix the error above and rerun.")
        sys.exit(1)

    except Exception as e:
        logger.error(f"Unexpected error: {type(e).__name__}: {e}")
        logger.error("Phase 0 FAILED ❌")
        raise


if __name__ == "__main__":
    main()
