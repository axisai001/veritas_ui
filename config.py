# config.py
from __future__ import annotations
import json, logging, os, time, uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional

try:
    import streamlit as st
except Exception:
    st = None

try:
    from dotenv import load_dotenv
except Exception:
    load_dotenv = None

@dataclass
class Settings:
    openai_api_key: str
    openai_model: str = "gpt-4o-mini"
    app_password: Optional[str] = None
    log_level: str = "INFO"
    rate_limit_per_min: int = 10
    auth_log_ttl_days: int = 365
    sentry_dsn: Optional[str] = None
    env: str = os.environ.get("ENV", "production")
    allowed_origins: Optional[str] = None

def _merge_secrets_and_env() -> Dict[str, Any]:
    if load_dotenv:
        load_dotenv()
    secrets: Dict[str, Any] = {}
    if st is not None:
        try:
            secrets = {k: v for k, v in st.secrets.items()}  # type: ignore
        except Exception:
            secrets = {}
    env_overlay = dict(os.environ)
    secrets.update(env_overlay)
    return secrets

def load_settings() -> Settings:
    cfg = _merge_secrets_and_env()
    def get(name: str, default: Optional[str] = None) -> Optional[str]:
        return cfg.get(name) or cfg.get(name.lower()) or default

    key = get("OPENAI_API_KEY")
    if not key:
        if st is not None:
            import streamlit as _st
            _st.error("Missing OPENAI_API_KEY. Add it in App → ••• → Settings → Secrets.")
            _st.stop()
        raise RuntimeError("Missing OPENAI_API_KEY")

    settings = Settings(
        openai_api_key=key,
        openai_model=(get("OPENAI_MODEL", "gpt-4o-mini") or "gpt-4o-mini"),
        app_password=get("APP_PASSWORD") or None,
        log_level=(get("LOG_LEVEL", "INFO") or "INFO").upper(),
        rate_limit_per_min=int(get("RATE_LIMIT_PER_MIN", "10") or "10"),
        auth_log_ttl_days=int(get("AUTH_LOG_TTL_DAYS", "365") or "365"),
        sentry_dsn=get("SENTRY_DSN") or None,
        env=(get("ENV", "production") or "production"),
        allowed_origins=get("ALLOWED_ORIGINS") or None,
    )
    _configure_root_logging(settings.log_level)
    _init_sentry_if_configured(settings)
    return settings

class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "level": record.levelname,
            "msg": record.getMessage(),
            "logger": record.name,
            "time": int(time.time()),
        }
        for k, v in getattr(record, "__dict__", {}).items():
            if k in ("msg","args","levelname","levelno","pathname","filename","module",
                     "exc_info","exc_text","stack_info","lineno","funcName","created",
                     "msecs","relativeCreated","thread","threadName","processName","process"):
                continue
            try:
                json.dumps({k: v})
                payload[k] = v
            except Exception:
                payload[k] = str(v)
        return json.dumps(payload, separators=(",", ":"))

def _configure_root_logging(level: str = "INFO") -> None:
    root = logging.getLogger()
    root.setLevel(level)
    for h in list(root.handlers):
        root.removeHandler(h)
    handler = logging.StreamHandler()
    handler.setFormatter(_JsonFormatter())
    root.addHandler(handler)

def get_tracking_id() -> str:
    if st is not None:
        if "tracking_id" not in st.session_state:
            st.session_state["tracking_id"] = uuid.uuid4().hex
        return st.session_state["tracking_id"]
    return uuid.uuid4().hex

def get_logger(name: str = "app", tracking_id: Optional[str] = None) -> logging.Logger:
    logger = logging.getLogger(name)
    if tracking_id:
        class _Inject(logging.Filter):
            def filter(self, record: logging.LogRecord) -> bool:
                setattr(record, "tracking_id", tracking_id)
                return True
        if not any(isinstance(f, _Inject) for f in logger.filters):
            logger.addFilter(_Inject())
    return logger

def check_rate_limit(label: str, limit_per_min: int) -> bool:
    if st is None:
        return False
    key = f"rl_{label}"
    window = 60.0
    t = time.time()
    bucket = [ts for ts in st.session_state.get(key, []) if (t - ts) < window]
    if len(bucket) >= max(1, int(limit_per_min)):
        st.session_state[key] = bucket
        return True
    bucket.append(t)
    st.session_state[key] = bucket
    return False

def _init_sentry_if_configured(settings: Settings) -> None:
    if not settings.sentry_dsn:
        return
    try:
        import sentry_sdk  # type: ignore
        sentry_sdk.init(dsn=settings.sentry_dsn, environment=settings.env, traces_sample_rate=0.0)
    except Exception:
        pass

def require_password_if_set(settings: Settings) -> None:
    if st is None or not settings.app_password:
        return
    if st.session_state.get("auth_ok"):
        return
    pw = st.text_input("Enter access password", type="password")
    if not pw:
        st.stop()
    if pw != settings.app_password:
        st.error("Incorrect password.")
        st.stop()
    st.session_state["auth_ok"] = True
