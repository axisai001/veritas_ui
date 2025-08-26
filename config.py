# streamlit_app.py
import streamlit as st
from openai import OpenAI

from config import (
    load_settings,
    get_logger,
    get_tracking_id,
    check_rate_limit,
    require_password_if_set,
)

st.set_page_config(page_title="VERITAS – Pilot", layout="wide")

# Load settings & init logger
settings = load_settings()
tracking_id = get_tracking_id()
logger = get_logger("veritas", tracking_id)

# Optional pilot gate
require_password_if_set(settings)

st.title("VERITAS – Pilot")

txt = st.text_area("Paste text to analyze:", height=220)

if st.button("Analyze"):
    if check_rate_limit("analyze", settings.rate_limit_per_min):
        st.warning("Rate limit reached. Please wait a few seconds and try again.")
    elif not txt.strip():
        st.warning("Please paste some text first.")
    else:
        with st.spinner("Analyzing…"):
            try:
                client = OpenAI(api_key=settings.openai_api_key)
                resp = client.responses.create(
                    model=settings.openai_model,
                    input=f"Analyze for bias and summarize:\n\n{txt}",
                )
                st.write(resp.output_text)
                logger.info("analysis_ok", extra={"event": "analyze", "chars": len(txt)})
            except Exception as e:
                logger.error("analysis_error", extra={"event": "analyze", "error": str(e)})
                st.error(f"Error: {e}")
