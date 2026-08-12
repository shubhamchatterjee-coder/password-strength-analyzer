import streamlit as st
from analyzer import score_password, suggest_password
from reuse_tracker import has_been_used_before, record_password

st.set_page_config(page_title="Password Strength Analyzer", page_icon="🔐")

st.title("🔐 Password Strength Analyzer")
st.write(
    "Enter a password below to see how strong it is, why, and how to "
    "improve it. Nothing you type is stored unless you click **Save**."
)

password = st.text_input("Enter a password", type="password")

if password:
    result = score_password(password)

    # --- Strength label with color ---
    color_map = {
        "Weak": "🔴", "Medium": "🟠", "Strong": "🟢", "Very Strong": "🟢"
    }
    st.subheader(f"{color_map.get(result['label'], '')} Strength: {result['label']}")

    # --- Progress bar (score out of 8) ---
    st.progress(min(result["score"] / 8, 1.0))

    col1, col2 = st.columns(2)
    with col1:
        st.metric("Entropy (bits)", result["entropy"])
        st.caption("Higher = more guesses needed to brute-force")
    with col2:
        st.metric("Score", f"{result['score']} / 8")

    st.write(f"**Length:** {result['length_msg']}")
    st.write(f"**Character types used:** {', '.join(result['complexity_details']) or 'None'}")
    st.write(f"**Pattern check:** {result['common_msg']}")

    st.subheader("💡 Suggestions")
    for tip in result["feedback"]:
        st.write(f"- {tip}")

    # --- Optional reuse check ---
    st.divider()
    st.subheader("🔁 Reuse Check (optional)")
    st.caption(
        "This checks your password against a local database of hashed "
        "passwords you've saved before. Only a salted hash is ever "
        "stored — never the password itself."
    )
    if has_been_used_before(password):
        st.warning("⚠️ You've used this password before (or one identical to it).")
    else:
        st.info("This password hasn't been saved before.")

    if st.button("Save this password's hash to history"):
        record_password(password)
        st.success("Saved (as a salted hash — not as plaintext).")

    # --- Suggested alternative ---
    if result["label"] in ("Weak", "Medium"):
        st.divider()
        st.subheader("🎲 Try a stronger alternative")
        if st.button("Generate a strong password"):
            st.code(suggest_password())
else:
    st.info("Start typing a password above to see the analysis.")
