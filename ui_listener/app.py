"""
NetSkill Agent — Sistem Özeti (Dashboard Ana Sayfası)

Çalıştırmak için:
    cd ui_listener
    streamlit run app.py
"""

import sys
from pathlib import Path

import streamlit as st
import streamlit.components.v1 as components

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from sidebar_nav import render_sidebar_nav

# ---------------------------------------------------------------------------
# Sayfa yapılandırması
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="NetSkill Agent — Sistem Özeti",
    page_icon="🌐",
    layout="wide",
    initial_sidebar_state="expanded",
)

render_sidebar_nav()

# ---------------------------------------------------------------------------
# Sidebar — Sistem Durumu paneli
# ---------------------------------------------------------------------------
with st.sidebar:
    # Toplam arşiv sayısını güvenle çek (sidebar için de gerekli)
    try:
        from chat_history import list_all_conversations as _list_convs
        _sb_archive = len(_list_convs())
    except Exception:
        _sb_archive = "—"

    st.markdown("### 🖥️ Sistem Durumu")

    sb_c1, sb_c2 = st.columns(2)
    sb_c1.metric("Aktif Yetenek", 5)
    sb_c2.metric("Toplam Arşiv", _sb_archive)

    st.success("🟢 Sistem Çevrimiçi")

    st.divider()

    # Kısa yetenek listesi
    st.markdown("#### ⚡ Yetenekler")
    for _skill in [
        "📦 eBPF Snapshot",
        "🔍 IP Analizi",
        "🔌 Port Envanteri",
        "🩺 TCP Probe",
        "🌐 DNS Sağlığı",
    ]:
        st.markdown(
            f"<p style='margin:2px 0; font-size:0.82rem; color:#94a3b8;'>{_skill}</p>",
            unsafe_allow_html=True,
        )

    st.divider()

    st.caption("eBPF · Go · Node.js · LangChain · Llama 3.1")

# ---------------------------------------------------------------------------
# Genel CSS
# ---------------------------------------------------------------------------
st.markdown(
    """
    <style>
    /* Sayfa arka planı */
    [data-testid="stAppViewContainer"] { background: #0e1117; }
    [data-testid="stHeader"]           { background: transparent; }

    /* ── Sidebar ──────────────────────────────────────────────────────────── */
    [data-testid="stSidebar"] { border-right: 1px solid #2d3a4a; }

    /* Sidebar metric kartları */
    section[data-testid="stSidebar"] div[data-testid="stMetric"] {
        background: #1e293b !important;
        border: 1px solid #2d3a4a !important;
        border-radius: 8px !important;
        padding: 10px 14px !important;
    }

    /* Sidebar butonları (page_link) */
    section[data-testid="stSidebar"] button {
        text-align:      left !important;
        justify-content: flex-start !important;
        padding:         5px 10px !important;
        border-radius:   6px !important;
        font-size:       0.82rem !important;
        font-weight:     400 !important;
        background:      transparent !important;
        color:           #94a3b8 !important;
        border:          none !important;
        box-shadow:      none !important;
        transition:      background 0.15s ease, color 0.15s ease !important;
    }
    section[data-testid="stSidebar"] button:hover {
        background: rgba(59, 130, 246, 0.12) !important;
        color:      #e2e8f0 !important;
    }

    /* Skill kart hover efekti */
    .skill-card {
        background: #1e293b;
        border: 1px solid #2d3a4a;
        border-radius: 10px;
        padding: 20px 16px;
        min-height: 170px;
        transition: border-color 0.2s, box-shadow 0.2s;
        display: flex;
        flex-direction: column;
        gap: 6px;
    }
    .skill-card:hover {
        border-color: #3b82f6;
        box-shadow: 0 0 0 1px #3b82f6;
    }
    .skill-icon   { font-size: 1.8rem; line-height: 1; }
    .skill-name   { font-size: 0.9rem; font-weight: 700; color: #f1f5f9; margin: 4px 0 2px 0; }
    .skill-desc   { font-size: 0.78rem; color: #94a3b8; line-height: 1.45; flex: 1; }
    .skill-tags   { font-size: 0.7rem; color: #64748b; margin-top: 6px; }

    /* CTA page_link butonları */
    a[data-testid="stPageLink"] {
        display: block;
        background: #1e293b !important;
        border: 1px solid #3b82f6 !important;
        border-radius: 10px !important;
        padding: 18px 24px !important;
        text-decoration: none;
        font-weight: 600;
        transition: background 0.18s;
    }
    a[data-testid="stPageLink"]:hover {
        background: #273549 !important;
    }

    /* Metrik kutu arka planı */
    div[data-testid="stMetric"] {
        background: #1e293b;
        border: 1px solid #2d3a4a;
        border-radius: 10px;
        padding: 14px 18px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ===========================================================================
# BLOK 1 — HERO + SİSTEM TELEMETRİSİ
# ===========================================================================
st.markdown("## 🌐 NetSkill Agent")
st.markdown(
    "<p style='color:#94a3b8; font-size:1.05rem; margin-top:-8px;'>"
    "Yetenek tabanlı otonom ağ tanılama ve izleme sistemi."
    "</p>",
    unsafe_allow_html=True,
)

st.markdown("&nbsp;", unsafe_allow_html=True)

# Toplam arşiv sayısı (sidebar bloğunda zaten çekildi, buraya da aktar)
_archive_count = _sb_archive

c1, c2, c3, c4, c5 = st.columns(5)

with c1:
    st.markdown("**Ajan Durumu**")
    st.success("● Çevrimiçi")

with c2:
    st.markdown("**eBPF Durumu**")
    st.success("● Aktif")

with c3:
    st.metric("Aktif Yetenek", 5)

with c4:
    st.metric("Toplam Arşiv", _archive_count)

with c5:
    st.metric("Hafıza Tamponu", "1.000 olay")

st.divider()

# ===========================================================================
# BLOK 2 — MİMARİ AKIŞ (MERMAID.JS)
# ===========================================================================
st.markdown("### 🔄 Sistem Mimarisi ve İşleyiş Akışı")
st.caption("Kullanıcı sorusundan nihai rapora kadar uçtan uca pipeline")

_mermaid_html = """
<!DOCTYPE html>
<html>
<head>
  <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
</head>
<body style="margin:0; background:#1e293b; padding:16px 20px 24px 20px; border-radius:10px; border:1px solid #2d3a4a; min-height:420px;">
  <div class="mermaid">
%%{init: {
  "theme": "base",
  "themeVariables": {
    "primaryColor":       "#3b82f6",
    "primaryTextColor":   "#f1f5f9",
    "primaryBorderColor": "#1d4ed8",
    "lineColor":          "#64748b",
    "secondaryColor":     "#1e3a5f",
    "tertiaryColor":      "#0f172a",
    "background":         "#1e293b",
    "nodeBorder":         "#3b82f6",
    "clusterBkg":         "#1e293b",
    "titleColor":         "#f1f5f9",
    "edgeLabelBackground":"#1e293b",
    "fontFamily":         "Inter, sans-serif"
  }
}}%%
flowchart LR
    A("👤 Kullanıcı") --> B("🖥️ Streamlit UI")
    B --> C("🔌 POST /api/chat")
    C --> D("🔍 Extractor LLM\nJSON Intent")
    D --> E{"Araç Seçimi"}
    E -->|eBPF| F1("📦 eBPF Snapshot")
    E -->|Port| F2("🩺 TCP Probe")
    E -->|DNS| F3("🌐 DNS Sağlığı")
    E -->|Port Listesi| F4("🔌 Port Envanteri")
    E -->|IP Sorgu| F5("🔍 IP Analizi")
    F1 & F2 & F3 & F4 & F5 --> G("⚙️ Node.js Executor")
    G --> H("📝 Reporter LLM\nMarkdown Rapor")
    H --> B
  </div>
  <script>
    mermaid.initialize({ startOnLoad: true, theme: "base" });
  </script>
</body>
</html>
"""

components.html(_mermaid_html, height=460)

st.divider()

# ===========================================================================
# BLOK 3 — YETENEKLER (SKILL) ENVANTERİ
# ===========================================================================
st.markdown("### ⚡ Aktif Yetenekler (Skills)")
st.caption("Ajan, kullanıcı isteğine göre aşağıdaki yeteneklerden birini otomatik olarak seçer.")

st.markdown("&nbsp;", unsafe_allow_html=True)

SKILLS = [
    {
        "icon": "📦",
        "name": "eBPF Snapshot",
        "desc": "Kernel seviyesinde yakalanan son TCP paketlerini filtreler, Ters DNS ile zenginleştirir ve LLM'e analiz ettirir.",
        "tags": '"ağ trafiği", "bağlantılar", "paketler"',
    },
    {
        "icon": "🔍",
        "name": "IP Analizi",
        "desc": "Harici IP adresinin ülke, ISP ve organizasyon bilgisini ip-api.com üzerinden gerçek zamanlı sorgular.",
        "tags": '"şüpheli IP", "kim bu adres", "hangi ülke"',
    },
    {
        "icon": "🔌",
        "name": "Port Envanteri",
        "desc": "ss -tlnp komutuyla sistemdeki tüm dinleyen TCP portlarını ve hangi süreçlerin bağlandığını listeler.",
        "tags": '"hangi portlar açık", "dinleyen servisler"',
    },
    {
        "icon": "🩺",
        "name": "Port TCP Probe",
        "desc": "Belirtilen host:port çiftine gerçek TCP bağlantı denemesi yapar. OPEN / REFUSED / TIMEOUT sonucu döner.",
        "tags": '"bağlanamıyorum", "test et", ":3000 açık mı"',
    },
    {
        "icon": "🌐",
        "name": "DNS Sağlığı",
        "desc": "A ve AAAA kayıtlarını sorgular, çözüm süresini ve hata kodunu (ENOTFOUND, ETIMEOUT) raporlar.",
        "tags": '"açılmıyor", "dns sorunu", "domain"',
    },
]

skill_cols = st.columns(5)
for col, skill in zip(skill_cols, SKILLS):
    with col:
        st.markdown(
            f"""
            <div class="skill-card">
              <span class="skill-icon">{skill['icon']}</span>
              <p class="skill-name">{skill['name']}</p>
              <p class="skill-desc">{skill['desc']}</p>
              <p class="skill-tags">Tetikleyici: {skill['tags']}</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

st.divider()

# ===========================================================================
# BLOK 4 — HIZLI BAŞLANGIÇ (CTA)
# ===========================================================================
st.markdown("### 🚀 Hızlı Başlangıç")
st.caption("Sistemi kullanmaya başlamak için bir panel seç.")

st.markdown("&nbsp;", unsafe_allow_html=True)

cta_left, cta_right = st.columns(2)

with cta_left:
    st.page_link(
        "pages/01_traffic_monitor.py",
        label="📡  Canlı Trafiği İzle — eBPF ağ olaylarını gerçek zamanlı görüntüle",
        icon="📡",
        use_container_width=True,
    )

with cta_right:
    st.page_link(
        "pages/02_copilot_chat.py",
        label="🤖  Siber Copilot'u Başlat — Ajan ile ağ trafiğini analiz et",
        icon="🤖",
        use_container_width=True,
    )

st.divider()

# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------
st.markdown(
    "<p style='text-align:center; color:#475569; font-size:0.75rem;'>"
    "Powered by eBPF &nbsp;·&nbsp; Go &nbsp;·&nbsp; Node.js &nbsp;·&nbsp; "
    "LangChain &nbsp;·&nbsp; Llama 3.1 &nbsp;·&nbsp; Streamlit"
    "</p>",
    unsafe_allow_html=True,
)
