from __future__ import annotations

from pathlib import Path
from typing import Iterable
import time
import unicodedata
import re
import shutil
import hashlib
import hmac
import json
import secrets
from datetime import datetime
import os
from zoneinfo import ZoneInfo

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

BASE = Path(__file__).resolve().parent
RAW = BASE / "data" / "raw"
DOWNLOADS = Path.home() / "Downloads"
START_DATE = pd.Timestamp("2026-01-01")
TODAY = pd.Timestamp.today().normalize()

MONITORED_USERS = {
    "fernanda dos anjos moraes silva",
    "camilli de jesus",
    "vitoria assuncao marcelino",
    "kawany goncalves silveira",
    "lorrany isabelly da silva",
    "thais roberta melo de souza",
}

USER_DISPLAY = {
    "fernanda dos anjos moraes silva": "Fernanda",
    "camilli de jesus": "Camilli",
    "vitoria assuncao marcelino": "Vitoria",
    "kawany goncalves silveira": "Kawany",
    "lorrany isabelly da silva": "Lorrany",
    "thais roberta melo de souza": "Thais",
}

st.set_page_config(
    page_title="Market4U BI 2026",
    page_icon="📊",
    layout="wide",
)

st.markdown(
    """
    <style>
    .block-container {padding-top: 1.25rem; padding-bottom: 2rem;}
    [data-testid="stMetric"] {
        background: #ffffff;
        border: 1px solid #e7e7e7;
        border-radius: 12px;
        padding: 14px;
        box-shadow: 0 1px 2px rgba(0,0,0,.03);
    }
    .small-note {color:#666; font-size:.90rem;}
    </style>
    """,
    unsafe_allow_html=True,
)


def strip_accents(value: object) -> str:
    text = "" if value is None else str(value)
    return "".join(
        char for char in unicodedata.normalize("NFKD", text)
        if not unicodedata.combining(char)
    ).strip().casefold()



AUTH_FILE = BASE / "data" / "auth.json"
ACCESS_LOG_FILE = BASE / "data" / "access_log.csv"
LOCAL_TZ = ZoneInfo("America/Sao_Paulo")
LOGIN_USERS = {
    "joao paulo": "João Paulo",
    "kawany": "Kawany",
    "camilli": "Camilli",
    "vitoria": "Vitoria",
    "fernanda": "Fernanda",
}


def _hash_password(password: str, salt_hex: str | None = None) -> dict[str, str | int]:
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    iterations = 240_000
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return {
        "salt": salt.hex(),
        "hash": digest.hex(),
        "iterations": iterations,
    }


def _verify_password(password: str, record: dict) -> bool:
    try:
        salt = bytes.fromhex(record["salt"])
        iterations = int(record.get("iterations", 240_000))
        expected = bytes.fromhex(record["hash"])
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def _load_auth() -> dict:
    # Primeiro tenta carregar os acessos já configurados no primeiro acesso
    if AUTH_FILE.exists():
        try:
            data = json.loads(AUTH_FILE.read_text(encoding="utf-8"))
            if data.get("users"):
                return data
        except Exception:
            pass

    # Se não houver arquivo de autenticação, tenta usar variáveis de ambiente
    users_config = [
        ("fernanda", "Fernanda", "SENHA_FERNANDA", "admin"),
        ("joao paulo", "João Paulo", "SENHA_JOAO_PAULO", "full"),
        ("kawany", "Kawany", "SENHA_KAWANY", "full"),
        ("camilli", "Camilli", "SENHA_CAMILLI", "devedores"),
        ("vitoria", "Vitória", "SENHA_VITORIA", "devedores"),
    ]

    users = {}

    for username, display, env_name, role in users_config:
        password = os.getenv(env_name, "")
        if password:
            users[username] = {
                "display": display,
                "role": role,
                **_hash_password(password),
            }

    return {"users": users}


def _save_auth(data: dict) -> None:
    AUTH_FILE.parent.mkdir(parents=True, exist_ok=True)
    AUTH_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _register_access(user_key: str, display: str) -> None:
    """Registra somente logins bem-sucedidos; nunca grava senha."""
    ACCESS_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    now = datetime.now(LOCAL_TZ)
    row = pd.DataFrame([{
        "timestamp": now.isoformat(timespec="seconds"),
        "usuario": user_key,
        "nome": display,
        "data": now.strftime("%d/%m/%Y"),
        "hora": now.strftime("%H:%M:%S"),
    }])
    if ACCESS_LOG_FILE.exists():
        try:
            old = pd.read_csv(ACCESS_LOG_FILE, dtype=str)
            row = pd.concat([old, row], ignore_index=True)
        except Exception:
            pass
    row.to_csv(ACCESS_LOG_FILE, index=False, encoding="utf-8-sig")


def _load_access_log() -> pd.DataFrame:
    cols = ["timestamp", "usuario", "nome", "data", "hora"]
    if not ACCESS_LOG_FILE.exists():
        return pd.DataFrame(columns=cols)
    try:
        df = pd.read_csv(ACCESS_LOG_FILE, dtype=str)
        for col in cols:
            if col not in df.columns:
                df[col] = ""
        return df[cols]
    except Exception:
        return pd.DataFrame(columns=cols)



def require_login() -> None:
    auth = _load_auth()

    # PRIMEIRO ACESSO - CRIAR TODAS AS SENHAS
    if not auth.get("users"):
        st.title("🔐 Configurar acesso ao Monitoramento")
        st.info(
            "Primeiro acesso: configure os acessos. "
            "As senhas são armazenadas somente como hash, não em texto aberto."
        )

        with st.form("first_setup"):
            p_fernanda = st.text_input("Senha de Fernanda", type="password")
            pc_fernanda = st.text_input(
                "Confirmar senha de Fernanda",
                type="password"
            )

            p_joao = st.text_input("Senha de João Paulo", type="password")
            pc_joao = st.text_input(
                "Confirmar senha de João Paulo",
                type="password"
            )

            p_kawany = st.text_input("Senha de Kawany", type="password")
            pc_kawany = st.text_input(
                "Confirmar senha de Kawany",
                type="password"
            )

            p_camilli = st.text_input("Senha de Camilli", type="password")
            pc_camilli = st.text_input(
                "Confirmar senha de Camilli",
                type="password"
            )

            p_vitoria = st.text_input("Senha de Vitória", type="password")
            pc_vitoria = st.text_input(
                "Confirmar senha de Vitória",
                type="password"
            )

            submit = st.form_submit_button("Salvar acessos")

        if submit:
            senhas = {
                "fernanda": (p_fernanda, pc_fernanda),
                "joao paulo": (p_joao, pc_joao),
                "kawany": (p_kawany, pc_kawany),
                "camilli": (p_camilli, pc_camilli),
                "vitoria": (p_vitoria, pc_vitoria),
            }

            if any(
                len(senha) < 6
                for senha, confirmacao in senhas.values()
            ):
                st.error(
                    "Todas as senhas devem ter pelo menos 6 caracteres."
                )

            elif any(
                senha != confirmacao
                for senha, confirmacao in senhas.values()
            ):
                st.error(
                    "Uma ou mais confirmações de senha não coincidem."
                )

            else:
                data = {
                    "users": {
                        "fernanda": {
                            "display": "Fernanda",
                            "role": "admin",
                            **_hash_password(p_fernanda),
                        },
                        "joao paulo": {
                            "display": "João Paulo",
                            "role": "full",
                            **_hash_password(p_joao),
                        },
                        "kawany": {
                            "display": "Kawany",
                            "role": "full",
                            **_hash_password(p_kawany),
                        },
                        "camilli": {
                            "display": "Camilli",
                            "role": "devedores",
                            **_hash_password(p_camilli),
                        },
                        "vitoria": {
                            "display": "Vitória",
                            "role": "devedores",
                            **_hash_password(p_vitoria),
                        },
                    }
                }

                _save_auth(data)
                st.success("Todos os acessos foram criados com sucesso.")
                st.rerun()

        st.stop()

    # LOGIN
    if not st.session_state.get("authenticated"):
        st.title("🔐 Monitoramento")
        st.caption("Acesso restrito")

        with st.form("login_form"):
            username = st.text_input("Usuário")
            password = st.text_input("Senha", type="password")
            submitted = st.form_submit_button("Entrar")

        if submitted:
            key = strip_accents(username)
            record = auth.get("users", {}).get(key)

            if record and _verify_password(password, record):
                display = record.get("display", username)

                st.session_state["authenticated"] = True
                st.session_state["login_user"] = key
                st.session_state["login_display"] = display
                st.session_state["login_role"] = record.get("role", "full")

                _register_access(key, display)
                st.rerun()

            else:
                st.error("Usuário ou senha inválidos.")

        st.stop()

       # USUÁRIO JÁ LOGADO
    with st.sidebar:
        st.caption(
            f"Conectado como **{st.session_state.get('login_display', '')}**"
        )

        if st.button("Sair", use_container_width=True):
            for k in (
                "authenticated",
                "login_user",
                "login_display",
                "login_role",
            ):
                st.session_state.pop(k, None)

            st.rerun()


def read_csv_flexible(source):
    """Read Market4U CSVs with the encodings normally used by the exports."""
    last_error = None
    for encoding in ("utf-8-sig", "utf-8", "latin1"):
        try:
            return pd.read_csv(source, sep=";", encoding=encoding, low_memory=False)
        except Exception as exc:  # pragma: no cover - fallback behavior
            last_error = exc
            if hasattr(source, "seek"):
                source.seek(0)
    raise last_error


@st.cache_data(show_spinner=False)
def read_path_cached(path_text: str, mtime_ns: int) -> pd.DataFrame:
    del mtime_ns  # Used only to invalidate Streamlit's cache when the file changes.
    return read_csv_flexible(Path(path_text))


def read_path(path: Path) -> pd.DataFrame:
    return read_path_cached(str(path), path.stat().st_mtime_ns).copy()


def money_to_float(series: pd.Series) -> pd.Series:
    values = series.astype(str).str.replace("R$", "", regex=False).str.strip()
    values = values.replace({"--": None, "nan": None, "None": None, "": None})
    values = values.str.replace(".", "", regex=False).str.replace(",", ".", regex=False)
    return pd.to_numeric(values, errors="coerce").fillna(0.0)


def brl(value: float) -> str:
    return f"R$ {value:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")


def normalize_link_id(series: pd.Series) -> pd.Series:
    # Extract the numeric payment-link ID and avoid values such as '--' or 'nan'.
    return series.astype(str).str.extract(r"(\d+)", expand=False)


def source_name(source) -> str:
    if isinstance(source, Path):
        return source.name
    return getattr(source, "name", "arquivo_enviado.csv")


def discover_download_files(patterns: Iterable[str]) -> list[Path]:
    if not DOWNLOADS.exists():
        return []
    found: dict[str, Path] = {}
    for pattern in patterns:
        for path in DOWNLOADS.glob(pattern):
            if path.is_file():
                found[str(path.resolve())] = path
    return sorted(found.values(), key=lambda p: (p.stat().st_mtime_ns, p.name))


def load_transactions(uploaded_files=None, include_downloads: bool = True):
    sources: list = []
    sources.extend(sorted(p for p in RAW.glob("*.csv") if not p.name.startswith("links_")))
    if include_downloads:
        sources.extend(discover_download_files(["market4u-cliente_transacoes_*.csv"]))
    if uploaded_files:
        sources.extend(uploaded_files)

    frames: list[pd.DataFrame] = []
    failed: list[str] = []
    for source_order, source in enumerate(sources):
        try:
            frame = read_path(source) if isinstance(source, Path) else read_csv_flexible(source)
            if "Data e hora" not in frame.columns or "ID" not in frame.columns:
                continue
            frame["_fonte"] = source_name(source)
            frame["_ordem_fonte"] = source_order
            frames.append(frame)
        except Exception:
            failed.append(source_name(source))

    if not frames:
        return pd.DataFrame(), set(), failed

    data = pd.concat(frames, ignore_index=True)
    data["Data e hora"] = pd.to_datetime(data["Data e hora"], errors="coerce")
    data = data[
        (data["Data e hora"] >= START_DATE)
        & (data["Data e hora"] < TODAY + pd.Timedelta(days=1))
    ].copy()

    data = data.sort_values(["Data e hora", "_ordem_fonte"])
    data = data.drop_duplicates(subset=["ID"], keep="last")
    # Valor recuperado financeiro: use o Subtotal da transação de cobrança.
    # Isso representa o valor efetivamente recebido e evita inflar o recuperado
    # com saldo de carteira/voucher. Mantemos o Total bruto apenas para auditoria.
    data["Valor bruto"] = money_to_float(data.get("Total", pd.Series(index=data.index, dtype=str)))
    data["Valor"] = money_to_float(data.get("Subtotal", data.get("Total", pd.Series(index=data.index, dtype=str))))
    data["Link ID"] = normalize_link_id(
        data.get("ID link de pagamento", pd.Series(index=data.index, dtype=str))
    )
    data["Mês"] = data["Data e hora"].dt.to_period("M").astype(str)
    months_available = set(data["Mês"].dropna().unique())
    return data, months_available, failed


def load_links(uploaded_files=None, include_downloads: bool = True):
    sources: list = []
    sources.extend(sorted(p for p in RAW.glob("links_*.csv")))
    if include_downloads:
        sources.extend(discover_download_files(["market4u-sistema_link_pg*.csv"]))
    if uploaded_files:
        sources.extend(uploaded_files)

    frames: list[pd.DataFrame] = []
    failed: list[str] = []
    for source_order, source in enumerate(sources):
        try:
            frame = read_path(source) if isinstance(source, Path) else read_csv_flexible(source)
            required = {"Status", "ID", "Data"}
            if not required.issubset(frame.columns):
                continue
            frame["_fonte"] = source_name(source)
            frame["_ordem_fonte"] = source_order
            frames.append(frame)
        except Exception:
            failed.append(source_name(source))

    if not frames:
        return pd.DataFrame(), failed

    data = pd.concat(frames, ignore_index=True)
    data["Data"] = pd.to_datetime(data["Data"], errors="coerce")
    data = data[
        (data["Data"] >= START_DATE)
        & (data["Data"] < TODAY + pd.Timedelta(days=1))
    ].copy()
    data["Link ID"] = normalize_link_id(data["ID"])
    data["Valor_num"] = money_to_float(
        data.get("Valor", pd.Series(index=data.index, dtype=str))
    )
    data = data.sort_values(["Data", "_ordem_fonte"])
    data = data.drop_duplicates(subset=["Link ID"], keep="last")
    return data, failed


def consolidated_charge_total(frame: pd.DataFrame) -> float | None:
    """Return the official 'Cobranças' subtotal from a Vendas Consolidadas export."""
    if "Tipo" not in frame.columns:
        return None
    type_norm = frame["Tipo"].map(strip_accents)
    rows = frame[type_norm.eq("cobrancas")].copy()
    if rows.empty:
        return None
    preferred = [
        "Subtotal =   ( Total - Desconto )",
        "Subtotal = ( Total - Desconto )",
        "Subtotal  - Saldo da carteira (Voucher)",
        "Total =  ( Formas de pg + Desconto )",
    ]
    for column in preferred:
        if column in rows.columns:
            return float(money_to_float(rows[column]).sum())
    # Fallback: sum payment-method columns while excluding totals/discounts/wallet fields.
    excluded_tokens = ("total", "subtotal", "desconto", "cashback", "saldo da carteira", "voucher")
    candidates = [
        c for c in rows.columns
        if c != "Tipo" and not any(token in strip_accents(c) for token in excluded_tokens)
    ]
    if not candidates:
        return None
    return float(sum(money_to_float(rows[c]).sum() for c in candidates))


def infer_consolidated_month(name: str) -> str | None:
    """Infer YYYY-MM only when the month is explicitly present in the filename."""
    text = strip_accents(Path(str(name)).stem)
    match = re.search(r"(20\d{2})[-_](0[1-9]|1[0-2])", text)
    if match:
        return f"{match.group(1)}-{match.group(2)}"
    months = {
        "janeiro": 1, "fevereiro": 2, "marco": 3, "abril": 4,
        "maio": 5, "junho": 6, "julho": 7, "agosto": 8,
        "setembro": 9, "outubro": 10, "novembro": 11, "dezembro": 12,
    }
    year_match = re.search(r"20\d{2}", text)
    if year_match:
        for label, month in months.items():
            if label in text:
                return f"{year_match.group(0)}-{month:02d}"
    return None


def load_consolidated(uploaded_files=None, include_downloads: bool = True):
    sources: list = []
    # Only files whose filename explicitly identifies the month can feed the monthly KPI.
    sources.extend(sorted(RAW.glob("consolidado_*.csv")))
    sources.extend(sorted(RAW.glob("market4u-vendas_consolidadas*.csv")))
    if include_downloads:
        sources.extend(discover_download_files(["market4u-vendas_consolidadas*.csv"]))
    if uploaded_files:
        sources.extend(uploaded_files)

    records = []
    failed = []
    for source_order, source in enumerate(sources):
        try:
            frame = read_path(source) if isinstance(source, Path) else read_csv_flexible(source)
            total = consolidated_charge_total(frame)
            if total is None:
                continue
            name = source_name(source)
            mtime = source.stat().st_mtime if isinstance(source, Path) else time.time()
            records.append({
                "fonte": name,
                "mes": infer_consolidated_month(name),
                "total_cobrancas": total,
                "mtime": mtime,
                "ordem": source_order,
            })
        except Exception:
            failed.append(source_name(source))
    if not records:
        return pd.DataFrame(), failed
    result = pd.DataFrame(records).sort_values(["mtime", "ordem"])
    return result, failed


require_login()

st.title("📊 Market4U BI — Cobranças e Recuperações 2026")

with st.sidebar:
    st.header("Atualizar dados")
    auto_downloads = st.checkbox(
        "Ler novas exportações da pasta Downloads",
        value=True,
        help=(
            "Ao deixar marcado, o BI procura arquivos "
            "market4u-cliente_transacoes_*.csv e market4u-sistema_link_pg*.csv."
        ),
    )
    auto_refresh_5min = st.checkbox(
        "Atualizar automaticamente a cada 5 minutos",
        value=True,
        key="auto_refresh_5min",
        disabled=not auto_downloads,
        help=(
            "Com o BI aberto, ele verifica a pasta Downloads a cada 5 minutos. "
            "Se houver uma nova exportação do Market4U, os indicadores são recalculados automaticamente."
        ),
    )
    if auto_downloads and auto_refresh_5min:
        st.success("Atualização automática ativa • verificação a cada 5 min")
    elif auto_downloads:
        st.info("Leitura de Downloads ativa • atualização automática desligada")
    transaction_uploads = st.file_uploader(
        "CSV de transações",
        type=["csv"],
        accept_multiple_files=True,
        key="transactions",
    )
    link_uploads = st.file_uploader(
        "CSV de links de pagamento",
        type=["csv"],
        accept_multiple_files=True,
        key="links",
    )
    consolidated_uploads = st.file_uploader(
        "CSV de Vendas Consolidadas",
        type=["csv"],
        accept_multiple_files=True,
        key="consolidated",
        help="Fonte oficial do indicador Valor recuperado (linha Cobranças).",
    )
    if st.button("Atualizar agora", use_container_width=True):
        st.cache_data.clear()
        st.session_state["_last_auto_full_refresh"] = time.time()
        st.rerun()


@st.fragment(run_every=300)
def automatic_downloads_refresh():
    """Trigger a full BI refresh every five minutes while the app is open."""
    if not st.session_state.get("auto_refresh_5min", True):
        return
    now = time.time()
    last = st.session_state.get("_last_auto_full_refresh")
    if last is None:
        st.session_state["_last_auto_full_refresh"] = now
        return
    # The fragment itself runs every 5 minutes. The guard prevents an immediate
    # rerun loop after the full app refresh.
    if now - last >= 290:
        st.session_state["_last_auto_full_refresh"] = now
        st.cache_data.clear()
        st.rerun()


automatic_downloads_refresh()

transactions, months_available, transaction_failures = load_transactions(
    transaction_uploads,
    include_downloads=auto_downloads,
)
links, link_failures = load_links(link_uploads, include_downloads=auto_downloads)
consolidated, consolidated_failures = load_consolidated(
    consolidated_uploads, include_downloads=auto_downloads
)

with st.sidebar:
    if auto_downloads:
        tx_files = discover_download_files(["market4u-cliente_transacoes_*.csv"])
        link_files = discover_download_files(["market4u-sistema_link_pg*.csv"])
        consolidated_files = discover_download_files(["market4u-vendas_consolidadas*.csv"])
        st.caption(
            f"Downloads detectados: {len(tx_files)} arquivo(s) de transações, "
            f"{len(link_files)} arquivo(s) de links e "
            f"{len(consolidated_files)} de Vendas Consolidadas."
        )
        if tx_files:
            newest = max(tx_files, key=lambda p: p.stat().st_mtime_ns)
            newest_time = pd.Timestamp.fromtimestamp(newest.stat().st_mtime).strftime("%d/%m/%Y %H:%M")
            st.caption(f"Última exportação detectada: {newest.name} • {newest_time}")

if transactions.empty:
    st.error("Nenhuma transação de 2026 foi encontrada.")
    st.stop()

last_data_date = transactions["Data e hora"].max()
data_end = min(TODAY, last_data_date.normalize()) if pd.notna(last_data_date) else TODAY
st.caption(
    f"Período: 01/01/2026 até {data_end.strftime('%d/%m/%Y')} "
    "• dados anteriores a 2026 são ignorados"
)

# ============================================================
# CONCILIAÇÃO DE CARRINHOS / COBRANÇAS
# Regra oficial:
# cada "Pagamento efetuada (cobrança)" = 1 carrinho recuperado.
# O arquivo de links identifica colaboradora, cliente e status.
# O valor recuperado vem do Subtotal da transação.
# ============================================================

type_normalized = (
    transactions["Tipo"]
    .astype(str)
    .str.strip()
    .map(strip_accents)
)

recovery_type = type_normalized.eq(
    strip_accents("Pagamento efetuada (cobrança)")
)

# Todo pagamento de cobrança é um carrinho recuperado.
recovered = transactions[recovery_type].copy()

recovered["Valor_recuperado"] = money_to_float(
    recovered.get(
        "Subtotal",
        recovered.get(
            "Total",
            pd.Series(index=recovered.index, dtype=str),
        ),
    )
)

recovered["Link ID"] = normalize_link_id(
    recovered.get(
        "ID link de pagamento",
        pd.Series(index=recovered.index, dtype=str),
    )
)

recovered["Data_pagamento"] = pd.to_datetime(
    recovered["Data e hora"],
    errors="coerce",
)

recovered["Mês pagamento"] = (
    recovered["Data_pagamento"]
    .dt.to_period("M")
    .astype(str)
)

# Classificação da taxa
recovered["Taxa"] = (
    recovered
    .get(
        "Possui taxa de cobrança",
        pd.Series("--", index=recovered.index),
    )
    .astype(str)
    .str.strip()
    .map(strip_accents)
    .map({
        "sim": "Com taxa",
        "nao": "Sem taxa",
    })
    .fillna("Não informado")
)

# ------------------------------------------------------------
# PREPARAR BASE DE LINKS
# ------------------------------------------------------------

links_prod = links.copy()

if not links_prod.empty:

    links_prod["Link ID"] = normalize_link_id(
        links_prod["ID"]
    )

    links_prod["Data"] = pd.to_datetime(
        links_prod["Data"],
        errors="coerce",
    )

    if "Data pagamento" in links_prod.columns:
        links_prod["Data pagamento"] = pd.to_datetime(
            links_prod["Data pagamento"],
            errors="coerce",
        )

    links_prod["Valor_num"] = money_to_float(
        links_prod.get(
            "Valor",
            pd.Series(index=links_prod.index, dtype=str),
        )
    )

    links_prod["Valor_pago_num"] = money_to_float(
        links_prod.get(
            "Valor pago",
            pd.Series(index=links_prod.index, dtype=str),
        )
    )

    links_prod["_usuario_norm"] = (
        links_prod
        .get(
            "Usuário",
            pd.Series("", index=links_prod.index),
        )
        .map(strip_accents)
    )

    # Identifica a colaboradora
    links_prod["Colaboradora"] = (
        links_prod["_usuario_norm"]
        .map(USER_DISPLAY)
    )

    # Se aparecer outro usuário, mantém o nome original
    links_prod["Colaboradora"] = (
        links_prod["Colaboradora"]
        .fillna(
            links_prod.get(
                "Usuário",
                pd.Series("Não identificado", index=links_prod.index),
            )
        )
        .replace({
            "": "Não identificado",
            "--": "Não identificado",
        })
        .fillna("Não identificado")
    )

    links_prod["Status_norm"] = (
        links_prod["Status"]
        .astype(str)
        .str.strip()
        .map(strip_accents)
    )

else:
    links_prod = pd.DataFrame()


# ------------------------------------------------------------
# ATRIBUIR PAGAMENTOS ÀS COLABORADORAS
# ------------------------------------------------------------

recovery_events = recovered.copy()

if not links_prod.empty:

    link_info = (
        links_prod
        .sort_values("Data")
        .drop_duplicates(
            subset=["Link ID"],
            keep="last",
        )
    )

    link_columns = [
        "Link ID",
        "Colaboradora",
        "Usuário",
        "Status",
        "Nome",
        "Valor_num",
        "Valor_pago_num",
        "Data",
    ]

    link_columns = [
        c for c in link_columns
        if c in link_info.columns
    ]

    recovery_events = recovery_events.merge(
        link_info[link_columns],
        on="Link ID",
        how="left",
        suffixes=("", "_link"),
    )

else:
    recovery_events["Colaboradora"] = "Não identificado"


recovery_events["Colaboradora"] = (
    recovery_events
    .get(
        "Colaboradora",
        pd.Series(
            "Não identificado",
            index=recovery_events.index,
        ),
    )
    .fillna("Não identificado")
)

# Cliente: prioriza o cliente da transação
recovery_events["Cliente"] = recovery_events.get(
    "Nome Cliente",
    pd.Series("", index=recovery_events.index),
)

if "Nome" in recovery_events.columns:

    recovery_events["Cliente"] = (
        recovery_events["Cliente"]
        .replace({"--": "", "nan": ""})
        .fillna("")
    )

    missing_client = (
        recovery_events["Cliente"]
        .astype(str)
        .str.strip()
        .eq("")
    )

    recovery_events.loc[
        missing_client,
        "Cliente",
    ] = recovery_events.loc[
        missing_client,
        "Nome",
    ]


# Condomínio vem da transação
recovery_events["Condomínio"] = recovery_events.get(
    "PDX",
    pd.Series(
        "(Não identificado)",
        index=recovery_events.index,
    ),
)

recovery_events["Condomínio filtro"] = (
    recovery_events["Condomínio"]
    .fillna("(Não identificado)")
)

recovery_events["Situação reconciliada"] = "Pago"

recovery_events["Data referência"] = (
    recovery_events["Data_pagamento"]
)

recovery_events["Mês"] = (
    recovery_events["Data referência"]
    .dt.to_period("M")
    .astype(str)
)

recovery_events["Dia"] = (
    recovery_events["Data referência"]
    .dt.normalize()
)


# ------------------------------------------------------------
# PENDENTES E CANCELADOS
# ------------------------------------------------------------

open_links = pd.DataFrame()

if not links_prod.empty:

    non_paid = links_prod[
        links_prod["Status_norm"].isin(
            [
                "pendente",
                "aguardando pagamento",
                "cancelado",
            ]
        )
    ].copy()

    non_paid["Situação reconciliada"] = (
        non_paid["Status_norm"]
        .map({
            "pendente": "Pendente",
            "aguardando pagamento": "Pendente",
            "cancelado": "Cancelado",
        })
    )

    non_paid["Cliente"] = non_paid.get(
        "Nome",
        pd.Series("", index=non_paid.index),
    )

    non_paid["Valor_recuperado"] = 0.0

    non_paid["Data referência"] = non_paid["Data"]

    non_paid["Mês"] = (
        non_paid["Data referência"]
        .dt.to_period("M")
        .astype(str)
    )

    non_paid["Dia"] = (
        non_paid["Data referência"]
        .dt.normalize()
    )

    if "Condomínio" not in non_paid.columns:
        non_paid["Condomínio"] = "(Não identificado)"

    non_paid["Condomínio filtro"] = (
        non_paid["Condomínio"]
        .fillna("(Não identificado)")
    )

    open_links = non_paid


# ------------------------------------------------------------
# PRODUTIVIDADE FINAL
# Pago = transação real
# Pendente/Cancelado = arquivo de links
# ------------------------------------------------------------

productivity_links = pd.concat(
    [
        recovery_events,
        open_links,
    ],
    ignore_index=True,
    sort=False,
)

productivity_links["Colaboradora"] = (
    productivity_links["Colaboradora"]
    .fillna("Não identificado")
)

if "Valor_num" not in productivity_links.columns:
    productivity_links["Valor_num"] = 0.0

productivity_links["Valor_num"] = (
    pd.to_numeric(
        productivity_links["Valor_num"],
        errors="coerce",
    )
    .fillna(0.0)
)

# Nos pagos, o valor correto vem do Subtotal da transação
paid_mask = (
    productivity_links["Situação reconciliada"]
    .eq("Pago")
)

productivity_links.loc[
    paid_mask,
    "Valor_num",
] = productivity_links.loc[
    paid_mask,
    "Valor_recuperado",
]


# ------------------------------------------------------------
# PENDÊNCIAS / DEVEDORES
# ------------------------------------------------------------

pending = productivity_links[
    productivity_links["Situação reconciliada"]
    .eq("Pendente")
].copy()

if not pending.empty:

    pending["Dias em aberto"] = (
        TODAY
        - pending["Data referência"].dt.normalize()
    ).dt.days.clip(lower=0)


# IDs pagos
paid_ids = set(
    recovery_events["Link ID"]
    .dropna()
)

# IDs cancelados
canceled_ids = set()

if not links_prod.empty:

       canceled_ids = set(
        links_prod.loc[
            links_prod["Status_norm"].eq("cancelado"),
            "Link ID",
        ].dropna()
    )

month_periods = pd.period_range(START_DATE, data_end, freq="M")
month_codes = month_periods.astype(str)

month_labels = {
    code: pd.Period(code, freq="M").strftime("%b/%y").replace("Jan", "Jan")
    for code in month_codes
}

# Portuguese labels independent of operating-system locale.
month_names_pt = {
    1: "Jan", 2: "Fev", 3: "Mar", 4: "Abr", 5: "Mai", 6: "Jun",
    7: "Jul", 8: "Ago", 9: "Set", 10: "Out", 11: "Nov", 12: "Dez",
}
month_labels = {
    code: f"{month_names_pt[pd.Period(code).month]}/{str(pd.Period(code).year)[-2:]}"
    for code in month_codes
}

monthly_rows = []
for month_code in month_codes:
    subset = recovered[recovered["Mês"].eq(month_code)]
    total_detail = float(subset["Valor"].sum())
    with_tax = float(subset.loc[subset["Taxa"].eq("Com taxa"), "Valor"].sum())
    without_tax = float(subset.loc[subset["Taxa"].eq("Sem taxa"), "Valor"].sum())
    unknown_tax = float(subset.loc[subset["Taxa"].eq("Não informado"), "Valor"].sum())
    monthly_rows.append({
        "Mês": month_code,
        "Período": month_labels[month_code],
        "Recuperado total": total_detail,
        "Com taxa": with_tax,
        "Sem taxa": without_tax,
        "Taxa não informada": unknown_tax,
        "Pagamentos": len(subset),
        "Clientes": subset.get("Nome Cliente", pd.Series(dtype=str)).nunique(),
        "Arquivo detalhado": "Sim" if month_code in months_available else "Não recebido",
        "Fonte": "Transações • Subtotal de Pagamento efetuada (cobrança)",
    })
monthly = pd.DataFrame(monthly_rows)

# O Vendas Consolidadas mais recente é usado automaticamente para o mês corrente
# como valor oficial de conferência. Não exige cadastro manual de mês.
latest_official_total = None
latest_official_source = None
if not consolidated.empty:
    latest = consolidated.sort_values(["mtime", "ordem"]).iloc[-1]
    latest_official_total = float(latest["total_cobrancas"])
    latest_official_source = str(latest["fonte"])
    current_code = f"{data_end.year:04d}-{data_end.month:02d}"
    mask_current = monthly["Mês"].eq(current_code)
    if mask_current.any():
        monthly.loc[mask_current, "Recuperado total"] = latest_official_total
        monthly.loc[mask_current, "Fonte"] = f"Vendas Consolidadas • {latest_official_source}"

with st.sidebar:
    st.divider()
    login_user = st.session_state.get("login_user", "")
    if login_user in {"camilli", "vitoria"}:
        page_options = ["Devedores"]
    else:
        page_options = [
            "Visão geral",
            "Recuperações",
            "Produtividade",
            "Devedores",
            "Condomínios",
            "Qualidade dos dados",
            "Transações",
        ]
        if login_user == "fernanda":
            page_options.append("Acessos")
    page = st.radio("Seção", page_options)

if page == "Visão geral":
    c1, c2, c3, c4, c5 = st.columns(5)
    recovered_total_2026 = float(pd.to_numeric(monthly["Recuperado total"], errors="coerce").fillna(0).sum())
    c1.metric("Valor recuperado", brl(recovered_total_2026))
    c2.metric(
        "Em cobranças com taxa",
        brl(monthly["Com taxa"].sum()),
    )
    c3.metric(
        "Em cobranças sem taxa",
        brl(monthly["Sem taxa"].sum()),
    )
    c4.metric("Pagamentos recuperados", f"{len(recovered):,}".replace(",", "."))
    c5.metric("Pendências em aberto", f"{len(pending):,}".replace(",", "."))

    if latest_official_total is not None:
        st.success(
            f"Conferência do período atual: Vendas Consolidadas = {brl(latest_official_total)}."
        )
    st.caption(
        "Regra única: por mês, o BI soma o Subtotal apenas das linhas 'Pagamento efetuada (cobrança)'. "
        "Para o mês atual, o Vendas Consolidadas mais recente substitui o total como valor oficial de conferência."
    )

    st.subheader("Recuperação mensal")
    figure = go.Figure()
    figure.add_bar(x=monthly["Período"], y=monthly["Sem taxa"], name="Sem taxa")
    figure.add_bar(x=monthly["Período"], y=monthly["Com taxa"], name="Com taxa")
    if monthly["Taxa não informada"].sum() > 0:
        figure.add_bar(
            x=monthly["Período"],
            y=monthly["Taxa não informada"],
            name="Taxa não informada",
        )
    figure.update_layout(
        barmode="stack",
        yaxis_title="Valor recuperado (R$)",
        xaxis_title="",
        height=410,
        legend_title="Classificação",
        margin=dict(t=15, b=20),
    )
    st.plotly_chart(figure, use_container_width=True)

    missing_months = [month_labels[m] for m in month_codes if m not in months_available]
    if missing_months:
        st.warning(
            "Arquivo detalhado ainda não recebido para: "
            + ", ".join(missing_months)
            + ". O BI mantém esses meses zerados, sem estimar valores."
        )
    else:
        st.success("Todos os meses de janeiro até o período atual possuem arquivo detalhado.")

    if not pending.empty:
        st.subheader("Pendências atuais")
        p1, p2, p3 = st.columns(3)
        p1.metric("Valor em aberto", brl(pending["Valor_num"].sum()))
        p2.metric("Links pendentes", len(pending))
        p3.metric("Com mais de 30 dias", int((pending["Dias em aberto"] > 30).sum()))

elif page == "Recuperações":
    st.subheader("Recuperado mês a mês")
    table = monthly[
        [
            "Período",
            "Recuperado total",
            "Com taxa",
            "Sem taxa",
            "Taxa não informada",
            "Pagamentos",
            "Clientes",
            "Arquivo detalhado",
            "Fonte",
        ]
    ].copy()
    def brl_or_pending(value):
        return "Não importado" if pd.isna(value) else brl(float(value))
    table["Recuperado total"] = table["Recuperado total"].map(brl_or_pending)
    for column in ["Com taxa", "Sem taxa", "Taxa não informada"]:
        table[column] = table[column].map(brl)
    st.dataframe(table, use_container_width=True, hide_index=True)

    st.caption(
        "Os valores “Com taxa” e “Sem taxa” são separados pela coluna "
        "Possui taxa de cobrança do Market4U."
    )

    st.subheader("Detalhamento")
    selected_labels = st.multiselect(
        "Mês",
        list(month_labels.values()),
        default=list(month_labels.values()),
    )
    reverse_labels = {label: code for code, label in month_labels.items()}
    selected_months = [reverse_labels[label] for label in selected_labels]
    detail = recovered[recovered["Mês"].isin(selected_months)].copy()
    tax_option = st.selectbox(
        "Classificação da taxa",
        ["Todas", "Com taxa", "Sem taxa", "Não informado"],
    )
    if tax_option != "Todas":
        detail = detail[detail["Taxa"].eq(tax_option)]
    detail_columns = [
        column
        for column in [
            "Data e hora",
            "PDX",
            "Nome Cliente",
            "ID link de pagamento",
            "Total",
            "Taxa",
            "Forma pagamento",
        ]
        if column in detail.columns
    ]
    st.dataframe(
        detail[detail_columns].sort_values("Data e hora", ascending=False),
        use_container_width=True,
        hide_index=True,
    )

elif page == "Produtividade":
    st.subheader("Produtividade por colaboradora")
    st.caption(
        "Regra de período: recuperados entram no mês da DATA DO PAGAMENTO. "
        "Pendentes/cancelados entram no mês da criação do carrinho. Assim um link criado em janeiro e pago em fevereiro conta como recuperação de fevereiro, nunca de janeiro."
    )
    st.caption(
        "Aqui você consegue filtrar por mês, colaboradora, condomínio e status e conferir "
        "exatamente quais clientes/carrinhos formam a produtividade de cada pessoa. "
        "O pagamento é reconciliado pelo ID do link."
    )

    if productivity_links.empty:
        st.info("Nenhum link de cobrança das colaboradoras monitoradas foi encontrado.")
    else:
        # Filtros ficam dentro da própria área de produtividade.
        available_months = sorted(productivity_links["Mês"].dropna().unique(), reverse=True)
        prod_month_labels = {
            code: f"{month_names_pt[pd.Period(code).month]}/{str(pd.Period(code).year)[-2:]}"
            for code in available_months
        }
        month_label_to_code = {label: code for code, label in prod_month_labels.items()}
        selected_month_labels = st.multiselect(
            "Mês",
            [prod_month_labels[m] for m in available_months],
            default=[prod_month_labels[available_months[0]]] if available_months else [],
            key="prod_months",
        )
        selected_months = [month_label_to_code[label] for label in selected_month_labels]

        filter_cols = st.columns(3)
        collaborators = list(USER_DISPLAY.values())

        selected_collaborators = filter_cols[0].multiselect(
            "Colaboradora",
            collaborators,
            default=collaborators,
            key="prod_users",
        )

        status_options = ["Pago", "Pendente", "Cancelado"]

        selected_status = filter_cols[1].multiselect(
            "Status",
            status_options,
            default=status_options,
            key="prod_status",
        )

        condominium_options = [
    "GOWORK",
    "GRAND CLUB SC",
    "VIVA MAIS",
    "ELEVATTO",
    "IBITIRAMA",
    "NEW LIFE",
    "GIOIA",
    "YOU ACLIMAÇÃO",
    "DEZ VILA EMA",
    "MOOV",
    "BONJOUR",
    "ORIGINE MOOCA",
    "ORIGINE PISCINA",
    "TERRAZA",
    "LIVING WISH",
    "LE CHAMP",
    "VITTORIO",
    "WELCOME",
    "VOXY",
    "SUPREMO",
    "GRAND LIFE",
    "ORIGEM",
    "PARQUE SANTA ISABEL",
    "GOLDEN TOWER",
    "INSIDE",
    "SAN MARTINO",
    "NEXUS",
    "SPAZIO DELLARTE",
    "FOREVER",
    "MORADAS DO BOSQUE",
    "ILHAS DO HAWAII",
]

condominium_aliases = {
    "Condomínio Grand Life Ipiranga": "GRAND LIFE",
    "Condomínio Vittorio Emanuelle": "VITTORIO",
    "Condomínio Spazio Dellarte": "SPAZIO DELLARTE",
    "Condomínio Supremo Ipiranga": "SUPREMO",
    "Condomínio Grand Club São Caetano": "GRAND CLUB SC",
    "Condomínio Mooca Terraza": "TERRAZA",
    "Condomínio Le Champ": "LE CHAMP",
    "Condomínio Origine Mooca": "ORIGINE MOOCA",
    "Condomínio Moov": "MOOV",
    "Condomínio Origem Tatuapé": "ORIGEM",
    "Condomínio Ilhas do Havaí": "ILHAS DO HAWAII",
    "Condomínio Ilhas do Hawaii": "ILHAS DO HAWAII",
    "Condomínio Living Wish Mooca": "LIVING WISH",
    "Condomínio Parque Santa Isabel": "PARQUE SANTA ISABEL",
    "Condomínio Dez Vila Ema": "DEZ VILA EMA",
    "Condomínio Viva Mais": "VIVA MAIS",
    "Condomínio Inside Guarulhos": "INSIDE",
    "Condomínio Forever Resort": "FOREVER",
    "Condomínio Praça Ibitirama": "IBITIRAMA",
}

productivity_links["Condomínio filtro"] = (
    productivity_links["Condomínio filtro"]
    .replace(condominium_aliases)
)

selected_condominiums = filter_cols[2].multiselect(
    "Condomínio",
    condominium_options,
    default=condominium_options,
    key="prod_condominiums",
)

prod = productivity_links[
    (productivity_links["Mês"].isin(selected_months))
    & (productivity_links["Colaboradora"].isin(selected_collaborators))
    & (productivity_links["Situação reconciliada"].isin(selected_status))
    & (productivity_links["Condomínio filtro"].isin(selected_condominiums))
].copy()

if prod.empty:
    st.warning("Nenhum carrinho/link encontrado para os filtros selecionados.")
else:
            date_min = prod["Data referência"].min().normalize()
            date_max = prod["Data referência"].max().normalize()
            active_days = max((date_max - date_min).days + 1, 1)
            k1, k2, k3, k4, k5 = st.columns(5)
            paid_mask = prod["Situação reconciliada"].eq("Pago")
            pending_mask = prod["Situação reconciliada"].eq("Pendente")
            k1.metric("Carrinhos/links", len(prod))
            k2.metric("Recuperados", int(paid_mask.sum()))
            k3.metric("Pendentes", int(pending_mask.sum()))
            identified_value = float(prod.loc[paid_mask, "Valor_recuperado"].sum())
            selected_official_total = None
            current_code = f"{data_end.year:04d}-{data_end.month:02d}"
            if len(selected_months) == 1 and selected_months[0] == current_code and latest_official_total is not None:
                selected_official_total = float(latest_official_total)
            if (
                selected_official_total is not None
                and set(selected_collaborators) == set(collaborators)
                and set(selected_status) == set(status_options)
                and set(selected_condominiums) == set(condominium_options)
            ):
                displayed_recovered_value = selected_official_total
            else:
                displayed_recovered_value = identified_value
            k4.metric("Valor recuperado", brl(displayed_recovered_value))
            k5.metric(
                "Taxa de recuperação",
                f"{(100 * paid_mask.sum() / len(prod)):.1f}%".replace(".", ","),
            )

            if selected_official_total is not None and len(selected_months) == 1:
                difference = identified_value - selected_official_total
                st.caption(
                    f"Conciliação do período: Vendas Consolidadas {brl(selected_official_total)} • "
                    f"carrinhos identificados {brl(identified_value)} • diferença {brl(difference)}. "
                    "A diferença é exibida para auditoria; o BI não altera artificialmente o valor de nenhum carrinho."
                )

            summary_rows = []
            for collaborator in selected_collaborators:
                sub = prod[prod["Colaboradora"].eq(collaborator)]
                paid_count = int(sub["Situação reconciliada"].eq("Pago").sum()) if not sub.empty else 0
                summary_rows.append({
                    "Colaboradora": collaborator,
                    "Carrinhos": len(sub),
                    "Recuperados": paid_count,
                    "Pendentes": int(sub["Situação reconciliada"].eq("Pendente").sum()) if not sub.empty else 0,
                    "Cancelados": int(sub["Situação reconciliada"].eq("Cancelado").sum()) if not sub.empty else 0,
                    "Recuperado identificado_num": sub.loc[sub["Situação reconciliada"].eq("Pago"), "Valor_recuperado"].sum() if not sub.empty else 0.0,
                    "Taxa de recuperação_num": (100 * paid_count / len(sub)) if len(sub) else 0.0,
                    "Média/dia": len(sub) / active_days if active_days else 0.0,
                })
            prod_summary = pd.DataFrame(summary_rows).sort_values(
                ["Carrinhos", "Recuperados"], ascending=False
            )
            display_summary = prod_summary.copy()
            display_summary["Recuperado identificado"] = display_summary["Recuperado identificado_num"].map(brl)
            display_summary["Taxa de recuperação"] = display_summary["Taxa de recuperação_num"].map(
                lambda x: f"{x:.1f}%".replace(".", ",")
            )
            display_summary["Média/dia"] = display_summary["Média/dia"].map(
                lambda x: f"{x:.2f}".replace(".", ",")
            )
            st.dataframe(
                display_summary[[
                    "Colaboradora", "Carrinhos", "Recuperados", "Pendentes", "Cancelados",
                    "Recuperado identificado", "Taxa de recuperação", "Média/dia"
                ]],
                use_container_width=True,
                hide_index=True,
            )

            if selected_official_total is not None and len(selected_months) == 1:
                identified_people = float(prod.loc[paid_mask, "Valor_recuperado"].sum())
                not_attributed = selected_official_total - identified_people
                st.info(
                    f"Fechamento do mês: oficial Vendas Consolidadas {brl(selected_official_total)} • "
                    f"identificado por ID de link/colaboradora {brl(identified_people)} • "
                    f"diferença ainda não atribuída {brl(not_attributed)}. "
                    "O BI NÃO distribui essa diferença artificialmente entre as colaboradoras."
                )

            st.subheader("Carrinhos por colaboradora")
            chart = px.bar(
                prod_summary,
                x="Colaboradora",
                y="Carrinhos",
                text="Carrinhos",
            )
            chart.update_layout(height=390, xaxis_title="", yaxis_title="Carrinhos/links")
            st.plotly_chart(chart, use_container_width=True)

            st.subheader("Clientes e carrinhos por colaboradora")
            st.caption(
                "Use as abas abaixo para ver todos os clientes trabalhados, somente os recuperados "
                "ou somente os que continuam pendentes."
            )

            def build_prod_detail(frame: pd.DataFrame) -> pd.DataFrame:
                cols = [
                    c for c in [
                        "Data", "Data referência", "Mês criação", "Mês pagamento", "Colaboradora", "Cliente", "Condomínio", "ID", "Link ID",
                        "Valor_num", "Situação reconciliada", "Classificação taxa",
                        "Data_pagamento", "Valor_recuperado"
                    ] if c in frame.columns
                ]
                sort_col = "Data referência" if "Data referência" in frame.columns else "Data"
                detail_df = frame[cols].sort_values(sort_col, ascending=False).copy()
                rename = {
                    "Data": "Data do carrinho",
                    "Data referência": "Data de referência do período",
                    "ID": "ID do carrinho",
                    "Link ID": "ID do link",
                    "Situação reconciliada": "Status",
                    "Classificação taxa": "Taxa de cobrança",
                    "Data_pagamento": "Data do pagamento",
                }
                detail_df = detail_df.rename(columns=rename)
                if "Valor_num" in detail_df.columns:
                    detail_df["Valor do carrinho"] = detail_df["Valor_num"].map(brl)
                    detail_df = detail_df.drop(columns=["Valor_num"])
                if "Valor_recuperado" in detail_df.columns:
                    detail_df["Valor recuperado"] = detail_df["Valor_recuperado"].map(brl)
                    detail_df = detail_df.drop(columns=["Valor_recuperado"])
                return detail_df

            all_tab, recovered_tab, pending_tab = st.tabs([
                "Todos", "Recuperados", "Pendentes"
            ])
            with all_tab:
                st.dataframe(build_prod_detail(prod), use_container_width=True, hide_index=True)
            with recovered_tab:
                recovered_detail = prod[prod["Situação reconciliada"].eq("Pago")]
                st.dataframe(
                    build_prod_detail(recovered_detail), use_container_width=True, hide_index=True
                )
            with pending_tab:
                pending_detail = prod[prod["Situação reconciliada"].eq("Pendente")]
                st.dataframe(
                    build_prod_detail(pending_detail), use_container_width=True, hide_index=True
                )

            st.subheader("Evolução diária")
            daily = (
                prod.groupby(["Dia", "Colaboradora"])
                .size()
                .reset_index(name="Carrinhos")
            )
            daily_chart = px.line(
                daily, x="Dia", y="Carrinhos", color="Colaboradora", markers=True
            )
            daily_chart.update_layout(height=420, xaxis_title="", yaxis_title="Carrinhos/links")
            st.plotly_chart(daily_chart, use_container_width=True)

if page == "Devedores":
    st.subheader("Pessoas que ainda precisam ser cobradas")
    st.caption(
        "São considerados apenas links pendentes de Fernanda, Camilli, Vitoria, Kawany, Lorrany e Thais. "
        "Links encontrados como pagos ou cancelados nos arquivos de transações são retirados."
)

if pending.empty:
    st.success("Nenhuma pendência encontrada nos arquivos carregados.")
else:
    d1, d2, d3 = st.columns(3)
    d1.metric("Links pendentes", len(pending))
    d2.metric("Valor em aberto", brl(pending["Valor_num"].sum()))
    d3.metric("Com mais de 30 dias", int((pending["Dias em aberto"] > 30).sum()))

    search = st.text_input("Buscar cliente")
    filtered = pending.copy()
    if search:
        filtered = filtered[
            filtered.get("Nome", "").astype(str).str.contains(search, case=False, na=False)
        ]

    bands = st.multiselect(
        "Faixa de atraso",
        ["0–7", "8–15", "16–30", "31–60", "60+"],
        default=["0–7", "8–15", "16–30", "31–60", "60+"],
    )
    bucket = pd.cut(
        filtered["Dias em aberto"],
        bins=[-1, 7, 15, 30, 60, 100_000],
        labels=["0–7", "8–15", "16–30", "31–60", "60+"],
    )
    filtered = filtered[bucket.isin(bands)]

    summary_tab, detail_tab = st.tabs(["Resumo por pessoa", "Detalhe por link"])
    with summary_tab:
        if "Nome" in filtered.columns:
            person = (
                filtered.groupby("Nome", dropna=False)
                .agg(
                    Pendências=("Link ID", "count"),
                    Valor_em_aberto=("Valor_num", "sum"),
                    Pendência_mais_recente=("Data", "max"),
                    Maior_atraso=("Dias em aberto", "max"),
                )
                .reset_index()
                .sort_values("Pendência_mais_recente", ascending=False)
            )
            person["Valor em aberto"] = person["Valor_em_aberto"].map(brl)
            person = person.rename(
                columns={
                    "Nome": "Cliente",
                    "Pendência_mais_recente": "Pendência mais recente",
                    "Maior_atraso": "Maior atraso (dias)",
                }
            )
            st.dataframe(
                person[
                    [
                        "Cliente",
                        "Pendências",
                        "Valor em aberto",
                        "Pendência mais recente",
                        "Maior atraso (dias)",
                    ]
                ],
                use_container_width=True,
                hide_index=True,
            )
    with detail_tab:
        columns = [
            column
            for column in ["ID", "Nome", "Valor", "Usuário", "Data", "Dias em aberto"]
            if column in filtered.columns
        ]
        st.dataframe(
            filtered[columns].sort_values("Data", ascending=False),
            use_container_width=True,
            hide_index=True,
        )

if page == "Condomínios":
    st.subheader("Recuperações por condomínio")
    if "PDX" not in recovered.columns:
        st.info("O campo de condomínio não foi encontrado.")
    else:
        condominium = (
            recovered.groupby("PDX", dropna=False)
            .agg(
                Pagamentos=("ID", "count"),
                Clientes=("Nome Cliente", "nunique"),
                Recuperado=("Valor", "sum"),
            )
            .reset_index()
            .sort_values("Recuperado", ascending=False)
        )
        selected_condominiums = st.multiselect(
            "Condomínio",
            condominium["PDX"].dropna().astype(str).tolist(),
        )
        if selected_condominiums:
            condominium = condominium[
                condominium["PDX"].astype(str).isin(selected_condominiums)
            ]
        chart = px.bar(
            condominium.head(20),
            x="Recuperado",
            y="PDX",
            orientation="h",
            title="Top 20 por valor recuperado",
        )
        chart.update_layout(yaxis={"categoryorder": "total ascending"}, height=620)
        st.plotly_chart(chart, use_container_width=True)
        display = condominium.copy()
        display["Recuperado"] = display["Recuperado"].map(brl)
        st.dataframe(display, use_container_width=True, hide_index=True)

elif page == "Qualidade dos dados":
    st.subheader("Qualidade e cobertura")
    q1, q2, q3, q4 = st.columns(4)
    q1.metric("Meses completos", len(months_available.intersection(set(month_codes))))
    q2.metric("Recuperações válidas", len(recovered))
    q3.metric("Registros internos excluídos", len(internal_recovery_rows))
    q4.metric(
        "Taxa não informada",
        int(recovered["Taxa"].eq("Não informado").sum()),
    )

    coverage = monthly[["Período", "Arquivo detalhado", "Pagamentos", "Recuperado total"]].copy()
    coverage["Recuperado total"] = coverage["Recuperado total"].map(
        lambda v: "Não importado" if pd.isna(v) else brl(float(v))
    )
    st.dataframe(coverage, use_container_width=True, hide_index=True)

    st.info(
        "O mês atual é conferido pela linha Cobranças do relatório Vendas Consolidadas. "
        "Para identificar os carrinhos e atribuí-los às colaboradoras, o BI usa registros "
        "Pagamento efetuada (cobrança) que possuem ID de link de pagamento."
    )

    if transaction_failures or link_failures or consolidated_failures:
        st.warning(
            "Alguns arquivos não puderam ser lidos: "
            + ", ".join(transaction_failures + link_failures + consolidated_failures)
        )

elif page == "Transações":
    st.subheader("Base de transações de cobrança — 2026")
    relevant_mask = type_normalized.str.contains("cobran", na=False)
    financial_events = transactions[relevant_mask].copy()
    types = sorted(financial_events["Tipo"].dropna().astype(str).unique())
    selected_types = st.multiselect("Tipo", types)
    if selected_types:
        financial_events = financial_events[financial_events["Tipo"].isin(selected_types)]
    columns = [
        column
        for column in [
            "Data e hora",
            "PDX",
            "Nome Cliente",
            "Tipo",
            "Total",
            "Forma pagamento",
            "ID link de pagamento",
            "Possui taxa de cobrança",
            "_fonte",
        ]
        if column in financial_events.columns
    ]
    st.dataframe(
        financial_events[columns]
        .sort_values("Data e hora", ascending=False)
        .head(5000),
        use_container_width=True,
        hide_index=True,
    )
    st.caption("A tela exibe no máximo 5.000 linhas para manter o BI rápido.")

elif page == "Acessos":
    # Área administrativa exclusiva da Fernanda.
    if st.session_state.get("login_user") != "fernanda":
        st.error("Você não tem permissão para visualizar esta área.")
        st.stop()

    st.subheader("Histórico de acessos")
    st.caption("Registra apenas logins bem-sucedidos. Senhas nunca são armazenadas neste histórico.")
    access = _load_access_log()
    if access.empty:
        st.info("Nenhum acesso registrado ainda.")
    else:
        access["_dt"] = pd.to_datetime(access["timestamp"], errors="coerce")
        summary = (
            access.groupby(["usuario", "nome"], dropna=False)
            .agg(
                Acessos=("timestamp", "count"),
                Primeiro_acesso=("_dt", "min"),
                Ultimo_acesso=("_dt", "max"),
            )
            .reset_index()
            .sort_values("Ultimo_acesso", ascending=False)
        )
        summary["Primeiro acesso"] = summary["Primeiro_acesso"].dt.strftime("%d/%m/%Y %H:%M:%S")
        summary["Último acesso"] = summary["Ultimo_acesso"].dt.strftime("%d/%m/%Y %H:%M:%S")
        summary = summary[["nome", "Acessos", "Primeiro acesso", "Último acesso"]].rename(columns={"nome": "Nome"})
        st.markdown("#### Resumo por usuário")
        st.dataframe(summary, use_container_width=True, hide_index=True)

        st.markdown("#### Histórico detalhado")
        detailed = access.sort_values("_dt", ascending=False)[["nome", "data", "hora"]].rename(
            columns={"nome": "Nome", "data": "Data", "hora": "Hora"}
        )
        st.dataframe(detailed, use_container_width=True, hide_index=True)

st.divider()
st.caption(
    "Market4U BI 2026 • período iniciado em 01/01/2026 • "
    "novas exportações da pasta Downloads podem ser lidas automaticamente"
)
