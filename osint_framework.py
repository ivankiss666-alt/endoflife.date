import io
import re
import zipfile

import pandas as pd
import requests
import streamlit as st
import vt

# =================================================================
# CONFIGURACIÓN DE LA INTERFAZ
# =================================================================
st.set_page_config(page_title="Professional OSINT Framework", layout="wide")

st.title("🕵️‍♂️ Advanced Threat Intelligence Framework")
st.markdown(
    """
Este framework integra **VirusTotal Intelligence** y **Have I Been Pwned** para localizar
y extraer credenciales filtradas mediante Regex.
*Nota: Requiere API Keys válidas (VT Enterprise para descargas).*
"""
)

# --- SIDEBAR: GESTIÓN DE CREDENCIALES ---
st.sidebar.header("🔑 API Configuration")
vt_api_key = st.sidebar.text_input(
    "VirusTotal Enterprise Key",
    type="password",
    help="Necesaria para buscar contenido y descargar archivos.",
)
hibp_api_key = st.sidebar.text_input(
    "Have I Been Pwned Key",
    type="password",
    help="Necesaria para consultar brechas históricas.",
)


# =================================================================
# MOTOR LÓGICO: EXTRACCIÓN Y ANÁLISIS
# =================================================================
def regex_credential_extractor(text):
    """
    Motor Regex para identificar patrones de credenciales en texto plano.
    """
    pattern = re.compile(
        r"(?:URL|Host|Site):\s*(?P<URL>https?://[^\s]+)\s*"
        r"(?:User|Login|Username|Email):\s*(?P<Usuario>[^\s]+)\s*"
        r"(?:Pass|Password):\s*(?P<Password>[^\s]+)",
        re.IGNORECASE | re.MULTILINE,
    )
    return [m.groupdict() for m in pattern.finditer(text)]


def process_file_content(content, filename):
    """
    Procesa el contenido de un archivo, manejando ZIPs o archivos de texto.
    """
    del filename
    extracted_data = []
    # Si es un ZIP (formato común de logs de malware)
    if zipfile.is_zipfile(io.BytesIO(content)):
        with zipfile.ZipFile(io.BytesIO(content)) as z:
            for name in z.namelist():
                # Buscamos archivos de texto que suelen contener passwords
                if name.endswith(".txt") and any(
                    x in name.lower() for x in ["pass", "log", "user"]
                ):
                    with z.open(name) as f:
                        text = f.read().decode("utf-8", errors="ignore")
                        extracted_data.extend(regex_credential_extractor(text))
    else:
        # Si es un archivo de texto plano
        text = content.decode("utf-8", errors="ignore")
        extracted_data.extend(regex_credential_extractor(text))

    return extracted_data


def query_hibp(email, api_key):
    """Consulta brechas históricas en HIBP."""
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {"hibp-api-key": api_key, "user-agent": "OSINT-Framework"}
    try:
        response = requests.get(url, headers=headers, timeout=30)
        return response.json() if response.status_code == 200 else []
    except requests.RequestException:
        return []


# =================================================================
# INTERFAZ DE USUARIO Y EJECUCIÓN
# =================================================================
target = st.text_input(
    "🎯 Identificador Objetivo (Email, Usuario o Dominio):",
    "cinthiatun98@gmail.com",
)

col1, col2 = st.columns(2)

with col1:
    if st.button("🔍 Escanear VirusTotal (Real)"):
        if not vt_api_key:
            st.error("❌ Se requiere API Key de VT Enterprise.")
        else:
            with st.spinner("Buscando logs de malware en VirusTotal..."):
                try:
                    client = vt.Client(vt_api_key)
                    # Dork para buscar el target dentro de archivos de malware
                    query = f'content:"{target}" AND (tag:stealer OR filename:passwords)'
                    files = client.iterate_objects("files", filter=query, limit=10)

                    all_results = []
                    for file_obj in files:
                        # Descarga real del archivo
                        file_data = client.get_object(
                            f"/files/{file_obj.id}/download"
                        ).read()
                        extracted = process_file_content(file_data, file_obj.id)
                        all_results.extend(extracted)

                    client.close()

                    if all_results:
                        df_vt = pd.DataFrame(all_results)
                        # Filtrar para asegurar que el target esté presente
                        df_vt = df_vt[
                            df_vt.apply(
                                lambda r: target.lower() in str(r).lower(),
                                axis=1,
                            )
                        ]

                        st.session_state["vt_data"] = df_vt
                        st.success(f"✅ Encontrados {len(df_vt)} registros en VT.")
                        st.dataframe(df_vt)
                    else:
                        st.warning("No se encontraron credenciales en logs de malware.")
                except Exception as e:  # noqa: BLE001
                    st.error(f"Error en VT: {e}")

with col2:
    if st.button("🛡️ Consultar Brechas HIBP"):
        if not hibp_api_key:
            st.error("❌ Se requiere API Key de HIBP.")
        else:
            with st.spinner("Consultando HIBP..."):
                breaches = query_hibp(target, hibp_api_key)
                if breaches:
                    st.warning(
                        f"⚠️ El objetivo aparece en {len(breaches)} brechas públicas."
                    )
                    df_hibp = pd.DataFrame(breaches)[
                        ["Name", "Domain", "BreachDate", "PwnCount"]
                    ]
                    st.dataframe(df_hibp)
                    st.session_state["hibp_data"] = df_hibp
                else:
                    st.success("✅ No se detectaron brechas públicas.")

# =================================================================
# EXPORTACIÓN DE RESULTADOS
# =================================================================
st.divider()
st.subheader("📦 Exportar Inteligencia")

if "vt_data" in st.session_state and not st.session_state["vt_data"].empty:
    csv = st.session_state["vt_data"].to_csv(index=False).encode("utf-8-sig")
    st.download_button(
        label="⬇️ Descargar Reporte CSV (Credenciales)",
        data=csv,
        file_name=f"REPORT_OSINT_{target}.csv",
        mime="text/csv",
    )
