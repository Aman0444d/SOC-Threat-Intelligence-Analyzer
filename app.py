import streamlit as st
import requests
from datetime import datetime
history = []

st.set_page_config(page_title="SOC Analyzer", page_icon="🔐")

st.title("🔐 SOC IP Analyzer")
st.write("Check IP reputation using VirusTotal")

ip = st.text_input("Enter IP Address")

if st.button("Analyze"):
    scan_time = datetime.now()

    if ip == "":
        st.warning("⚠️ Please enter an IP")

    else:
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            abuse_url = "https://api.abuseipdb.com/api/v2/check"

            headers = {
                "x-apikey": "Your VTAPI key"
            }
            abuse_headers = {
    "Key": "Your ABDB Api key",
    "Accept": "application/json"
}

            params = {
    "ipAddress": ip,
    "maxAgeInDays": 90
}

            response = requests.get(url, headers=headers)
            abuse_response = requests.get(
            abuse_url,
             headers=abuse_headers,
             params=params
                     )

            abuse_data = abuse_response.json()
            data = response.json()

            stats = data["data"]["attributes"]["last_analysis_stats"]

            malicious = stats["malicious"]
            suspicious = stats["suspicious"]
            harmless = stats["harmless"]
            abuse_score = abuse_data["data"]["abuseConfidenceScore"]
            country = data["data"]["attributes"].get("country", "Unknown")
            owner = data["data"]["attributes"].get("as_owner", "Unknown")
            st.write(f"🚨 AbuseIPDB Score: {abuse_score}%")

            st.subheader("🔍 Analysis Result")

            st.write(f"🕒 Scan Time: {scan_time}")
            st.write(f"🌍 Country: {country}")
            st.write(f"🏢 Organization: {owner}")

            # 🔥 Dashboard metrics
            col1, col2, col3 = st.columns(3)

            col1.metric("🔴 Malicious", malicious)
            col2.metric("🟡 Suspicious", suspicious)
            col3.metric("🟢 Harmless", harmless)

            # 🔥 Threat level system
            if malicious >= 5 or abuse_score >= 50:
                threat_level = "🔴 HIGH RISK"
            elif suspicious > 0:
                threat_level = "🟠 MEDIUM RISK"
            else:
                threat_level = "🟢 LOW RISK"

            # 🔥 Show threat level
            st.write(f"Threat Level: {threat_level}")
            st.progress(min(malicious / 10, 1.0))

            history.append({
    "IP": ip,
    "Threat": threat_level
})

            # 🔥 Report
            report = f"""
SOC Threat Intelligence Report

IP Address: {ip}
Scan Time: {scan_time}

Malicious: {malicious}
Suspicious: {suspicious}
Harmless: {harmless}

Threat Level: {threat_level}
"""

            # 🔥 Final verdict
            if malicious > 0:
                st.error("⚠️ MALICIOUS IP")
            elif suspicious > 0:
                st.warning("⚠️ SUSPICIOUS IP")
            else:
                st.success("✅ SAFE IP")

            # 🔥 Download button
            st.download_button(
                label="📥 Download Report",
                data=report,
                file_name=f"report_{ip}.txt",
                mime="text/plain"
            )
                    
            st.subheader("📜 Scan History")

            st.write(history)
              
        except Exception as e:
            st.error(f"❌ Error fetching data: {e}")    