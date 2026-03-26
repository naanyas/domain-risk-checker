"""
Domain Sender Approval - Streamlit App
=======================================
User view: Enter domains, run analysis, download results
Admin view: Configure scoring weights and thresholds
"""

import streamlit as st
import pandas as pd
import json
import copy
import os
from datetime import datetime
from io import BytesIO

# Import the analysis engine
from analyzer import analyze_domain, DomainApprovalResult, calculate_score, ANALYZER_VERSION
from config import load_config, save_config, DEFAULT_CONFIG

# Page config
st.set_page_config(
    page_title="Domain Sender Approval",
    page_icon="📧",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .stAlert {margin-top: 1rem;}
    .result-approve {background-color: #d4edda; padding: 10px; border-radius: 5px; margin: 5px 0;}
    .result-deny {background-color: #f8d7da; padding: 10px; border-radius: 5px; margin: 5px 0;}
    .metric-card {background-color: #f8f9fa; padding: 20px; border-radius: 10px; text-align: center;}
    .big-number {font-size: 48px; font-weight: bold;}
    .admin-section {background-color: #fff3cd; padding: 15px; border-radius: 10px; margin: 10px 0;}
    
    /* Text wrapping for dataframes */
    .stDataFrame div[data-testid="stDataFrameResizable"] {
        width: 100% !important;
    }
    .stDataFrame [data-testid="stDataFrameResizable"] div {
        white-space: pre-wrap !important;
        word-wrap: break-word !important;
    }
    div[data-testid="stDataFrame"] div[role="gridcell"] {
        white-space: pre-wrap !important;
        word-wrap: break-word !important;
        overflow-wrap: break-word !important;
        line-height: 1.4 !important;
    }
    /* Make summary column wider and wrap */
    .dataframe td, .dataframe th {
        white-space: pre-wrap !important;
        word-wrap: break-word !important;
        max-width: 500px !important;
    }
</style>
""", unsafe_allow_html=True)


def init_session_state():
    """Initialize session state variables."""
    if 'config' not in st.session_state:
        st.session_state.config = load_config()
    if 'results' not in st.session_state:
        st.session_state.results = None
    if 'admin_authenticated' not in st.session_state:
        st.session_state.admin_authenticated = False


def parse_domains(text: str) -> list:
    """Parse domain input text into list of domains."""
    domains = []
    for line in text.replace(',', '\n').replace(';', '\n').splitlines():
        d = line.strip().lower()
        if not d or d.startswith('#'):
            continue
        # Clean URLs
        if '://' in d:
            from urllib.parse import urlparse
            d = urlparse(d).netloc or urlparse(d).path
        d = d.strip('/').strip('.')
        # Strip common mail subdomains — we want to analyze the root domain
        _MAIL_PREFIXES = ("mail.", "mailing.", "webmail.", "smtp.", "imap.", "pop.", "mx.", "email.",
                          "mailer.", "newsletter.", "news.", "notify.", "notifications.",
                          "bounce.", "sender.", "send.", "em.", "mg.",  # Mailgun, SendGrid
                          "return.", "reply.")
        for pfx in _MAIL_PREFIXES:
            if d.startswith(pfx):
                d = d[len(pfx):]
                break
        if d and '.' in d:
            domains.append(d)
    return domains  # Return all entries in input order, including duplicates


def run_analysis(domains: list, config: dict, progress_callback=None) -> list:
    """Run domain analysis with current config."""
    results = []
    for i, domain in enumerate(domains):
        if progress_callback:
            progress_callback(i, len(domains), domain)
        try:
            result = analyze_domain(
                domain=domain,
                timeout=config.get('timeout', 10.0),
                check_rdap=config.get('check_rdap', True),
                weights=config.get('weights', {}),
                threshold=config.get('approve_threshold', 50),
                full_config=config,
            )
            results.append(result)
        except Exception as e:
            # Create error result
            results.append({
                'domain': domain,
                'risk_score': 100,
                'recommendation': 'DENY',
                'summary': f'Analysis failed: {str(e)[:100]}',
                'risk_level': 'ERROR'
            })
    return results


def results_to_dataframe(results: list) -> pd.DataFrame:
    """Convert results to DataFrame."""
    if not results:
        return pd.DataFrame()
    
    # Primary columns first
    primary_cols = ['domain', 'risk_score', 'recommendation', 'summary']
    
    # Convert to list of dicts if needed
    if hasattr(results[0], '__dict__'):
        data = [vars(r) for r in results]
    else:
        data = results
    
    df = pd.DataFrame(data)
    
    # Reorder columns
    cols = primary_cols + [c for c in df.columns if c not in primary_cols]
    df = df[[c for c in cols if c in df.columns]]
    
    return df


def user_view():
    """Main user interface for domain analysis."""
    st.title("📧 Domain Sender Approval")
    st.markdown("Analyze email sender domains for risk assessment and approval recommendations.")
    
    # Sidebar info
    with st.sidebar:
        st.header("ℹ️ How to Use")
        st.markdown("""
        1. **Paste domains** in the text box (one per line)
        2. Click **Analyze Domains**
        3. Review results and **download CSV**
        
        ---
        
        **Scoring:**
        - Score < {threshold}: ✅ APPROVE
        - Score ≥ {threshold}: 🚫 DENY
        """.format(threshold=st.session_state.config.get('approve_threshold', 50)))
        
        st.markdown("---")
        
        # Options
        st.subheader("⚙️ Options")
        check_rdap = st.checkbox("Check domain age (RDAP)", value=True, 
                                  help="Lookup domain registration date - adds ~1s per domain")
        
        st.session_state.config['check_rdap'] = check_rdap
    
    # Main input area
    col1, col2 = st.columns([2, 1])
    
    with col1:
        domains_input = st.text_area(
            "Enter domains to analyze (one per line)",
            height=200,
            placeholder="example.com\nanotherdomain.com\nhttps://somesite.org/path",
            help="Paste domains, URLs, or a list from a spreadsheet"
        )
    
    with col2:
        st.markdown("### 📁 Or upload a file")
        uploaded_file = st.file_uploader(
            "CSV or TXT file",
            type=['csv', 'txt'],
            help="First column should contain domains"
        )
        
        if uploaded_file:
            try:
                if uploaded_file.name.endswith('.csv'):
                    df = pd.read_csv(uploaded_file)
                    file_domains = df.iloc[:, 0].astype(str).tolist()
                else:
                    file_domains = uploaded_file.read().decode('utf-8').splitlines()
                domains_input = '\n'.join(file_domains)
                st.success(f"Loaded {len(file_domains)} lines from file")
            except Exception as e:
                st.error(f"Error reading file: {e}")
    
    # Parse domains
    domains = parse_domains(domains_input) if domains_input else []
    
    if domains:
        st.info(f"**{len(domains)} domains** ready for analysis")
    
    # Analyze button
    col1, col2, col3 = st.columns([1, 1, 2])
    with col1:
        analyze_clicked = st.button("🔍 Analyze Domains", type="primary", disabled=len(domains) == 0)
    
    # Run analysis
    if analyze_clicked and domains:
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        def update_progress(i, total, domain):
            progress_bar.progress((i + 1) / total)
            status_text.text(f"Analyzing {i+1}/{total}: {domain}")
        
        with st.spinner("Running analysis..."):
            results = run_analysis(domains, st.session_state.config, update_progress)
            st.session_state.results = results
        
        progress_bar.empty()
        status_text.empty()
        st.success(f"✅ Analysis complete! Analyzed {len(results)} domains.")
    
    # Display results
    if st.session_state.results:
        display_results(st.session_state.results)


def display_results(results: list):
    """Display analysis results."""
    st.markdown("---")
    st.header("📊 Results")
    
    df = results_to_dataframe(results)
    
    # Summary metrics
    approve_count = len(df[df['recommendation'] == 'APPROVE'])
    deny_count = len(df[df['recommendation'] == 'DENY'])
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Analyzed", len(df))
    with col2:
        st.metric("✅ Approved", approve_count)
    with col3:
        st.metric("🚫 Denied", deny_count)
    with col4:
        avg_score = df['risk_score'].mean()
        st.metric("Avg Risk Score", f"{avg_score:.1f}")
    
    # Tabs for different views
    tab1, tab2, tab3 = st.tabs(["📋 Summary View", "📊 Full Details", "⬇️ Download"])
    
    with tab1:
        # Summary table with color coding — clean view: domain, score, result, threats, summary
        summary_df = df[['domain', 'risk_score', 'recommendation', 'summary']].copy()
        
        # v7.3.1: Build threat indicator column showing kit files and malicious links
        def _safe_str(val, default=''):
            """Return string value, converting NaN/None to default."""
            if pd.isna(val) if isinstance(val, float) else val is None:
                return default
            return str(val)

        def _build_threat_indicator(row):
            parts = []
            # Kit filename
            kit_fn = _safe_str(row.get('phishing_kit_filename'))
            if kit_fn:
                parts.append(f"🎣 {kit_fn}")
            # Phishing paths
            phish_paths = _safe_str(row.get('phishing_paths_found'))
            if phish_paths:
                paths = phish_paths.split(';')[:2]
                parts.append(f"📂 {', '.join(paths)}")
            # Malicious script
            if row.get('hacklink_malicious_script'):
                conf = _safe_str(row.get('hacklink_malicious_script_confidence'))
                parts.append(f"💀 Script ({conf})")
            # Hidden injection
            if row.get('hacklink_hidden_injection') and row.get('hacklink_hidden_injection_confidence') == 'HIGH':
                parts.append("💉 Hidden inject")
            # MX hijack
            if row.get('mx_provider_mismatch'):
                conf = _safe_str(row.get('mx_hijack_confidence'))
                ghost = _safe_str(row.get('mx_ghost_provider'))
                parts.append(f"🔓 MX hijack ({ghost}, {conf})")
            # Subdomain delegation abuse
            if row.get('subdomain_infra_divergent'):
                conf = _safe_str(row.get('subdomain_divergence_confidence'))
                parts.append(f"🔀 Subdomain divergence ({conf})")
            # CT reactivation (aged domain purchase)
            if row.get('ct_reactivated'):
                gap = row.get('ct_gap_months', 0)
                if pd.isna(gap) if isinstance(gap, float) else gap is None:
                    gap = 0
                parts.append(f"📜 CT reactivation ({gap}mo gap)")
            # v7.3.1: OAuth consent phishing
            if row.get('has_oauth_phish'):
                parts.append("🔑 OAuth phish")
            # v7.3.1: Homoglyph / IDN spoofing
            if row.get('is_homoglyph_domain'):
                target = _safe_str(row.get('homoglyph_target'))
                parts.append(f"🔤 Homoglyph ({target})")
            # v7.3.1: Quishing profile
            if row.get('quishing_profile'):
                parts.append("📱 Quishing")
            # v7.3.1: CDN tunnel abuse
            if row.get('cdn_tunnel_suspect'):
                cdn = _safe_str(row.get('cdn_provider'))
                parts.append(f"☁️ CDN tunnel ({cdn})")
            # v7.7: Domain category risk
            if row.get('domain_category'):
                _ct = _safe_str(row.get('domain_category_risk_tier'))
                _cl = _safe_str(row.get('domain_category_label'))
                _ce = {'HIGH': '🔴', 'ELEVATED': '🟠', 'MODERATE': '🟡'}.get(_ct, '')
                parts.append(f'{_ce} {_cl}')
            # v7.7.1: VT-flagged external domains on page
            _ext_mal = row.get('vt_external_malicious_count', 0)
            if pd.notna(_ext_mal) and int(_ext_mal) > 0:
                _ext_doms = _safe_str(row.get('vt_external_malicious_domains'))
                parts.append(f'🛡️ {int(_ext_mal)} malicious ext ({_ext_doms})')
            # Spam links
            spam_ct = row.get('hacklink_spam_link_count', 0)
            if pd.isna(spam_ct) if isinstance(spam_ct, float) else spam_ct is None:
                spam_ct = 0
            if spam_ct > 0:
                parts.append(f"🔗 {int(spam_ct)} spam links")
            # Phishing kit composite
            if row.get('phishing_kit_detected') and not kit_fn:
                parts.append("🎣 Kit detected")
            # Exfil
            if row.get('has_exfil_drop_script'):
                parts.append("📡 Exfil")
            # v7.5: Client-side harvest combo
            if row.get('has_harvest_combo'):
                parts.append("🕸️ Harvest combo")
            # v8.0: Mail-only domain indicator
            if row.get('is_mail_only_domain'):
                mx_type = _safe_str(row.get('mail_only_mx_provider_type') or row.get('mx_provider_type'))
                parts.insert(0, f"📧 Mail-only ({mx_type})" if mx_type else "📧 Mail-only")
            # v8.1: No-resolve domain indicator
            if row.get('is_no_resolve_domain'):
                parts.insert(0, "🔇 No-resolve (no A, no MX)")
            # v8.1.1: Cannot receive mail indicator
            if row.get('cannot_receive_mail'):
                parts.insert(1 if row.get('is_no_resolve_domain') else 0, "📭 Cannot receive mail")
            # v8.1.1: No email auth indicator (only for no-resolve domains)
            if row.get('is_no_resolve_domain'):
                _has_spf = row.get('spf_exists', False)
                _has_dkim = row.get('dkim_exists', False)
                _has_dmarc = row.get('dmarc_exists', False)
                if not _has_spf and not _has_dkim and not _has_dmarc:
                    parts.append("🚫 No email auth")
                elif row.get('registration_opaque'):
                    parts.append("🔒 WHOIS opaque")
            return ' · '.join(parts) if parts else ''
        
        # Build from full df (has all fields), then attach to summary_df
        threat_indicators = df.apply(_build_threat_indicator, axis=1)
        summary_df.insert(3, 'threats', threat_indicators)
        
        def color_recommendation(val):
            if val == 'APPROVE':
                return 'background-color: #d4edda; color: #155724'
            else:
                return 'background-color: #f8d7da; color: #721c24'
        
        def color_score(val):
            if val <= 30:
                return 'background-color: #d4edda'
            elif val < 50:
                return 'background-color: #fff3cd'
            else:
                return 'background-color: #f8d7da'
        
        styled_df = summary_df.style.applymap(
            color_recommendation, subset=['recommendation']
        ).applymap(
            color_score, subset=['risk_score']
        )
        
        # Column configuration for better display
        column_config = {
            "domain": st.column_config.TextColumn("Domain", width="medium"),
            "risk_score": st.column_config.NumberColumn("Score", width="small"),
            "recommendation": st.column_config.TextColumn("Result", width="small"),
            "threats": st.column_config.TextColumn("Threats", width="medium"),
            "summary": st.column_config.TextColumn("Summary", width="large"),
        }
        
        st.dataframe(
            styled_df, 
            use_container_width=True, 
            height=400,
            column_config=column_config
        )
        

    
    with tab2:
        # Full details table with column config
        full_column_config = {
            "domain": st.column_config.TextColumn("Domain", width="medium"),
            "risk_score": st.column_config.NumberColumn("Score", width="small"),
            "recommendation": st.column_config.TextColumn("Result", width="small"),
            "high_risk_phish_infra": st.column_config.CheckboxColumn("🚨 Phish Infra", width="small"),
            "phishing_kit_detected": st.column_config.CheckboxColumn("🎣 Kit", width="small"),
            "has_harvest_combo": st.column_config.CheckboxColumn("🕸️ Harvest", width="small"),
            "vt_malicious_count": st.column_config.NumberColumn("🛡️ VT Mal", width="small"),
            "hacklink_detected": st.column_config.CheckboxColumn("🕷️ Hacklink", width="small"),
            "hacklink_campaign_profile": st.column_config.CheckboxColumn("🕸️ Hacklink Profile", width="small"),
            "hacklink_malicious_script": st.column_config.CheckboxColumn("💀 Mal Script", width="small"),
            "hacklink_hidden_injection": st.column_config.CheckboxColumn("💀 Hidden Inj", width="small"),
            "domain_transfer_lock_recent": st.column_config.CheckboxColumn("🔓 Lock Recent", width="small"),
            "is_empty_page": st.column_config.CheckboxColumn("📄 Empty", width="small"),
            "ct_log_count": st.column_config.NumberColumn("📜 CT Certs", width="small"),
            "ct_cert_tls_dead": st.column_config.CheckboxColumn("🔒 Cert Dead", width="small"),
            "mx_provider_mismatch": st.column_config.CheckboxColumn("🔓 MX Hijack", width="small"),
            "subdomain_infra_divergent": st.column_config.CheckboxColumn("🔀 Sub Diverge", width="small"),
            "ct_reactivated": st.column_config.CheckboxColumn("📜 CT React", width="small"),
            "has_oauth_phish": st.column_config.CheckboxColumn("🔑 OAuth", width="small"),
            "is_homoglyph_domain": st.column_config.CheckboxColumn("🔤 Homoglyph", width="small"),
            "quishing_profile": st.column_config.CheckboxColumn("📱 Quish", width="small"),
            "domain_category": st.column_config.TextColumn("Category", width="medium"),
            "domain_category_risk_tier": st.column_config.TextColumn("Cat. Risk", width="small"),
            "vt_external_malicious_count": st.column_config.NumberColumn("VT Ext Mal", width="small"),
            "vt_external_malicious_domains": st.column_config.TextColumn("VT Ext Domains", width="medium"),
            "cdn_tunnel_suspect": st.column_config.CheckboxColumn("☁️ CDN Tunnel", width="small"),
            "asn_display": st.column_config.TextColumn("ASN", width="medium"),
            "rules_triggered": st.column_config.TextColumn("Rules Fired", width="medium"),
            "summary": st.column_config.TextColumn("Summary", width="large"),
            "signals_triggered": st.column_config.TextColumn("Signals", width="medium"),
        }
        st.dataframe(df, use_container_width=True, height=400, column_config=full_column_config)
        
        # Column selector
        with st.expander("🔧 Select columns to display"):
            all_cols = df.columns.tolist()
            desired_defaults = ['domain', 'risk_score', 'recommendation', 'summary', 
                        'vt_malicious_count', 'hacklink_detected',
                        'hacklink_malicious_script', 'hacklink_hidden_injection',
                        'domain_transfer_lock_recent', 'mx_provider_mismatch',
                        'subdomain_infra_divergent', 'ct_reactivated',
                        'has_oauth_phish', 'is_homoglyph_domain',
                        'domain_category', 'domain_category_risk_tier',
                        'vt_external_malicious_count', 'vt_external_malicious_domains',
                        'quishing_profile', 'cdn_tunnel_suspect',
                        'asn_display', 'rules_triggered',
                        'spf_exists', 'dkim_exists', 'dmarc_exists', 'domain_age_days']
            safe_defaults = [c for c in desired_defaults if c in all_cols]
            selected_cols = st.multiselect(
                "Columns",
                all_cols,
                default=safe_defaults
            )
            if selected_cols:
                st.dataframe(df[selected_cols], use_container_width=True)
    
    with tab3:
        st.subheader("⬇️ Download Results")
        
        # CSV download
        csv_buffer = BytesIO()
        df.to_csv(csv_buffer, index=False)
        csv_buffer.seek(0)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        col1, col2 = st.columns(2)
        with col1:
            st.download_button(
                label="📥 Download Full CSV",
                data=csv_buffer.getvalue(),
                file_name=f"domain_approval_results_{timestamp}.csv",
                mime="text/csv"
            )
        
        with col2:
            # Summary CSV (just key columns)
            summary_csv = BytesIO()
            summary_cols = ['domain', 'risk_score', 'recommendation', 'score_breakdown', 
                           'phishing_kit_filename', 'hacklink_spam_links_found',
                           'mx_provider_mismatch', 'mx_ghost_provider', 'mx_hijack_confidence',
                           'subdomain_infra_divergent', 'subdomain_divergence_confidence',
                           'ct_reactivated', 'ct_gap_months',
                           'has_oauth_phish', 'is_homoglyph_domain', 'homoglyph_target',
                           'domain_category', 'domain_category_risk_tier',
                           'vt_external_malicious_count', 'vt_external_malicious_domains',
                           'quishing_profile', 'cdn_tunnel_suspect', 'cdn_provider',
                           'summary']
            summary_cols = [c for c in summary_cols if c in df.columns]
            df[summary_cols].to_csv(summary_csv, index=False)
            summary_csv.seek(0)
            st.download_button(
                label="📥 Download Summary CSV",
                data=summary_csv.getvalue(),
                file_name=f"domain_approval_summary_{timestamp}.csv",
                mime="text/csv"
            )
    
    # Detailed breakdown by domain
    st.markdown("---")
    st.subheader("🔍 Individual Domain Details")
    
    selected_domain = st.selectbox(
        "Select a domain to view details",
        df['domain'].tolist()
    )
    
    if selected_domain:
        domain_data = df[df['domain'] == selected_domain].iloc[0]
        
        col1, col2 = st.columns([1, 2])
        
        with col1:
            # Score display
            score = domain_data['risk_score']
            rec = domain_data['recommendation']
            
            if rec == 'APPROVE':
                st.success(f"### ✅ {rec}")
            else:
                st.error(f"### 🚫 {rec}")
            
            st.metric("Risk Score", score)
            
            if 'risk_level' in domain_data:
                st.metric("Risk Level", domain_data.get('risk_level', 'N/A'))
            
            # Pattern match indicator for specialists
            pattern = domain_data.get('pattern_match', '')
            if pattern:
                st.warning(f"**Pattern Match:** {pattern}")
            
            # High-risk phishing infrastructure indicator
            if domain_data.get('high_risk_phish_infra'):
                st.error(f"### 🚨 HIGH-RISK PHISHING INFRA")
                st.caption(domain_data.get('high_risk_phish_infra_reason', ''))
            
            # Phishing Kit detection banner (v7.3)
            if domain_data.get('phishing_kit_detected'):
                st.error("### 🎣 PHISHING KIT DETECTED")
                st.caption(domain_data.get('phishing_kit_reason', ''))
            elif domain_data.get('has_exfil_drop_script'):
                # Show exfil banner only if kit composite didn't already fire
                st.error("### 📡 EXFIL DROP SCRIPT")
                st.caption(domain_data.get('exfil_drop_details', '').replace(';', ' · '))
            
            # v7.5: Client-side harvest combo banner
            if domain_data.get('has_harvest_combo'):
                st.warning("### 🕸️ CLIENT-SIDE HARVEST COMBO")
                st.caption(domain_data.get('harvest_combo_reason', ''))
            
            # ASN display
            asn_display = domain_data.get('asn_display', '')
            if asn_display:
                is_render = 'render' in asn_display.lower()
                if is_render:
                    st.warning(f"**ASN:** 🔴 {asn_display}")
                else:
                    st.markdown(f"**ASN:** {asn_display}")
        
        with col2:
            st.markdown("**Summary:**")
            st.info(domain_data['summary'])
            
            # === SCORE BREAKDOWN ===
            breakdown_json = domain_data.get('score_breakdown', '')
            if breakdown_json:
                try:
                    breakdown = json.loads(breakdown_json)
                except (json.JSONDecodeError, TypeError):
                    breakdown = {}
            else:
                breakdown = {}
            
            if breakdown:
                # Split into penalties (>0), bonuses (<0), and neutral (0)
                penalties = {k: v for k, v in breakdown.items() if v > 0}
                bonuses = {k: v for k, v in breakdown.items() if v < 0}
                
                # Penalties sorted by impact (highest first)
                sorted_penalties = sorted(penalties.items(), key=lambda x: x[1], reverse=True)
                # Bonuses sorted by impact (most negative first)
                sorted_bonuses = sorted(bonuses.items(), key=lambda x: x[1])
                
                total_penalty = sum(penalties.values())
                total_bonus = sum(bonuses.values())
                
                # Rules labels lookup for display
                rules_labels_str = domain_data.get('rules_labels', '')
                rules_str = domain_data.get('rules_triggered', '')
                rule_label_map = {}
                if rules_str and rules_labels_str:
                    names = rules_str.split(';')
                    labels = rules_labels_str.split(';')
                    for i, name in enumerate(names):
                        if i < len(labels) and labels[i].strip():
                            rule_label_map[name.strip()] = labels[i].strip()
                
                if sorted_penalties:
                    st.markdown(f"**🔴 Penalties** ({total_penalty} pts)")
                    for item, pts in sorted_penalties:
                        is_rule = item.startswith("rule:")
                        display_name = item[5:] if is_rule else item
                        label = rule_label_map.get(display_name, '')
                        prefix = "📐" if is_rule else "⚡"
                        label_text = f" — {label}" if label else ""
                        st.markdown(f"&nbsp;&nbsp;{prefix} `{display_name}` **+{pts}**{label_text}")
                
                if sorted_bonuses:
                    st.markdown(f"**🟢 Bonuses** ({total_bonus} pts)")
                    for item, pts in sorted_bonuses:
                        is_rule = item.startswith("rule:")
                        display_name = item[5:] if is_rule else item
                        label = rule_label_map.get(display_name, '')
                        prefix = "📐" if is_rule else "⚡"
                        label_text = f" — {label}" if label else ""
                        st.markdown(f"&nbsp;&nbsp;{prefix} `{display_name}` **{pts}**{label_text}")
                
                st.caption(f"Net score: {total_penalty + total_bonus} → clamped to {domain_data['risk_score']}")
            
            # === ACTIVE SUPPRESSIONS / LEGITIMACY CONTEXT (v7.5.2+) ===
            # Shows the reviewer WHY certain signals were suppressed or not scored.
            _suppression_items = []
            
            # No-A-record recovery
            if domain_data.get('no_a_record'):
                dns_found = domain_data.get('dns_records_found', 'unknown')
                _suppression_items.append(
                    f"📡 **Mail-only domain (no A record)** — DNS records found: {dns_found}. "
                    f"Web-presence penalties suppressed: `no_https`, `no_ptr`, `missing_trust_signals`, `opaque_entity`."
                )
            
            # Dev/staging environment detection
            if domain_data.get('is_dev_staging'):
                confidence = domain_data.get('dev_staging_confidence', '')
                evidence = domain_data.get('dev_staging_evidence', '').replace(';', ', ')
                if confidence == "HIGH":
                    _suppression_items.append(
                        f"🧪 **Dev/staging environment detected (HIGH confidence, -15 pts)** — Evidence: {evidence}. "
                        f"Score reduced because dev/QA environments are not production abuse."
                    )
                elif confidence:
                    _suppression_items.append(
                        f"🧪 **Possible dev/staging environment ({confidence})** — Evidence: {evidence}. "
                        f"Informational only (no score impact at {confidence} confidence)."
                    )
            
            # NS inherited from parent (not lame delegation)
            if domain_data.get('ns_inherited_from_parent'):
                _suppression_items.append(
                    "🔗 **NS inherited from parent zone** — Subdomain has 0 NS records because it inherits from the parent domain (RFC 1034). "
                    "`lame_delegation` penalty suppressed."
                )
            
            # TLD variant analysis results — always show when data exists
            tld_summary = domain_data.get('tld_variant_summary', '')
            if tld_summary:
                variant_domain = domain_data.get('tld_variant_domain', '')
                variant_words = domain_data.get('tld_variant_content_words', 0)
                signup_words = domain_data.get('tld_variant_signup_content_words', 0)
                variant_has_email = domain_data.get('tld_variant_has_email_infra', False)
                detected = domain_data.get('tld_variant_detected', False)
                
                if detected:
                    # Variant WAS flagged — show the match that caused the penalty
                    _suppression_items.append(
                        f"⚠️ **TLD variant DETECTED: `{variant_domain}`** — "
                        f"Variant has {variant_words}w vs signup {signup_words}w | "
                        f"Variant email infra: {'Yes' if variant_has_email else 'No'}\n\n"
                        f"&nbsp;&nbsp;&nbsp;&nbsp;`{tld_summary}`"
                    )
                elif 'ALLOWLISTED' in tld_summary:
                    _suppression_items.append(
                        f"✅ **TLD variant allowlisted** — {tld_summary}"
                    )
                elif 'signup has DKIM' in tld_summary or 'signup stronger email' in tld_summary or 'signup DMARC' in tld_summary:
                    # Suppressed by reverse asymmetry
                    _suppression_items.append(
                        f"🔄 **TLD variant suppressed (reverse asymmetry)** — Signup domain has stronger email auth than the variant. "
                        f"Spoofers don't invest in DKIM/DMARC. `tld_variant_spoofing` penalty suppressed.\n\n"
                        f"&nbsp;&nbsp;&nbsp;&nbsp;`{tld_summary}`"
                    )
                elif 'CHECK ERROR' in tld_summary:
                    _suppression_items.append(
                        f"❗ **TLD variant check error** — {tld_summary}"
                    )
                else:
                    # Checked but below threshold — show what was evaluated
                    _suppression_items.append(
                        f"ℹ️ **TLD variant checked (not triggered)** — Variants evaluated but asymmetry below threshold.\n\n"
                        f"&nbsp;&nbsp;&nbsp;&nbsp;`{tld_summary}`"
                    )
            
            # Safe script suppression (inferred: malicious_script raw flag is true but not in breakdown)
            if domain_data.get('hacklink_malicious_script') and breakdown:
                if 'malicious_script' not in breakdown:
                    ext_scripts = domain_data.get('content_external_script_domains', '')
                    if ext_scripts:
                        _suppression_items.append(
                            f"🛡️ **Malicious script detection suppressed** — All external scripts from known safe providers: "
                            f"`{ext_scripts.replace(';', '`, `')}`. `malicious_script` penalty suppressed."
                        )
                    elif domain_data.get('is_parking_page'):
                        _suppression_items.append(
                            "🛡️ **Malicious script detection suppressed** — Parking page with known provider scripts. "
                            "`malicious_script` penalty suppressed."
                        )
            
            # Safe iframe suppression (inferred: iframe exists but suspicious_iframe not flagged)
            # We can't check this directly without raw HTML, but if the issues mention iframe suppression we'd show it
            
            # Transfer lock suppressed on parking page
            if domain_data.get('is_parking_page') and domain_data.get('domain_transfer_lock_recent'):
                if breakdown and 'transfer_lock_recent' not in breakdown and 'transfer_lock_with_risk' not in breakdown:
                    _suppression_items.append(
                        "🏪 **Transfer lock suppressed (parking page)** — Domain marketplaces routinely add transfer locks "
                        "to protect for-sale domains. `transfer_lock_recent` penalty suppressed."
                    )
            
            if _suppression_items:
                with st.expander(f"🔍 Legitimacy Checks & Context ({len(_suppression_items)})", expanded=True):
                    st.caption("Detection context: what was checked, what was suppressed, and why. Suppressed signals were detected but reduced based on legitimacy evidence.")
                    for item in _suppression_items:
                        st.markdown(item)
                        st.markdown("")
            
            # === ALL ISSUES LIST ===
            all_issues_raw = domain_data.get('all_issues_text', '')
            if all_issues_raw:
                issues_list = [i.strip() for i in all_issues_raw.split(';') if i.strip()]
                with st.expander(f"📋 All Issues ({len(issues_list)})", expanded=False):
                    for issue in issues_list:
                        # Parse points prefix: "[+25] ISSUE TEXT" or "[-5] ISSUE TEXT" or "[0] ISSUE TEXT"
                        pts_str = ""
                        display_text = issue
                        if issue.startswith("["):
                            bracket_end = issue.find("]")
                            if bracket_end > 0:
                                pts_str = issue[1:bracket_end]
                                display_text = issue[bracket_end+1:].strip()
                        
                        # Format points badge
                        try:
                            pts_val = int(pts_str)
                        except (ValueError, TypeError):
                            pts_val = 0
                        
                        if pts_val > 0:
                            pts_badge = f"**`+{pts_val}`**"
                        elif pts_val < 0:
                            pts_badge = f"**`{pts_val}`**"
                        else:
                            pts_badge = "`0`"
                        
                        # Icon based on issue type
                        if "🚨" in display_text:
                            st.markdown(f"- {pts_badge} {display_text}")
                        elif display_text.startswith("RULE:"):
                            st.markdown(f"- {pts_badge} 📐 {display_text}")
                        else:
                            st.markdown(f"- {pts_badge} {display_text}")
            
            st.markdown("---")
            
            # === CONTEXT BANNERS (v7.5.2+) ===
            # Prominent indicators for special domain types that affect analysis scope
            if domain_data.get('no_a_record'):
                dns_found = domain_data.get('dns_records_found', '')
                st.info(f"📡 **Mail-only domain** — No A record (no web server). DNS records found: {dns_found}. Analysis limited to email auth, MX, WHOIS, NS, and CT logs. Web-presence penalties automatically suppressed.")
            
            if domain_data.get('is_dev_staging'):
                confidence = domain_data.get('dev_staging_confidence', '')
                evidence = domain_data.get('dev_staging_evidence', '').replace(';', ', ')
                if confidence == "HIGH":
                    st.info(f"🧪 **Dev/staging environment (HIGH confidence, -15 pts)** — {evidence}")
                elif confidence == "MEDIUM":
                    st.info(f"🧪 **Possible dev/staging environment (MEDIUM)** — {evidence}")
                elif confidence == "LOW":
                    st.info(f"🧪 **Possible dev/staging environment (LOW)** — {evidence}")
            
            # Key signals
            st.markdown("**Email Authentication:**")
            auth_col1, auth_col2, auth_col3 = st.columns(3)
            with auth_col1:
                spf = "✅" if domain_data.get('spf_exists') else "❌"
                st.markdown(f"SPF: {spf}")
            with auth_col2:
                dkim = "✅" if domain_data.get('dkim_exists') else "❌"
                st.markdown(f"DKIM: {dkim}")
            with auth_col3:
                dmarc = "✅" if domain_data.get('dmarc_exists') else "❌"
                st.markdown(f"DMARC: {dmarc}")
            
            age_days = domain_data.get('domain_age_days', -1)
            age_source = domain_data.get('domain_age_source', '')
            rdap_created = domain_data.get('rdap_created', '')
            if age_days >= 0:
                _age_date = rdap_created[:10] if rdap_created else ''
                _age_src = f" via {age_source.upper()}" if age_source else ''
                _age_date_str = f" (created {_age_date})" if _age_date else ''
                if age_days < 7:
                    st.markdown(f"**Domain Age:** 🔴 {age_days} days{_age_date_str}{_age_src}")
                elif age_days < 30:
                    st.markdown(f"**Domain Age:** 🟠 {age_days} days{_age_date_str}{_age_src}")
                elif age_days < 90:
                    st.markdown(f"**Domain Age:** 🟡 {age_days} days{_age_date_str}{_age_src}")
                elif age_days < 365:
                    st.markdown(f"**Domain Age:** {age_days} days{_age_date_str}{_age_src}")
                else:
                    years = age_days // 365
                    st.markdown(f"**Domain Age:** {age_days} days (~{years}yr){_age_date_str}{_age_src}")
            else:
                st.markdown("**Domain Age:** ⚠️ Unknown (RDAP/WHOIS lookup failed)")
            
            # Reregistration indicator
            if domain_data.get('domain_reregistered'):
                _rereg_date = domain_data.get('domain_reregistered_date', '')[:10]
                _rereg_days = domain_data.get('domain_reregistered_days', -1)
                st.markdown(f"**⚠️ Re-registered:** {_rereg_date} ({_rereg_days}d ago) — domain was dropped and re-bought")
            
            # WHOIS privacy indicator
            if domain_data.get('whois_privacy'):
                service = domain_data.get('whois_privacy_service', 'Unknown')
                if age_days >= 0 and age_days < 90:
                    st.markdown(f"**WHOIS:** 🔐 Privacy ({service}) — {age_days}d-old domain")
                else:
                    st.markdown(f"**WHOIS:** Privacy ({service})")
            
            # Page title display
            if domain_data.get('page_title'):
                title = domain_data['page_title'][:80]
                if domain_data.get('has_suspicious_page_title'):
                    st.markdown(f"**Page Title:** ⚠️ \"{title}\"")
                else:
                    st.markdown(f"**Page Title:** \"{title}\"")
            
            # Hosting Provider display
            if domain_data.get('hosting_provider'):
                provider = domain_data['hosting_provider']
                ptype = domain_data.get('hosting_provider_type', '')
                via = domain_data.get('hosting_detected_via', '')
                asn_org = domain_data.get('hosting_asn_org', '')
                type_icons = {
                    'budget_shared': '⚠️',
                    'free': '🚩',
                    'suspect': '🔴',
                    'premium': '✅',
                }
                icon = type_icons.get(ptype, 'ℹ️')
                st.markdown(f"**Hosting:** {icon} {provider} ({ptype}) — detected via {via}")
                if asn_org:
                    st.markdown(f"**ASN Org:** {asn_org}")
            
            # MX Provider display
            mx_ptype = domain_data.get('mx_provider_type', '')
            if mx_ptype and mx_ptype != 'unknown':
                mx_primary = domain_data.get('mx_primary', '')
                mx_icons = {
                    'enterprise': '✅',
                    'standard': 'ℹ️',
                    'disposable': '⚠️',
                    'selfhosted': '⚠️',
                }
                mx_icon = mx_icons.get(mx_ptype, 'ℹ️')
                st.markdown(f"**MX Provider:** {mx_icon} {mx_ptype} ({mx_primary})")
            
            # NS Records display (v7.3)
            ns_records = domain_data.get('ns_records', '')
            if ns_records:
                ns_list = ns_records.split(';')
                ns_count = domain_data.get('ns_count', len(ns_list))
                ns_flags = []
                if domain_data.get('ns_is_dynamic_dns'):
                    ns_flags.append(f"🔴 Dynamic DNS ({domain_data.get('ns_dynamic_dns_match', '')})")
                if domain_data.get('ns_is_parking'):
                    ns_flags.append(f"🟡 Parking NS ({domain_data.get('ns_parking_match', '')})")
                if domain_data.get('ns_is_lame_delegation'):
                    ns_flags.append("🔴 Lame delegation")
                if domain_data.get('ns_is_free_dns'):
                    ns_flags.append(f"⚠️ Free DNS ({domain_data.get('ns_free_dns_match', '')})")
                if domain_data.get('ns_is_single_ns'):
                    ns_flags.append("⚠️ Single NS")
                flag_str = " · ".join(ns_flags) if ns_flags else "✅"
                st.markdown(f"**NS Records ({ns_count}):** {', '.join(ns_list[:4])} {flag_str}")
            elif domain_data.get('ns_is_lame_delegation'):
                st.markdown("**NS Records:** 🔴 Lame delegation (0 NS records)")
        
        # === PHISHING KIT DETAILS (v7.3 + v7.4 + v7.5) ===
        has_any_kit = (
            domain_data.get('phishing_kit_detected')
            or domain_data.get('has_phishing_kit_filename')
            or domain_data.get('has_exfil_drop_script')
            or domain_data.get('has_form_action_kit')
            or domain_data.get('has_suspicious_page_title')
            or domain_data.get('has_harvest_combo')
            or domain_data.get('has_harvest_signals')
        )
        if has_any_kit:
            with st.expander("🎣 Phishing Kit Detection", expanded=True):
                kit_col1, kit_col2 = st.columns(2)
                with kit_col1:
                    if domain_data.get('phishing_kit_detected'):
                        st.error(f"**Kit Confirmed:** {domain_data.get('phishing_kit_reason', '')}")
                    if domain_data.get('has_phishing_kit_filename'):
                        fn = domain_data.get('phishing_kit_filename', '')
                        strength = "🔴 STRONG" if domain_data.get('phishing_kit_filename_strong') else "🟡 WEAK (needs combo)"
                        st.markdown(f"**Kit Filename:** `{fn}` ({strength})")
                    if domain_data.get('has_form_action_kit'):
                        target = domain_data.get('form_action_kit_target', '')
                        strength = "🔴 STRONG" if domain_data.get('form_action_kit_strong') else "🟡 WEAK"
                        st.markdown(f"**Form Action Target:** `{target}` ({strength})")
                    if domain_data.get('has_suspicious_page_title'):
                        title = domain_data.get('page_title', '')
                        match = domain_data.get('page_title_match', '')
                        st.markdown(f"**Suspicious Title:** \"{title}\"")
                        st.caption(f"Matched lure pattern: \"{match}\"")
                with kit_col2:
                    if domain_data.get('has_exfil_drop_script'):
                        signals = domain_data.get('exfil_drop_signals', '').replace(';', ', ')
                        details = domain_data.get('exfil_drop_details', '').replace(';', '\n- ')
                        st.markdown(f"**Exfil Signals:** {signals}")
                        st.markdown(f"- {details}")
                    if domain_data.get('whois_privacy') and domain_data.get('domain_age_days', 999) < 90:
                        service = domain_data.get('whois_privacy_service', 'Unknown')
                        st.markdown(f"**WHOIS Privacy:** {service}")
                        st.caption(f"Privacy-protected registrant on {domain_data.get('domain_age_days', '?')}d-old domain")
                
                # v7.5: Client-side harvest detection
                if domain_data.get('has_harvest_signals'):
                    st.divider()
                    harvest_signals = domain_data.get('harvest_signals', '').replace(';', ', ')
                    harvest_details = domain_data.get('harvest_details', '').replace(';', '\n- ')
                    if domain_data.get('has_harvest_combo'):
                        st.error(f"**🕸️ Client-Side Harvest Combo**")
                        st.caption(domain_data.get('harvest_combo_reason', ''))
                        st.markdown(f"**Harvest Signals:** {harvest_signals}")
                        st.markdown(f"- {harvest_details}")
                    else:
                        st.info(f"**🕸️ Client-Side Harvest (uncorroborated — not scored)**")
                        st.markdown(f"**Harvest Signals:** {harvest_signals}")
                        st.markdown(f"- {harvest_details}")
                        st.caption("Credential harvesting code detected but no corroborating phishing signals found")
        
        # === VIRUSTOTAL REPUTATION ===
        if domain_data.get('vt_available'):
            with st.expander("🛡️ VirusTotal Reputation", expanded=domain_data.get('vt_malicious_count', 0) > 0):
                vt_col1, vt_col2, vt_col3, vt_col4 = st.columns(4)
                mal = domain_data.get('vt_malicious_count', 0)
                sus = domain_data.get('vt_suspicious_count', 0)
                total = domain_data.get('vt_total_vendors', 0)
                
                with vt_col1:
                    color = "🔴" if mal >= 5 else "🟠" if mal >= 1 else "🟢"
                    st.metric(f"{color} Malicious", f"{mal}/{total}")
                with vt_col2:
                    st.metric("⚠️ Suspicious", sus)
                with vt_col3:
                    st.metric("Community", domain_data.get('vt_community_score', 0))
                with vt_col4:
                    st.metric("Reputation", domain_data.get('vt_reputation', 0))
                
                # Threat names
                threat_names = domain_data.get('vt_threat_names', '')
                if threat_names:
                    st.warning(f"**Threat families:** {threat_names.replace(';', ', ')}")
                
                # Malicious vendors
                mal_vendors = domain_data.get('vt_malicious_vendors', '')
                if mal_vendors:
                    st.markdown(f"**Flagged by:** {mal_vendors.replace(';', ', ')}")
                
                # Categories
                vt_cats = domain_data.get('vt_categories', '')
                if vt_cats and vt_cats != '{}':
                    try:
                        cats = json.loads(vt_cats)
                        if cats:
                            unique_cats = sorted(set(cats.values()))
                            st.markdown(f"**Categories:** {', '.join(unique_cats)}")
                    except (json.JSONDecodeError, TypeError):
                        pass
                
                last_analysis = domain_data.get('vt_last_analysis', '')
                if last_analysis:
                    st.caption(f"Last VT analysis: {last_analysis}")
        elif domain_data.get('vt_error'):
            with st.expander("🛡️ VirusTotal Reputation — ⚠️ CHECK FAILED", expanded=True):
                st.error(f"**VT check failed:** {domain_data['vt_error']}")
                st.caption("VirusTotal scoring is unavailable for this domain. Verify the API key in Settings → Config.")
        
        # === HACKLINK / SEO SPAM DETECTION ===
        has_hacklink = (
            domain_data.get('hacklink_detected') or domain_data.get('hacklink_keywords') or 
            domain_data.get('hacklink_wp_compromised') or domain_data.get('hacklink_malicious_script') or
            domain_data.get('hacklink_hidden_injection') or domain_data.get('hacklink_is_cpanel')
        )
        if has_hacklink:
            with st.expander("🕷️ Hacklink / SEO Spam Detection", expanded=domain_data.get('hacklink_detected', False) or domain_data.get('hacklink_malicious_script', False) or domain_data.get('hacklink_hidden_injection', False)):
                hl_col1, hl_col2, hl_col3 = st.columns(3)
                
                with hl_col1:
                    detected = domain_data.get('hacklink_detected', False)
                    icon = "🔴" if detected else "🟡"
                    st.metric(f"{icon} Hacklink Detected", "YES" if detected else "Keywords Found")
                with hl_col2:
                    st.metric("Risk Score", f"{domain_data.get('hacklink_score', 0)}/30")
                with hl_col3:
                    spam_count = domain_data.get('hacklink_spam_link_count', 0)
                    if spam_count > 0:
                        st.metric("🔗 Spam Links", spam_count)
                    else:
                        is_wp = domain_data.get('hacklink_is_wordpress', False)
                        st.metric("WordPress", "✅ Yes" if is_wp else "No")
                
                # Keywords found
                keywords = domain_data.get('hacklink_keywords', '')
                if keywords:
                    kw_list = keywords.split(';')
                    st.markdown(f"**Keywords found ({len(kw_list)}):** {', '.join(kw_list[:15])}")
                    if len(kw_list) > 15:
                        st.caption(f"... and {len(kw_list) - 15} more")
                
                # Injection patterns
                patterns = domain_data.get('hacklink_injection_patterns', '')
                if patterns:
                    st.warning(f"**Injection patterns:** {patterns.replace(';', ', ')}")
                
                # WordPress compromise
                if domain_data.get('hacklink_wp_compromised'):
                    st.error("**⚠️ WordPress compromise indicators detected** — WP files show signs of code injection")
                
                # Vulnerable plugins
                vuln_plugins = domain_data.get('hacklink_vulnerable_plugins', '')
                if vuln_plugins:
                    st.error(f"**Vulnerable plugins:** {vuln_plugins.replace(';', ', ')}")
                
                # === HIGH-VALUE SIGNALS ===
                if domain_data.get('hacklink_malicious_script'):
                    st.error("**💀 MALICIOUS SCRIPT INJECTION** — SocGholish/FakeUpdates-style obfuscated script detected; domain is actively compromised")
                
                if domain_data.get('hacklink_hidden_injection'):
                    st.error("**💀 HIDDEN CONTENT INJECTION** — CSS-cloaked content (display:none, font-size:0) with links; classic hacklink SEO spam fingerprint")
                
                if domain_data.get('hacklink_is_cpanel'):
                    st.warning("**cPanel hosting detected** — shared hosting environment frequently targeted in hacklink campaigns")
                
                sus_scripts = domain_data.get('hacklink_suspicious_scripts', '')
                if sus_scripts:
                    st.warning(f"**Suspicious external scripts:** {sus_scripts.replace(';', ', ')}")
        
        # === MALICIOUS LINKS & URLs (v7.3.1) ===
        # Aggregate all link-related findings into a single reference section
        _kit_fn = domain_data.get('phishing_kit_filename', '')
        _phish_paths = domain_data.get('phishing_paths_found', '')
        _malware_links = domain_data.get('malware_links_found', '')
        _spam_links = domain_data.get('hacklink_spam_links_found', '')
        _sus_scripts = domain_data.get('hacklink_suspicious_scripts', '')
        _phish_infra = domain_data.get('phishing_infra_domain', '')
        _final_url = domain_data.get('final_url', '')
        _redirect_chain = domain_data.get('redirect_chain', '')
        
        has_any_links = any([_kit_fn, _phish_paths, _malware_links, _spam_links, _sus_scripts, _phish_infra])
        
        if has_any_links:
            with st.expander("🔗 Malicious Links & URLs", expanded=True):
                st.caption("⚠️ URLs displayed as plain text — do not visit these domains")
                
                # Kit filename + full URL context
                if _kit_fn:
                    strength = "🔴 STRONG" if domain_data.get('phishing_kit_filename_strong') else "🟡 WEAK"
                    kit_url = _final_url if _final_url else f"(path ends with {_kit_fn})"
                    st.error(f"**🎣 Kit Entry Point:** `{_kit_fn}` ({strength})")
                    st.code(kit_url, language=None)
                
                # Phishing paths matched in URL
                if _phish_paths:
                    paths = _phish_paths.split(';')
                    st.warning(f"**📂 Phishing Paths ({len(paths)}):** URL contains known phishing directory patterns")
                    st.code('\n'.join(paths[:5]), language=None)
                
                # Redirect to phishing infrastructure
                if _phish_infra:
                    st.error(f"**🔀 Redirects to Phishing Infra:**")
                    st.code(_phish_infra, language=None)
                    if _redirect_chain:
                        st.code(_redirect_chain.replace(' → ', '\n→ '), language=None)
                
                # Spam/hacklink outbound links found in content
                if _spam_links:
                    urls = _spam_links.split(';')
                    st.warning(f"**🕷️ Spam/Hacklink URLs ({len(urls)}):** Hidden outbound links to gambling/pharma/spam domains")
                    display_urls = urls[:10]
                    st.code('\n'.join(u[:120] for u in display_urls), language=None)
                    if len(urls) > 10:
                        st.caption(f"... and {len(urls) - 10} more")
                
                # Malware links
                if _malware_links:
                    links = _malware_links.split(';')
                    st.error(f"**🦠 Malware Links ({len(links)}):** Known malicious URLs found in page content")
                    st.code('\n'.join(l[:120] for l in links[:5]), language=None)
                
                # Suspicious external scripts
                if _sus_scripts:
                    scripts = _sus_scripts.split(';')
                    st.warning(f"**⚠️ Suspicious Scripts ({len(scripts)}):** External JS from untrusted domains")
                    st.code('\n'.join(s[:120] for s in scripts[:5]), language=None)
        
        # === HACKLINK CAMPAIGN PROFILE (v7.5.1) ===
        if domain_data.get('hacklink_campaign_profile'):
            _hcp_conf = domain_data.get('hacklink_campaign_profile_confidence', 'MODERATE')
            _hcp_sigs = domain_data.get('hacklink_campaign_profile_signals', '')
            _icon = "🔴" if _hcp_conf == "HIGH" else "🟠"
            with st.expander(f"🕸️ Hacklink Campaign Profile ({_hcp_conf})", expanded=True):
                st.warning(
                    f"**{_icon} Hacklink Campaign Profile ({_hcp_conf})** — Domain matches known hacklink target "
                    f"infrastructure fingerprint. Injected content may be cloaked or cleaned up."
                )
                if _hcp_sigs:
                    sig_labels = {
                        "empty_page": "Empty/gutted page content",
                        "uk_variant_dark": ".co.uk TLD variant has no DNS",
                        "weak_email_auth": "No DKIM + DMARC p=none + SPF softfail",
                        "hidden_injection": "CSS-hidden content injection detected",
                        "cpanel": "cPanel hosting (mass exploitation target)",
                    }
                    for sig in _hcp_sigs.split(";"):
                        sig = sig.strip()
                        label = sig_labels.get(sig, sig)
                        st.markdown(f"- **{sig}**: {label}")
                st.caption("This is a PROFILE match, not confirmed hacklink. Only fires on domains 90+ days old.")
        
        # === SECURITY TOOLING (v7.5.1) ===
        _sec_signals = domain_data.get('content_security_signals', '')
        if _sec_signals:
            _sec_names = {
                "recaptcha": "Google reCAPTCHA",
                "cloudflare_bot_management": "Cloudflare Bot Management / Turnstile",
                "hcaptcha": "hCaptcha",
                "akamai_bot_manager": "Akamai Bot Manager",
                "datadome": "DataDome",
                "perimeterx": "PerimeterX / HUMAN Security",
            }
            _sec_list = [_sec_names.get(s.strip(), s.strip()) for s in _sec_signals.split(";") if s.strip()]
            if _sec_list:
                with st.expander(f"🛡️ Security Tooling ({len(_sec_list)} detected)", expanded=False):
                    st.success("**Security tooling detected** — Legitimate sites invest in bot management and CAPTCHA; phishing kits almost never implement these.")
                    for s in _sec_list:
                        st.markdown(f"- {s}")
        
        # === CONTENT IDENTITY VERIFICATION ===
        has_content_identity = (
            domain_data.get('content_title_body_mismatch') or
            domain_data.get('content_cross_domain_emails') or
            domain_data.get('content_is_broker_page') or
            domain_data.get('content_page_privacy_emails') or
            domain_data.get('content_is_placeholder') or
            domain_data.get('content_is_facade') or
            domain_data.get('registration_opaque') or
            domain_data.get('domain_reregistered') or
            domain_data.get('content_external_link_domains') or
            domain_data.get('content_page_emails')
        )
        if has_content_identity:
            with st.expander("🔍 Content Identity Verification", expanded=True):
                ci_col1, ci_col2, ci_col3, ci_col4 = st.columns(4)
                with ci_col1:
                    mismatch = domain_data.get('content_title_body_mismatch', False)
                    icon = "🔴" if mismatch else "🟢"
                    st.metric(f"{icon} Title/Body Match", "MISMATCH" if mismatch else "OK")
                with ci_col2:
                    xd = domain_data.get('content_cross_domain_emails', '')
                    xd_count = len(xd.split(';')) if xd else 0
                    icon = "🔴" if xd_count > 0 else "🟢"
                    st.metric(f"{icon} Cross-Domain Emails", xd_count)
                with ci_col3:
                    broker = domain_data.get('content_is_broker_page', False)
                    icon = "🟠" if broker else "🟢"
                    st.metric(f"{icon} Broker Page", "YES" if broker else "No")
                with ci_col4:
                    facade = domain_data.get('content_is_facade', False)
                    icon = "🔴" if facade else "🟢"
                    wc = domain_data.get('content_visible_word_count', -1)
                    label = f"YES ({wc} words)" if facade else "No"
                    st.metric(f"{icon} Content Facade", label)
                
                if mismatch:
                    detail = domain_data.get('content_title_body_detail', '')
                    st.error(f"**🔴 Title/Body Mismatch:** {detail}")
                
                xd_emails = domain_data.get('content_cross_domain_emails', '')
                xd_domains = domain_data.get('content_cross_domain_email_domains', '')
                if xd_emails:
                    emails_list = xd_emails.split(';')
                    domains_list = xd_domains.split(';') if xd_domains else []
                    st.error(
                        f"**🔴 Cross-Domain Emails ({len(emails_list)}):** "
                        f"Page contains emails from a different domain: "
                        f"**{', '.join(domains_list)}**"
                    )
                    st.code('\n'.join(emails_list[:10]), language=None)
                
                priv = domain_data.get('content_page_privacy_emails', '')
                if priv:
                    st.warning(f"**🟠 Privacy Emails on Page:** {priv.replace(';', ', ')}")
                
                free = domain_data.get('content_page_freemail_contacts', '')
                if free:
                    st.info(f"**ℹ️ Freemail Contacts:** {free.replace(';', ', ')}")
                
                if broker:
                    indicators = domain_data.get('content_broker_indicators', '')
                    st.warning(f"**🟠 Broker Page Indicators:** {indicators.replace(';', ', ')}")
                
                if domain_data.get('content_is_facade'):
                    facade_detail = domain_data.get('content_facade_detail', '')
                    st.error(f"**🔴 Content Facade / SPA Shell:** {facade_detail}")
                    ext_scripts = domain_data.get('content_external_script_domains', '')
                    if ext_scripts:
                        st.caption(f"External script domains: {ext_scripts.replace(';', ', ')}")
                    wc = domain_data.get('content_visible_word_count', -1)
                    if wc >= 0:
                        st.caption(f"Visible word count: {wc}")
                
                if domain_data.get('content_is_placeholder'):
                    st.warning("**🟠 Placeholder Content:** Page contains template/placeholder text")
                
                if domain_data.get('registration_opaque'):
                    st.error("**🔴 Registration Opaque:** Both RDAP and WHOIS failed to return domain creation date/registrar — registration data hidden or unavailable")
                
                if domain_data.get('domain_reregistered'):
                    _rereg_date = domain_data.get('domain_reregistered_date', '?')[:10]
                    _rereg_days = domain_data.get('domain_reregistered_days', -1)
                    _rereg_age = f"{_rereg_days}d ago" if _rereg_days >= 0 else "unknown"
                    st.error(f"**🔴 Domain Re-Registered:** Dropped and re-registered on {_rereg_date} ({_rereg_age}) — possible expired domain takeover for residual reputation")
                
                all_emails = domain_data.get('content_page_emails', '')
                all_phones = domain_data.get('content_page_phones', '')
                if all_emails or all_phones:
                    st.caption("📋 Contact info extracted from page:")
                    if all_emails:
                        st.text(f"Emails: {all_emails.replace(';', ', ')}")
                    if all_phones:
                        st.text(f"Phones: {all_phones.replace(';', ', ')}")
                
                ext_links = domain_data.get('content_external_link_domains', '')
                if ext_links:
                    link_list = ext_links.split(";")
                    st.markdown(f"**🔗 External Domains Linked on Page ({len(link_list)}):**")
                    for link in link_list:
                        st.text(f"  • {link}")
                
                ext_scripts = domain_data.get('content_external_script_domains', '')
                if ext_scripts:
                    script_list = ext_scripts.split(";")
                    st.markdown(f"**⚙️ External Script Sources ({len(script_list)}):**")
                    for script in script_list:
                        st.text(f"  • {script}")
        
        # === DOMAIN CATEGORY RISK (v7.7) ===
        if domain_data.get('domain_category'):
            _cat = domain_data['domain_category_label']
            _tier = domain_data.get('domain_category_risk_tier', '')
            _reason = domain_data.get('domain_category_risk_reason', '')
            _conf = domain_data.get('domain_category_confidence', 0)
            _sigs = domain_data.get('domain_category_signals', '')
            _color = {'HIGH': 'red', 'ELEVATED': 'orange', 'MODERATE': 'blue'}.get(_tier, 'gray')
            with st.expander(f"Category Risk: {_cat} ({_tier})", expanded=True):
                st.markdown(f":{_color}[**{_tier}**] — **{_cat}**")
                st.caption(_reason)
                st.text(f"  Confidence: {_conf}/18")
                if _sigs:
                    st.text(f"  Signals: {_sigs}")
        
                # === CONTACT CROSS-REFERENCE (OSINT) ===
        # v7.7.1: VT-flagged external domains on page
        _ext_mal_ct = domain_data.get('vt_external_malicious_count', 0)
        if _ext_mal_ct and int(_ext_mal_ct) > 0:
            with st.expander(f"VT External Malicious ({int(_ext_mal_ct)} domains)", expanded=True):
                st.error(f"**{int(_ext_mal_ct)} external domain(s)** referenced on this page are flagged malicious by VirusTotal")
                _ext_detail_str = domain_data.get('vt_external_malicious_details', '')
                if _ext_detail_str:
                    try:
                        _ext_info = json.loads(_ext_detail_str)
                        for _ed, _ei in _ext_info.items():
                            _threats = ", ".join(_ei.get("threats", [])[:5])
                            _vendors = ", ".join(_ei.get("vendors", [])[:5])
                            st.markdown(f"**{_ed}** — {_ei['malicious']}/{_ei['total']} vendors")
                            if _threats:
                                st.caption(f"Threats: {_threats}")
                            if _vendors:
                                st.caption(f"Vendors: {_vendors}")
                    except Exception:
                        st.text(domain_data.get('vt_external_malicious_domains', ''))
                st.caption(f"Checked {domain_data.get('vt_external_checked_count', 0)} non-CDN external domains against VT")
        
        contact_reuse_json = domain_data.get('contact_reuse_results', '')
        if contact_reuse_json:
            try:
                cr_data = json.loads(contact_reuse_json)
                cr_matches = cr_data.get("matches", [])
                if cr_matches:
                    with st.expander(f"🌐 Contact Cross-Reference ({sum(len(m['found_on']) for m in cr_matches)} other domains)", expanded=True):
                        st.markdown("*Contact info from this page was found on other domains:*")
                        for match in cr_matches:
                            icon = "📧" if match["type"] == "email" else "📞"
                            contact = match["contact"]
                            domains = match["found_on"]
                            st.markdown(f"**{icon} `{contact}`** — found on {len(domains)} other domain(s):")
                            for d in domains:
                                st.text(f"  • {d}")
                        searched = cr_data.get("searched", 0)
                        st.caption(f"ℹ️ Informational only — {searched} web search(es) performed. Same contact on unrelated domains may indicate coordinated activity.")
            except Exception:
                pass
        
        # === DOMAIN TAKEOVER / TRANSFER LOCK ===
        has_takeover_signal = (
            domain_data.get('domain_transfer_lock_recent') or 
            domain_data.get('whois_recently_updated') or
            domain_data.get('mx_provider_mismatch') or
            domain_data.get('subdomain_infra_divergent') or
            (domain_data.get('ct_recent_issuance') and domain_data.get('domain_age_days', 0) > 365)
        )
        if has_takeover_signal:
            with st.expander("🔓 Domain Takeover Indicators", expanded=True):
                tk_col1, tk_col2, tk_col3 = st.columns(3)
                with tk_col1:
                    locked = domain_data.get('domain_transfer_locked', True)
                    recent = domain_data.get('domain_transfer_lock_recent', False)
                    if recent:
                        st.metric("🟠 Transfer Lock", "RECENTLY ADDED")
                    elif locked:
                        st.metric("🟢 Transfer Lock", "Locked")
                    else:
                        st.metric("🔴 Transfer Lock", "UNLOCKED")
                with tk_col2:
                    days = domain_data.get('whois_recently_updated_days', -1)
                    if days >= 0:
                        st.metric("WHOIS Updated", f"{days}d ago")
                    else:
                        st.metric("WHOIS Updated", "Unknown")
                with tk_col3:
                    registrar = domain_data.get('whois_registrar', '')
                    if registrar:
                        st.metric("Registrar", registrar[:30])
                
                statuses = domain_data.get('whois_statuses', '')
                if statuses:
                    st.caption(f"Domain statuses: {statuses.replace(';', ', ')}")
                
                # MX Hijack Fingerprint (v7.3.1)
                if domain_data.get('mx_provider_mismatch'):
                    confidence = domain_data.get('mx_hijack_confidence', '')
                    ghost = domain_data.get('mx_ghost_provider', '')
                    evidence = domain_data.get('mx_ghost_evidence', '').replace(';', '\n• ')
                    if confidence == "HIGH":
                        st.error(f"**🚨 MX HIJACK FINGERPRINT** — {ghost} ghost detected (HIGH confidence)")
                    elif confidence == "MEDIUM":
                        st.warning(f"**⚠️ MX Provider Mismatch** — {ghost} ghost detected (MEDIUM confidence)")
                    else:
                        st.info(f"**MX Provider Mismatch** — {ghost} residual detected (LOW — possible legitimate migration)")
                    st.code(f"• {evidence}", language=None)
                
                # Subdomain Delegation Abuse (v7.3.1)
                if domain_data.get('subdomain_infra_divergent'):
                    confidence = domain_data.get('subdomain_divergence_confidence', '')
                    parent = domain_data.get('parent_domain', '')
                    sub_evidence = domain_data.get('subdomain_divergence_evidence', '').replace(';', '\n• ')
                    parent_ip = domain_data.get('parent_ip', '')
                    parent_asn = domain_data.get('parent_asn', '')
                    parent_asn_org = domain_data.get('parent_asn_org', '')
                    parent_mx = domain_data.get('parent_mx_provider_type', '')
                    
                    if confidence == "HIGH":
                        st.error(f"**🚨 SUBDOMAIN DELEGATION ABUSE** — `{domain_data.get('domain', '')}` points to different infrastructure than parent `{parent}` (HIGH confidence)")
                    elif confidence == "MEDIUM":
                        st.warning(f"**⚠️ Subdomain Infrastructure Divergence** — `{domain_data.get('domain', '')}` diverges from parent `{parent}` (MEDIUM confidence)")
                    else:
                        st.info(f"**Subdomain Infrastructure Divergence** — Minor divergence from parent `{parent}` (LOW)")
                    
                    st.code(f"• {sub_evidence}\n\nParent: {parent} → IP {parent_ip} (AS{parent_asn} {parent_asn_org}), MX: {parent_mx}", language=None)
                
                if domain_data.get('domain_transfer_lock_recent'):
                    age = domain_data.get('domain_age_days', -1)
                    whois_days = domain_data.get('whois_recently_updated_days', -1)
                    if age > 365:
                        st.error(f"**⚠️ LOCK RECENTLY ADDED + {age}d OLD** — Established domain had transfer lock added recently; possible post-compromise lockdown")
                    elif whois_days >= 0:
                        st.warning(f"**Transfer lock recently added** (WHOIS updated {whois_days}d ago) — Monitor for post-compromise lockdown pattern")
                    else:
                        st.warning("**Transfer lock recently added** — Possible post-compromise lockdown response")
                
                if domain_data.get('whois_recently_updated'):
                    st.warning(f"**WHOIS recently updated** ({domain_data.get('whois_recently_updated_days')}d ago) — Possible ownership change, transfer, or DNS hijack")
        
        # === EMPTY PAGE ===
        if domain_data.get('is_empty_page'):
            st.warning("📄 **Empty page detected** — Reachable domain returns empty/near-empty content (parked, abandoned, or stripped post-compromise)")
        
        # === CERTIFICATE TRANSPARENCY ===
        ct_count = domain_data.get('ct_log_count', -1)
        if ct_count >= 0:
            with st.expander(f"📜 Certificate Transparency ({ct_count} certs)", expanded=ct_count == 0 or domain_data.get('ct_recent_issuance', False) or domain_data.get('ct_cert_tls_dead', False)):
                ct_col1, ct_col2, ct_col3 = st.columns(3)
                with ct_col1:
                    icon = "🔴" if ct_count == 0 else "🟢"
                    st.metric(f"{icon} CT Certs Found", ct_count)
                with ct_col2:
                    days_since = domain_data.get('ct_days_since_last_cert', -1)
                    if days_since >= 0 and days_since <= 7:
                        st.metric("Last Cert", f"⚠️ {days_since}d ago")
                    elif days_since >= 0:
                        st.metric("Last Cert", f"{days_since}d ago")
                    else:
                        recent = domain_data.get('ct_recent_issuance', False)
                        st.metric("Last Cert", "⚠️ <7d" if recent else "Unknown")
                with ct_col3:
                    issuers = domain_data.get('ct_issuers', '')
                    if issuers:
                        st.metric("Issuers", issuers.split(';')[0][:25])
                
                first = domain_data.get('ct_first_seen', '')
                last = domain_data.get('ct_last_seen', '')
                last_issuer = domain_data.get('ct_last_cert_issuer', '')
                days_since = domain_data.get('ct_days_since_last_cert', -1)
                if first:
                    detail = f"First cert: {first[:10]}  |  Most recent: {last[:10] if last else 'N/A'}"
                    if last_issuer:
                        detail += f"  |  Last issuer: {last_issuer}"
                    if days_since >= 0:
                        detail += f"  |  {days_since}d ago"
                    st.caption(detail)
                
                if ct_count == 0:
                    st.error("**No CT history** — Zero certificates found; domain may never have been used for HTTPS")
                elif domain_data.get('ct_recent_issuance') and domain_data.get('domain_age_days', 0) > 365:
                    # v7.5.1: Only warn if this isn't a routine renewal
                    if ct_count < 5:
                        st.warning(f"**Recent cert on old domain** — New certificate issued on {domain_data.get('domain_age_days')}d-old domain; possible takeover/reactivation")
                
                # v7.5.1: Cert issued but TLS dead
                if domain_data.get('ct_cert_tls_dead'):
                    _detail = domain_data.get('ct_cert_tls_dead_detail', '')
                    st.error(f"**🔒 CERT ISSUED BUT TLS DEAD** — {_detail or 'Certificate issued recently but TLS is now refusing connections'}")
                
                # v7.3.1: CT gap / aged domain purchase detection
                ct_gap = domain_data.get('ct_gap_months', -1)
                if domain_data.get('ct_reactivated'):
                    st.error(f"**🚨 CT REACTIVATION** — {ct_gap} month gap in cert history, then recent cert. Domain likely purchased from auction/expiry.")
                    st.code(domain_data.get('ct_gap_evidence', ''), language=None)
                elif ct_gap >= 12:
                    st.warning(f"**⚠️ CT Gap ({ct_gap} months)** — Significant gap in cert issuance history; may indicate period of inactivity/expiry.")
                    gap_ev = domain_data.get('ct_gap_evidence', '')
                    if gap_ev:
                        st.code(gap_ev, language=None)
        
        # === v7.3.1: OAUTH CONSENT PHISHING ===
        if domain_data.get('has_oauth_phish'):
            with st.expander("🔑 OAuth Consent Phishing", expanded=True):
                st.error("**OAuth consent phishing detected** — Page contains outbound links to Microsoft/Google OAuth authorization endpoints. Attacker tricks users into granting malicious app permissions (mail read, file access, etc.) instead of harvesting credentials directly.")
                evidence = domain_data.get('oauth_phish_evidence', '')
                if evidence:
                    st.code(evidence.replace(';', '\n'), language=None)
                st.caption("This bypasses password field detection because no credentials are entered on the phishing domain itself.")
        
        # === v7.3.1: HOMOGLYPH / IDN SPOOFING ===
        if domain_data.get('is_homoglyph_domain'):
            with st.expander("🔤 Homoglyph / IDN Spoofing", expanded=True):
                target = domain_data.get('homoglyph_target', '')
                decoded = domain_data.get('homoglyph_decoded', '')
                st.error(f"**IDN homoglyph attack** — Domain uses Unicode lookalike characters to impersonate **{target}**")
                if decoded:
                    st.metric("Displays as", decoded)
                st.code(f"Punycode: {domain_data.get('domain', '')}\nUnicode:  {decoded}\nTarget:   {target}", language=None)
                st.caption("Cyrillic/Greek characters that are visually identical to Latin letters in most fonts. Users cannot distinguish this from the real domain.")
        
        # === v7.3.1: QUISHING PROFILE ===
        if domain_data.get('quishing_profile'):
            with st.expander("📱 QR Code Phishing (Quishing)", expanded=True):
                st.warning("**Quishing profile detected** — Domain matches the behavioral fingerprint of a QR code phishing landing page: minimal content, new domain, phishing-associated TLD, and no organic web presence.")
                evidence = domain_data.get('quishing_evidence', '')
                if evidence:
                    st.code(evidence.replace(';', '\n'), language=None)
                st.caption("These domains exist solely as QR code scan destinations, often printed on fake parking meters, emails, or physical flyers.")
        
        # === v7.3.1: CDN TUNNEL ABUSE ===
        if domain_data.get('cdn_tunnel_suspect'):
            with st.expander("☁️ CDN Tunnel Abuse", expanded=True):
                cdn = domain_data.get('cdn_provider', '')
                st.warning(f"**CDN tunnel abuse suspected** — Domain resolves to **{cdn}** IPs (looks reputable), but shows suspicious signals suggesting the hidden origin server is attacker-controlled.")
                evidence = domain_data.get('cdn_tunnel_evidence', '')
                if evidence:
                    st.code(evidence.replace(';', '\n'), language=None)
                st.caption(f"The domain's SSL cert is a {cdn} universal/edge cert — it proves nothing about the origin server. Cloudflare Tunnels and similar services let anyone proxy through CDN IPs.")
        elif domain_data.get('is_cdn_hosted') and domain_data.get('cdn_provider'):
            st.info(f"☁️ **CDN-hosted** ({domain_data['cdn_provider']}) — Origin server hidden behind CDN proxy. No abuse indicators detected.")


def admin_view():
    """Admin interface for configuring scoring weights."""
    st.title("🔧 Admin Configuration")
    
    # Simple password protection
    if not st.session_state.admin_authenticated:
        st.warning("⚠️ Admin access required")
        password = st.text_input("Enter admin password", type="password")
        admin_password = st.session_state.config.get('admin_password', 'Doma!nHe5lThOS')
        
        if st.button("Login"):
            if password == admin_password:
                st.session_state.admin_authenticated = True
                st.rerun()
            else:
                st.error("Incorrect password")
        
        st.info("Default password: `*********` (change this in config!)")
        return
    
    # Admin is authenticated
    st.success("✅ Authenticated as Admin")
    
    if st.button("🚪 Logout"):
        st.session_state.admin_authenticated = False
        st.rerun()
    
    st.markdown("---")
    
    config = st.session_state.config
    
    # Tabs for different config sections
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(["⚖️ Scoring Weights", "📖 Signal Reference", "📐 Rules Engine", "🎯 Thresholds", "📋 Lists", "💾 Import/Export"])
    
    with tab1:
        st.header("⚖️ Scoring Weights")
        st.markdown("Adjust the risk points added for each signal. Higher = more risky.")
        
        weights = config.get('weights', {})
        
        # Group weights by category
        categories = {
            "Email Authentication": ['no_spf', 'spf_pass_all', 'spf_neutral_all', 'no_dkim', 'no_dmarc', 
                                     'dmarc_p_none', 'no_mx', 'null_mx', 'no_ptr', 'ptr_mismatch'],
            "Blacklists": ['domain_blacklisted', 'ip_blacklisted'],
            "Domain Age": ['domain_lt_7d', 'domain_lt_30d', 'domain_lt_90d'],
            "Domain Type": ['suspicious_tld', 'free_email_domain', 'disposable_email', 
                           'typosquat_detected', 'free_hosting'],
            "Web/TLS": ['no_https', 'tls_handshake_failed', 'tls_connection_failed',
                       'cert_expired', 'cert_self_signed', 'redirect_chain_2plus',
                       'redirect_cross_domain', 'redirect_temp_302_307'],
            "Content/Phishing": ['credential_form', 'brand_impersonation', 'phishing_paths',
                                'malware_links', 'minimal_shell', 'js_redirect',
                                'phishing_kit_filename_strong', 'phishing_kit_detected', 'exfil_drop_script',
                                'form_action_kit_strong', 'suspicious_page_title', 'whois_privacy',
                                'client_side_harvest_combo', 'oauth_phish', 'registrar_high_risk'],
            "DNS Infrastructure Abuse": ['redirect_arpa_abuse', 'content_arpa_links'],
            "Referral Fraud": ['viral_loops_script'],
            "Domain Name Patterns": ['suspicious_prefix', 'suspicious_suffix', 
                                     'tech_support_tld', 'domain_brand_impersonation',
                                     'brand_spoofing_keyword',
                                     'tld_variant_spoofing', 'tld_variant_uk_no_dns', 'homoglyph_domain'],
            "Hosting Provider": ['hosting_budget_shared', 'hosting_free', 'hosting_suspect',
                                 'cdn_tunnel_suspect'],
            "Nameserver Risk": ['ns_dynamic_dns', 'ns_parking', 'ns_lame_delegation', 'ns_free_dns', 'ns_single_ns'],
            "Bonuses (Reduce Score)": ['has_bimi', 'has_mta_sts', 'security_tooling'],
            "VirusTotal": ['vt_malicious_high', 'vt_malicious_medium', 'vt_malicious_low',
                          'vt_suspicious', 'vt_suspicious_low', 'vt_negative_community', 'vt_clean'],
            "Hacklink / SEO Spam": ['hacklink_detected', 'hacklink_keywords', 'hacklink_wp_compromised',
                                    'hacklink_vulnerable_plugins', 'hacklink_spam_links',
                                    'hacklink_campaign_profile'],
            "Malicious Script / Hidden Injection": ['malicious_script', 'hidden_injection', 'cpanel_detected'],
            "Content Identity": ['content_title_mismatch', 'content_cross_domain_email',
                                'content_broker_page', 'content_privacy_email', 'content_placeholder',
                                'content_facade', 'registration_opaque', 'registration_opaque_with_risk',
                                'domain_reregistered_recent', 'domain_reregistered_recent_with_risk',
                                'domain_reregistered_with_risk'],
            "Transfer Lock / Domain Takeover": ['transfer_lock_recent', 'whois_recently_updated',
                                                    'mx_hijack_high', 'mx_hijack_medium',
                                                    'subdomain_delegation_high', 'subdomain_delegation_medium'],
            "Empty Page / Cert Transparency": ['empty_page', 'ct_recent_issuance', 'ct_no_history',
                                                'ct_reactivated', 'ct_gap_large', 'ct_cert_tls_dead',
                                                'ct_cert_tls_dead_young', 'quishing_profile'],
        }
        
        new_weights = {}
        
        for category, signals in categories.items():
            with st.expander(f"**{category}**", expanded=(category in ["Malicious Script / Hidden Injection", "Transfer Lock / Domain Takeover"])):
                cols = st.columns(2)
                for i, signal in enumerate(signals):
                    with cols[i % 2]:
                        current = weights.get(signal, 0)
                        new_val = st.number_input(
                            signal.replace('_', ' ').title(),
                            min_value=-50,
                            max_value=100,
                            value=current,
                            step=1,
                            key=f"weight_{signal}",
                            help=f"Default: {DEFAULT_CONFIG['weights'].get(signal, 0)}"
                        )
                        new_weights[signal] = new_val
        
        # Merge and persist
        merged_weights = {**weights, **new_weights}
        config['weights'] = merged_weights
        
        # Detect changes and show save button
        has_changes = any(
            merged_weights.get(s, 0) != DEFAULT_CONFIG['weights'].get(s, 0)
            for s in new_weights
        )
        
        st.markdown("---")
        col_save, col_reset = st.columns(2)
        with col_save:
            if st.button("💾 Save Weight Changes", type="primary", key="save_weights"):
                save_config(config)
                st.success("✅ Weights saved to disk!")
        with col_reset:
            if st.button("🔄 Reset to Defaults", key="reset_weights"):
                config['weights'] = copy.deepcopy(DEFAULT_CONFIG['weights'])
                save_config(config)
                st.success("✅ Weights reset to defaults and saved!")
                st.rerun()
        
        if has_changes:
            st.info("⚠️ You have unsaved weight changes. Click **Save Weight Changes** to persist.")
    
    with tab2:
        st.header("📖 Signal Reference")
        st.caption("Read-only reference of all signals the analyzer can detect. "
                   "Use these signal names when creating or editing rules in the Rules Engine tab.")
        
        signal_groups = {
            "Email Authentication": {
                "no_spf": "No SPF record found — cannot verify authorized senders",
                "no_dkim": "No DKIM record — missing cryptographic email signature",
                "no_dmarc": "No DMARC policy — no spoofing protection framework",
                "spf_pass_all": "SPF +all — allows anyone to send as this domain (spoofable)",
                "spf_softfail_all": "SPF ~all — soft enforcement, common but weak",
                "spf_neutral_all": "SPF ?all — provides zero protection",
                "dmarc_p_none": "DMARC policy=none — monitoring only, no enforcement",
                "dmarc_no_rua": "DMARC has no rua= tag — cannot monitor authentication failures",
                "spf_no_external_includes": "SPF has no external includes — no third-party email service configured",
            },
            "MX / Mail Server": {
                "no_mx": "No MX records — domain cannot receive email",
                "null_mx": "Null MX record — domain explicitly refuses email",
                "mx_enterprise": "Enterprise MX provider (Google, Microsoft, etc.) — trusted",
                "mx_disposable": "Disposable/temporary MX provider — commonly used for spam",
                "mx_selfhosted": "Self-hosted MX — mail server on own domain, no external oversight",
                "mx_mail_prefix": "MX is mail.{domain} — common phishing infrastructure template pattern",
                "mx_hijack_high": "MX hijack fingerprint (HIGH) — SPF/DKIM ghosts enterprise provider but MX changed to self-hosted/budget; strong domain compromise indicator",
                "mx_hijack_medium": "MX provider mismatch (MEDIUM) — SPF references enterprise provider but MX doesn't match; possible hijack or stale migration",
                "mx_hijack_low": "MX provider mismatch (LOW) — DKIM-only ghost detected; likely residual from legitimate migration (informational, 0 points)",
            },
            "DNS": {
                "no_ptr": "No PTR (reverse DNS) record — enterprise filters may reject",
                "ptr_mismatch": "PTR doesn't match forward DNS — triggers spam filters",
            },
            "Subdomain Delegation": {
                "subdomain_delegation_high": "Subdomain delegation abuse (HIGH) — subdomain points to completely different ASN/IP/MX than parent domain; strong indicator of DNS compromise",
                "subdomain_delegation_medium": "Subdomain infrastructure divergence (MEDIUM) — partial infrastructure mismatch between subdomain and parent",
                "subdomain_delegation_low": "Subdomain infrastructure divergence (LOW) — minor difference from parent (informational, 0 points)",
            },
            "Certificate Transparency": {
                "ct_recent_issuance": "SSL certificate issued within last 7 days — new deployment or reactivation",
                "ct_no_history": "Zero certificates found in CT logs — domain may never have been used for HTTPS",
                "ct_reactivated": "Aged domain with long CT gap (6+ months) then recent cert — likely purchased from auction/expiry",
                "ct_gap_large": "CT gap ≥12 months without reactivation — domain was inactive for extended period",
                "ct_cert_tls_dead": "Certificate issued within 90 days (via CT logs) but TLS now refuses connections or fails handshake — infrastructure disrupted since cert issuance; strong compromise/disruption indicator on established domains",
                "ct_cert_tls_dead_young": "Same as ct_cert_tls_dead but for domains 30–364 days old (lower weight)",
            },
            "OAuth / Consent Phishing": {
                "oauth_phish": "Page contains outbound links to Microsoft/Google OAuth authorization endpoints with suspicious parameters (response_type=code, redirect_uri, excessive scopes). Attacker tricks users into granting malicious app permissions instead of harvesting passwords directly.",
            },
            "Homoglyph / IDN Spoofing": {
                "homoglyph_domain": "Domain uses Unicode/IDN homoglyphs (Cyrillic а, Greek ο, etc.) to visually impersonate a protected brand. The punycode (xn--) representation decodes to characters that look identical to Latin letters in most fonts.",
            },
            "QR Code Phishing (Quishing)": {
                "quishing_profile": "Domain matches the behavioral fingerprint of a QR code phishing landing page: quishing-associated TLD (.page, .link, .click), minimal content, new domain, no CT history, and/or credential form or OAuth phish endpoint.",
            },
            "CDN Tunnel Abuse": {
                "cdn_tunnel_suspect": "Domain resolves to CDN/proxy provider IPs (Cloudflare, Fastly, etc.) but shows suspicious signals: new domain, no CT history, minimal content, or credential forms. The CDN's universal SSL cert masks the hidden attacker-controlled origin server.",
            },
            "Trust & Authentication": {
                "has_bimi": "BIMI record present — brand logo authentication (high trust)",
                "has_mta_sts": "MTA-STS configured — enforces encrypted email transport",
                "security_tooling": "Security tooling detected on page (reCAPTCHA, Cloudflare Bot Management, hCaptcha, Akamai, DataDome, PerimeterX) — legitimate sites invest in bot protection; phishing kits almost never implement these",
            },
            "App Store Presence": {
                "app_store_high": "Found in major app store with high confidence — strong legitimacy signal",
                "app_store_medium": "Found in app store with medium confidence",
                "app_store_low": "Found in app store with low confidence",
                "app_store_platform_false_positive": "App store match is likely a platform false positive",
            },
            "Blacklists": {
                "domain_blacklisted": "Domain appears on email/DNS blacklists",
                "ip_blacklisted": "IP address appears on blacklists",
            },
            "Domain Age": {
                "domain_lt_7d": "Domain registered less than 7 days ago",
                "domain_lt_30d": "Domain registered less than 30 days ago",
                "domain_lt_90d": "Domain registered less than 90 days ago",
                "domain_gt_1yr": "Domain registered more than 1 year ago — established",
            },
            "Domain Type": {
                "suspicious_tld": "High-abuse TLD (.xyz, .top, .click, etc.)",
                "free_email_domain": "Free consumer email provider domain (gmail.com, etc.)",
                "disposable_email": "Disposable/temporary email domain",
                "typosquat_detected": "Domain appears to be a typosquat of a known brand",
                "free_hosting": "Domain on a free hosting provider",
            },
            "Hosting Provider": {
                "hosting_budget_shared": "Budget shared hosting — commonly used for spam/phishing",
                "hosting_free": "Free hosting — associated with throwaway sites",
                "hosting_suspect": "Suspect/bulletproof hosting — abuse-tolerant provider",
                "hosting_platform": "Developer platform hosting (Render, Vercel, etc.) — free tier abuse risk",
            },
            "Domain Name Patterns": {
                "suspicious_prefix": "Domain starts with suspicious prefix (secure-, login-, verify-, etc.)",
                "suspicious_suffix": "Domain ends with suspicious suffix (-support, -account, etc.)",
                "is_tech_support_tld": "Tech support scam TLD (.support, .tech, .help)",
                "domain_brand_impersonation": "Domain name impersonates a known brand",
                "brand_spoofing_keyword": "Brand spoofing keyword detected in domain",
                "brand_impersonation": "Brand impersonation detected via content analysis",
            },
            "TLD Variant": {
                "tld_variant_spoofing": "Established business exists at a variant TLD — potential impersonation",
                "tld_variant_uk_no_dns": "UK business TLD variant (.co.uk) has no DNS — domain operating on alternate TLD while .co.uk is dark. Only scored on established domains (90+ days); suppressed on new domains where .co.uk simply hasn't been registered yet",
            },
            "Web / TLS": {
                "no_https": "No valid HTTPS — may indicate abandoned or suspicious domain",
                "tls_handshake_failed": "TLS handshake failed — broken SSL config or evasion",
                "tls_connection_failed": "Cannot reach port 443 — no HTTPS service running",
                "cert_expired": "TLS certificate has expired",
                "cert_self_signed": "Self-signed TLS certificate",
            },
            "Redirects": {
                "redirect_chain_2plus": "Redirect chain with 2+ hops — may trigger phishing detection",
                "redirect_cross_domain": "Redirects to a different domain — suspicious pattern",
                "redirect_temp_302_307": "Uses temporary redirects (302/307) — suggests URL cloaking",
            },
            "HTTP Status Codes": {
                "status_401_unauthorized": "Returns 401 — public domain requires authentication",
                "status_403_cloaking": "Returns 403 — likely WAF/bot protection (logged, not scored)",
                "status_429_throttling": "Returns 429 — throttling automated checks",
                "status_503_disposable": "Returns 503 — disposable/intermittent infrastructure",
            },
            "Content Analysis": {
                "minimal_shell": "Minimal/shell website — common phishing indicator",
                "js_redirect": "JavaScript redirect — suspicious redirect technique",
                "meta_refresh": "Meta refresh redirect — often used for cloaking",
                "has_external_js": "External JavaScript loader — content from external source",
                "missing_trust_signals": "No corporate pages (/about, /contact, /privacy)",
                "access_restricted": "Access blocked — cannot fully analyze site content",
                "opaque_entity": "Access blocked AND no corporate pages — high B2B fraud risk",
                "parking_page": "Domain shows a parking/placeholder page — not actively used",
                "credential_form": "Login/credential form detected on landing page",
            },
            "Scam / Phishing Patterns": {
                "hijack_path_pattern": "Suspicious URL path pattern common in hijacked domains",
                "doc_sharing_lure": "Document sharing lure (fake OneDrive, Google Docs, etc.)",
                "phishing_js_behavior": "Suspicious JavaScript patterns matching phishing kits",
                "phishing_infra_redirect": "Redirects to known phishing infrastructure",
                "email_tracking_url": "Email/victim tracking URL parameters detected",
                "phishing_paths": "Known phishing URL paths detected",
            },
            "Phishing Kit Detection": {
                "phishing_kit_filename_strong": "URL ends with high-confidence kit filename (gate.php, process.php, submit.php, index2.php) — almost never legitimate",
                "phishing_kit_filename_weak": "URL ends with kit-common filename (login.php, verify.php) — only scored with a second corroborating signal",
                "form_action_kit_strong": "Form posts to strong kit filename (e.g., <form action='gate.php'>) — most common phishing kit signature",
                "form_action_kit_weak": "Form posts to weak kit filename (e.g., <form action='login.php'>) — only fires with combo corroboration",
                "exfil_drop_script": "Credential exfiltration code in page source (Telegram bot tokens, Discord webhooks, base64 payloads, hardcoded email recipients, cross-domain JS fetch/XHR)",
                "suspicious_page_title": "Page title matches phishing lure pattern (e.g., 'Verify Your Identity', 'Account Suspended', 'Secure Document Portal')",
                "phishing_kit_detected": "Composite: multiple phishing kit indicators confirmed — live kit running on this domain",
                "client_side_harvest_combo": "Client-side credential harvesting code (input value reads, keyloggers, sendBeacon, image pixel exfil, cookie theft, FormData send) corroborated by another phishing indicator (weak kit filename, credential form, brand impersonation, suspicious page title, phishing paths, etc.)",
                "whois_privacy": "WHOIS registrant uses privacy/proxy service — very common, only scored in combos with young domain + phishing infrastructure",
                "registrar_high_risk": "Registrar known for lax verification and disproportionate abuse volume — weighted by domain age (new domains penalized more)",
            },
            "DNS Infrastructure Abuse": {
                "redirect_arpa_abuse": ".arpa hostname found in HTTP redirect chain — reverse DNS namespace weaponized for phishing delivery (Infoblox Feb 2026); near-zero false positive rate",
                "content_arpa_links": "Page contains links or scripts pointing to .arpa reverse DNS hostnames — phishing infrastructure indicator; .arpa is reserved for DNS operations, not web hosting",
            },
            "Referral Fraud": {
                "viral_loops_script": "app.viral-loops.com script detected — referral/giveaway widget heavily abused in fake prize campaigns and spam referral schemes",
            },
            "Nameserver Risk": {
                "ns_dynamic_dns": "Domain delegated to dynamic DNS provider (noip, dyndns, duckdns) — almost exclusively phishing/malware",
                "ns_parking": "Domain delegated to parking nameserver (sedoparking, bodis, afternic) — parked or for-sale domain",
                "ns_lame_delegation": "Zero NS records found — broken or abandoned domain with no functioning DNS",
                "ns_free_dns": "Free/anonymous authoritative DNS — minimal infrastructure investment; unusual for business senders",
                "ns_single_ns": "Only 1 NS record — fragile or hastily configured; legitimate domains use 2-4 NS",
            },
            "E-commerce": {
                "retail_scam_tld": ".shop/.store TLD — heavily abused for fake stores",
                "cross_domain_brand_link": "Links to same brand on different TLD — clone store pattern",
                "ecommerce_no_identity": "E-commerce site without business identity information",
            },
            "VirusTotal": {
                "vt_malicious_high": "5+ VT vendors flagged domain as malicious — high confidence threat",
                "vt_malicious_medium": "3-4 VT vendors flagged as malicious — medium confidence",
                "vt_malicious_low": "1-2 VT vendors flagged as malicious — low confidence, may be false positive",
                "vt_suspicious": "3+ VT vendors flagged as suspicious",
                "vt_suspicious_low": "1-2 VT vendors flagged as suspicious",
                "vt_negative_community": "Negative VT community score (<0) — crowdsourced bad reputation",
                "vt_clean": "50+ VT vendors report clean — bonus that reduces score",
            },
            "Hacklink / SEO Spam": {
                "hacklink_detected": "Hacklink SEO spam injection confirmed — multiple indicators present",
                "hacklink_keywords": "Hacklink keywords present in page content (casino, viagra, bahis, etc.)",
                "hacklink_wp_compromised": "WordPress compromise indicators (injected PHP, malicious plugins, backdoors)",
                "hacklink_vulnerable_plugins": "Known-exploitable WordPress plugins detected on site",
                "hacklink_spam_links": "5+ hidden outbound spam links injected into page content",
                "hacklink_campaign_profile": "Composite: domain matches hacklink target infrastructure fingerprint (2+ of: empty_page, uk_variant_dark, weak_email_auth, hidden_injection, cpanel). Only fires on domains 90+ days old — new domains with empty pages are normal setup behavior",
            },
            "Malicious Script / Hidden Injection": {
                "malicious_script": "SocGholish/FakeUpdates-style obfuscated script injection detected — domain is actively compromised and serving malware to visitors",
                "hidden_injection": "CSS-cloaked hidden content injection (display:none, font-size:0, text-indent:-9999px) with embedded links — the #1 fingerprint of hacklink SEO spam campaigns",
                "cpanel_detected": "cPanel shared hosting environment detected — cPanel servers are the #1 target for mass hacklink injection campaigns",
            },
            "Transfer Lock / Domain Takeover": {
                "transfer_lock_recent": "Transfer lock recently added on established domain — possible post-compromise lockdown by owner or registrar",
                "whois_recently_updated": "WHOIS record updated within last 30 days — possible ownership change, transfer, or DNS hijack",
                "domain_gt_1yr": "Domain registered more than 1 year ago — established (used in takeover combos)",
                "mx_hijack_high": "MX hijack fingerprint (HIGH) — SPF/DKIM still references enterprise provider (Google/Microsoft) but MX changed to self-hosted or budget; strong indicator of domain compromise",
                "mx_hijack_medium": "MX provider mismatch (MEDIUM) — SPF references enterprise provider but MX doesn't match; could be hijack or stale migration",
                "subdomain_delegation_high": "Subdomain delegation abuse (HIGH) — subdomain's IP/ASN/MX completely diverges from parent domain; strong DNS compromise indicator",
                "subdomain_delegation_medium": "Subdomain infrastructure divergence (MEDIUM) — partial mismatch between subdomain and parent infrastructure",
            },
            "Empty Page": {
                "empty_page": "Reachable domain returns empty or near-empty content (<50 chars) — parked, abandoned, or stripped post-compromise",
            },
            "Certificate Transparency": {
                "ct_recent_issuance": "SSL certificate issued within last 7 days in CT logs — new deployment or reactivation",
                "ct_no_history": "Zero certificates found in Certificate Transparency logs — domain may never have been used for HTTPS",
                "ct_reactivated": "Aged domain with long CT gap (6+ months) then recent cert — likely purchased from auction/expiry to exploit reputation",
                "ct_gap_large": "CT gap ≥12 months — domain had extended period of inactivity in cert logs",
            },
            "OAuth / Consent Phishing": {
                "oauth_phish": "Page contains OAuth authorization endpoint links (Microsoft/Google) — consent phishing bypasses credential form detection",
            },
            "Homoglyph / IDN Spoofing": {
                "homoglyph_domain": "Domain uses Unicode/IDN homoglyphs to visually impersonate a protected brand — Cyrillic а, Greek ο, etc. look identical to Latin in most fonts",
            },
            "QR Code Phishing (Quishing)": {
                "quishing_profile": "Domain matches quishing behavioral fingerprint — minimal content, new domain, phishing TLD, no CT history",
            },
            "CDN Tunnel Abuse": {
                "cdn_tunnel_suspect": "Domain behind CDN proxy with suspicious signals — attacker may use CDN tunnel to hide phishing origin behind reputable IPs",
            },
            "Content Identity": {
                "content_title_mismatch": "Page <title> claims one business but body content shows a completely different business — facade or content cloning",
                "content_cross_domain_email": "Email addresses on page belong to a different domain — strongest indicator of cloned content (e.g., kigs.app showing @topdot.com emails)",
                "content_broker_page": "Page is a domain broker, parking, or for-sale page — 3+ broker phrases detected (domain brokerage, submit inquiry, premium domain, etc.)",
                "content_privacy_email": "Privacy email (Proton, Tutanota) used as business contact on page — legitimate businesses use their own domain email",
                "content_placeholder": "Placeholder or template content detected (lorem ipsum, coming soon, under construction)",
                "content_facade": "SPA shell / content facade — page title claims a business but body has <30 visible words, with content loaded entirely via external JavaScript",
                "registration_opaque": "Both RDAP and WHOIS failed to return domain creation date — registration data hidden or unavailable (standalone, mild signal)",
                "registration_opaque_with_risk": "Registration opaque COMBINED with content risk signals (facade/mismatch/broker) — much higher confidence of suspicious domain",
                "domain_reregistered_recent": "Domain was dropped and re-registered within last 90 days (RDAP reregistration event) — common tactic to buy expired domains for residual reputation",
                "domain_reregistered_recent_with_risk": "Domain re-registered ≤90d ago AND content risk signals present — high confidence expired domain takeover",
                "domain_reregistered_with_risk": "Domain re-registered >90d ago but content risk signals present — moderate expired domain takeover signal",
            },
        }
        
        for group_name, signals in signal_groups.items():
            with st.expander(f"**{group_name}** ({len(signals)} signals)"):
                for signal_name, description in sorted(signals.items()):
                    st.markdown(f"**`{signal_name}`** — {description}")
    
    with tab3:
        st.header("📐 Rules Engine")
        st.caption("All scoring rules grouped by category. Each rule fires when its signal conditions are met, "
                   "adding (or subtracting) its score. Toggle rules on/off, adjust scores, or create new rules.")
        
        rules = config.get('rules', [])
        
        # Group rules by category
        rule_categories = {}
        for idx, rule in enumerate(rules):
            cat = rule.get('category', 'Uncategorized')
            rule_categories.setdefault(cat, []).append((idx, rule))
        
        # Define category display order and icons
        cat_icons = {
            'Positive Signals': '✅',
            'Phishing Templates': '🎯',
            'Phishing Kit': '🎣',
            'WHOIS Risk': '🔐',
            'Nameserver Risk': '🔤',
            'Email Auth Weakness': '📧',
            'MX Provider Risk': '📬',
            'Brand Impersonation': '🛡️',
            'TLD Variant Spoofing': '🔀',
            'Fraud / Blacklist': '🚫',
            'Tech Support Scam': '☎️',
            'Hosting Risk': '🖥️',
            'Infrastructure Risk': '🏗️',
            'HTTP Status Evasion': '🔒',
            'Phishing Infrastructure': '🕸️',
            'Phishing Lures': '🪝',
            'Opaque Entity': '👻',
            'General Risk': '⚠️',
            'VirusTotal': '🛡️',
            'Hacklink / SEO Spam': '🕷️',
            'Hacklink Campaign Profile': '🕸️',
            'Malicious Script': '💀',
            'Domain Takeover': '🔓',
            'Content Identity': '🔍',
            'Security Tooling': '🛡️',
        }
        
        # Show positive signals first, then phishing templates, then rest alphabetically
        priority_order = ['Positive Signals', 'Phishing Templates']
        sorted_cats = priority_order + [c for c in sorted(rule_categories.keys()) if c not in priority_order]
        
        for cat_name in sorted_cats:
            if cat_name not in rule_categories:
                continue
            cat_rules = rule_categories[cat_name]
            icon = cat_icons.get(cat_name, '📋')
            
            # Count enabled/disabled
            enabled_count = sum(1 for _, r in cat_rules if r.get('enabled', True))
            disabled_count = len(cat_rules) - enabled_count
            
            header = f"{icon} **{cat_name}** — {enabled_count} active"
            if disabled_count > 0:
                header += f", {disabled_count} disabled"
            header += f" ({len(cat_rules)} total)"
            
            # Phishing Templates expanded by default
            is_priority = cat_name in priority_order
            
            with st.expander(header, expanded=is_priority):
                # Bulk controls
                bulk_col1, bulk_col2, bulk_col3 = st.columns([1, 1, 2])
                with bulk_col1:
                    if st.button(f"✅ Enable all", key=f"enable_all_{cat_name}"):
                        for rule_idx, r in cat_rules:
                            r['enabled'] = True
                            # Sync Streamlit widget state so toggles reflect the change
                            st.session_state[f"rule_toggle_{rule_idx}"] = True
                        save_config(config)
                        st.rerun()
                with bulk_col2:
                    if st.button(f"⛔ Disable all", key=f"disable_all_{cat_name}"):
                        for rule_idx, r in cat_rules:
                            r['enabled'] = False
                            # Sync Streamlit widget state so toggles reflect the change
                            st.session_state[f"rule_toggle_{rule_idx}"] = False
                        save_config(config)
                        st.rerun()
                
                st.markdown("---")
                
                for idx, rule in cat_rules:
                    rule_name = rule.get('name', f'rule_{idx}')
                    rule_score = rule.get('score', 0)
                    rule_enabled = rule.get('enabled', True)
                    rule_label = rule.get('label', '')
                    
                    # Main row: toggle + name + score
                    toggle_col, name_col, score_col = st.columns([0.4, 2.5, 1])
                    
                    with toggle_col:
                        new_enabled = st.toggle(
                            "on",
                            value=rule_enabled,
                            key=f"rule_toggle_{idx}",
                            label_visibility="collapsed",
                        )
                        rule['enabled'] = new_enabled
                    
                    with name_col:
                        status = "✅" if new_enabled else "⛔"
                        if new_enabled:
                            st.markdown(f"{status} **`{rule_name}`**")
                        else:
                            st.markdown(f"{status} ~~`{rule_name}`~~ *(disabled)*")
                        if rule_label:
                            st.caption(rule_label)
                    
                    with score_col:
                        new_score = st.number_input(
                            "pts",
                            min_value=-50,
                            max_value=100,
                            value=rule_score,
                            step=1,
                            key=f"rule_score_{idx}",
                            label_visibility="collapsed",
                            disabled=not new_enabled,
                        )
                        rule['score'] = new_score
                    
                    # Expandable conditions editor
                    with st.expander(f"Edit conditions: {rule_name}", expanded=False):
                        rule['label'] = st.text_input(
                            "Label", value=rule_label, key=f"rule_label_{idx}",
                        )
                        
                        new_cat = st.selectbox(
                            "Category",
                            options=sorted(cat_icons.keys()),
                            index=sorted(cat_icons.keys()).index(cat_name) if cat_name in cat_icons else 0,
                            key=f"rule_cat_{idx}",
                        )
                        rule['category'] = new_cat
                        
                        c1, c2, c3 = st.columns(3)
                        with c1:
                            if_all_str = st.text_area(
                                "if_all (ALL must match)",
                                value='\n'.join(rule.get('if_all', [])),
                                height=80, key=f"rule_if_all_{idx}",
                            )
                            rule['if_all'] = [s.strip() for s in if_all_str.splitlines() if s.strip()]
                        with c2:
                            if_any_str = st.text_area(
                                "if_any (AT LEAST ONE)",
                                value='\n'.join(rule.get('if_any', [])),
                                height=80, key=f"rule_if_any_{idx}",
                            )
                            rule['if_any'] = [s.strip() for s in if_any_str.splitlines() if s.strip()]
                        with c3:
                            if_not_str = st.text_area(
                                "if_not (NONE may match)",
                                value='\n'.join(rule.get('if_not', [])),
                                height=80, key=f"rule_if_not_{idx}",
                            )
                            rule['if_not'] = [s.strip() for s in if_not_str.splitlines() if s.strip()]
        
        # Add new rule
        st.markdown("---")
        st.subheader("➕ Add New Rule")
        
        with st.form("new_rule_form"):
            new_name = st.text_input("Rule name (unique, no spaces)", placeholder="my_new_rule")
            new_rule_label = st.text_input("Label", placeholder="What this rule detects")
            
            nr_col1, nr_col2 = st.columns(2)
            with nr_col1:
                new_rule_score = st.number_input("Score", min_value=-50, max_value=100, value=10, step=1)
            with nr_col2:
                new_rule_cat = st.selectbox("Category", options=sorted(cat_icons.keys()), index=0, key="new_rule_cat")
            
            nr_c1, nr_c2, nr_c3 = st.columns(3)
            with nr_c1:
                new_if_all = st.text_area("if_all (one per line)", height=80, key="new_rule_if_all")
            with nr_c2:
                new_if_any = st.text_area("if_any (one per line)", height=80, key="new_rule_if_any")
            with nr_c3:
                new_if_not = st.text_area("if_not (one per line)", height=80, key="new_rule_if_not")
            
            submitted = st.form_submit_button("Add Rule")
            if submitted and new_name:
                existing_names = [r.get('name', '') for r in rules]
                if new_name in existing_names:
                    st.error(f"Rule name '{new_name}' already exists.")
                else:
                    rules.append({
                        'name': new_name.strip().replace(' ', '_'),
                        'score': new_rule_score,
                        'label': new_rule_label,
                        'category': new_rule_cat,
                        'enabled': True,
                        'if_all': [s.strip() for s in new_if_all.splitlines() if s.strip()],
                        'if_any': [s.strip() for s in new_if_any.splitlines() if s.strip()],
                        'if_not': [s.strip() for s in new_if_not.splitlines() if s.strip()],
                    })
                    st.success(f"Rule '{new_name}' added! Click **Save Configuration** to persist.")
        
        config['rules'] = rules

    
    with tab4:
        st.header("🎯 Thresholds & Settings")
        
        col1, col2 = st.columns(2)
        
        with col1:
            config['approve_threshold'] = st.slider(
                "Approval Threshold",
                min_value=0,
                max_value=100,
                value=config.get('approve_threshold', 50),
                help="Scores at or below this value = APPROVE"
            )
            
            config['timeout'] = st.number_input(
                "Request Timeout (seconds)",
                min_value=1.0,
                max_value=60.0,
                value=config.get('timeout', 10.0),
                step=1.0
            )
        
        with col2:
            config['check_rdap'] = st.checkbox(
                "Enable RDAP (Domain Age) Lookup",
                value=config.get('check_rdap', True)
            )
            
            new_password = st.text_input(
                "Change Admin Password",
                type="password",
                help="Leave blank to keep current"
            )
            if new_password:
                config['admin_password'] = new_password
    
    with tab5:
        st.header("📋 Pattern Lists")
        
        st.subheader("Suspicious TLDs")
        suspicious_tlds = st.text_area(
            "One per line (include the dot)",
            value='\n'.join(config.get('suspicious_tlds', [])),
            height=150
        )
        config['suspicious_tlds'] = [t.strip() for t in suspicious_tlds.splitlines() if t.strip()]
        
        st.subheader("Protected Brands (for typosquatting)")
        protected_brands = st.text_area(
            "One per line",
            value='\n'.join(config.get('protected_brands', [])),
            height=150
        )
        config['protected_brands'] = [b.strip().lower() for b in protected_brands.splitlines() if b.strip()]
        
        st.markdown("---")
        st.subheader("🛡️ Allow Lists")
        st.caption("Domains cleared by admin review. Suppresses the specific signal only — all other scoring still applies.")
        
        col_al1, col_al2 = st.columns(2)
        
        with col_al1:
            st.markdown("**TLD Variant Allowlist**")
            st.caption("Suppress TLD variant spoofing for these domains. Use when a legitimate business operates on a non-.com TLD.")
            tld_variant_al = st.text_area(
                "One domain per line",
                value='\n'.join(config.get('tld_variant_allowlist', [])),
                height=120,
                key="tld_variant_allowlist_input"
            )
            config['tld_variant_allowlist'] = [d.strip().lower() for d in tld_variant_al.splitlines() if d.strip()]
        
        with col_al2:
            st.markdown("**Spoofing Allowlist**")
            st.caption("Suppress typosquat, brand impersonation, brand+keyword, and suspicious prefix/suffix for these domains.")
            spoofing_al = st.text_area(
                "One domain per line",
                value='\n'.join(config.get('spoofing_allowlist', [])),
                height=120,
                key="spoofing_allowlist_input"
            )
            config['spoofing_allowlist'] = [d.strip().lower() for d in spoofing_al.splitlines() if d.strip()]
    
    with tab6:
        st.header("💾 Import/Export Configuration")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Export")
            config_json = json.dumps(config, indent=2)
            st.download_button(
                "📥 Download Config JSON",
                data=config_json,
                file_name="domain_approval_config.json",
                mime="application/json"
            )
        
        with col2:
            st.subheader("Import")
            uploaded_config = st.file_uploader("Upload Config JSON", type=['json'])
            if uploaded_config:
                try:
                    imported = json.loads(uploaded_config.read())
                    if st.button("Apply Imported Config"):
                        st.session_state.config = imported
                        save_config(imported)
                        st.success("Config imported!")
                        st.rerun()
                except Exception as e:
                    st.error(f"Invalid config file: {e}")
        
        st.markdown("---")
        
        if st.button("🔄 Reset to Defaults"):
            st.session_state.config = copy.deepcopy(DEFAULT_CONFIG)
            save_config(copy.deepcopy(DEFAULT_CONFIG))
            st.success("Reset to defaults!")
            st.rerun()
    
    # Save button
    st.markdown("---")
    col1, col2, col3 = st.columns([1, 1, 2])
    with col1:
        if st.button("💾 Save Configuration", type="primary"):
            save_config(config)
            st.session_state.config = config
            st.success("✅ Configuration saved!")


def main():
    """Main app entry point."""
    init_session_state()
    
    # Navigation
    st.sidebar.title("Navigation")
    page = st.sidebar.radio(
        "Select Page",
        ["🔍 Analyze Domains", "🔧 Admin Config"],
        label_visibility="collapsed"
    )
    
    if page == "🔍 Analyze Domains":
        user_view()
    else:
        admin_view()
    
    # Footer
    st.sidebar.markdown("---")
    st.sidebar.caption(f"Domain Sender Approval v4.0 | Analyzer v{ANALYZER_VERSION}")
    st.sidebar.caption(f"Threshold: {st.session_state.config.get('approve_threshold', 50)}")


if __name__ == "__main__":
    main()
