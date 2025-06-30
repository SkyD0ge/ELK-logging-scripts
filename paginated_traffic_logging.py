from datetime import datetime, timedelta
import pytz
import requests
import os
import smtplib
from dotenv import load_dotenv
from urllib.parse import urlparse
from email.message import EmailMessage
from collections import defaultdict, Counter
from opensearchpy import OpenSearch, RequestsHttpConnection

load_dotenv()
# pulling credentials from .env file
SES_SMTP_USERNAME = os.getenv("SES_SMTP_USERNAME")
SES_SMTP_PASSWORD = os.getenv("SES_SMTP_PASSWORD")

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
INDEX_ACCESS = os.getenv("INDEX_ACCESS")
INDEX_PHP_ERRORS = os.getenv("INDEX_PHP_ERRORS")

EMAIL_SETTINGS = {
    "sender": os.getenv("EMAIL_SENDER"),
    "recipient": os.getenv("EMAIL_RECIPIENT"),
    "cc": os.getenv("EMAIL_CC", ""),
    "smtp_server": os.getenv("SMTP_SERVER"),
    "smtp_port": int(os.getenv("SMTP_PORT")),
    "username": os.getenv("SES_SMTP_USERNAME"),
    "password": os.getenv("SES_SMTP_PASSWORD")
}

EXCLUDED_USER_AGENTS = [
    # add useragents here to filter them out
    "Amazon CloudFront",
    "GoogleAssociationService",
    "Ubuy",
    "Mozilla",
    "okhttp"
]

def new_connection():
    host = os.getenv("OPENSEARCH_HOST")
    port = int(os.getenv("OPENSEARCH_PORT", 443))
    username = os.getenv("OPENSEARCH_USERNAME")
    password = os.getenv("OPENSEARCH_PASSWORD")

    return OpenSearch(
        hosts=[f"{host}:{port}"],
        http_auth=(username, password),
        use_ssl=True,
        verify_certs=True,
        connection_class=RequestsHttpConnection,
        timeout=60,
        max_retries=3,
        retry_on_timeout=True
    )

# formatting time to IST
def format_timestamp_with_ms(dt):
    return dt.strftime("%b %d, %Y @ %H:%M:%S.") + f"{dt.microsecond // 1000:03d}"

# total hit count
def get_hit_count(index_name, start_utc, end_utc, tag=None):
    must_clause = [{"range": {"@timestamp": {"gte": start_utc.isoformat(), "lte": end_utc.isoformat()}}}]
    if tag:
        must_clause.append({"term": {"tags.keyword": tag}})
    query = {"size": 0, "track_total_hits": True, "query": {"bool": {"must": must_clause}}}
    try:
        result = new_connection().search(index=index_name, body=query)
        return result["hits"]["total"]["value"]
    except Exception as e:
        print(f"Error getting count: {e}")
        return 0

# PHP incident count
def get_php_error_summary(start_utc, end_utc):
    connection = new_connection()
    total = 0
    counts = defaultdict(int)
    query = {
        "query": {"range": {"@timestamp": {"gte": start_utc.isoformat(), "lte": end_utc.isoformat()}}},
        "_source": ["message"]
    }
    scroll = connection.search(index=INDEX_PHP_ERRORS, body=query, scroll="2m", size=1000)
    scroll_id = scroll["_scroll_id"]
    hits = scroll["hits"]["hits"]
    while hits:
        for doc in hits:
            msg = doc["_source"].get("message", "").lower()
            total += 1
            for cat in ["notice", "warning", "deprecated", "fatal"]:
                if cat in msg:
                    counts[cat] += 1
        scroll = connection.scroll(scroll_id=scroll_id, scroll="2m")
        scroll_id = scroll["_scroll_id"]
        hits = scroll["hits"]["hits"]
    return total, counts

# extract domain from message as string
def extract_domain_from_request(request):
    try:
        if not request.startswith(("http://", "https://")):
            request = "http://" + request
        domain = urlparse(request).netloc.lower()
        if domain.startswith("www."):
            domain = domain[4:]
        return domain
    except Exception:
        return None

# assigning tags
def aggregate_fields_by_tag(index_name, start_utc, end_utc, field_name, tag, size=25):
    client = new_connection()

    if field_name == "domain":
        query_template = {
            "size": 10000,
            "_source": ["request"],
            "sort": [
                {"@timestamp": "asc"},
                {"_doc": "asc"}
            ],
            "query": {
                "bool": {
                    "must": [
                        {"term": {"tags.keyword": tag}},
                        {"exists": {"field": "request"}},
                        {"range": {"@timestamp": {
                            "gte": start_utc.isoformat(),
                            "lte": end_utc.isoformat()
                        }}}
                    ]
                }
            }
        }

        domain_counter = Counter()
        search_after = None
        total_docs = 0

        while True:
            if search_after:
                query_template["search_after"] = search_after

            response = client.search(index=index_name, body=query_template)
            hits = response["hits"]["hits"]
            if not hits:
                break

            for doc in hits:
                request = doc["_source"].get("request", "")
                domain = extract_domain_from_request(request)
                if domain:
                    domain_counter[domain] += 1
            total_docs += len(hits)
            if total_docs % 10000 == 0:
                print(f"[SearchAfter] Processed {total_docs} docs...")

            search_after = hits[-1]["sort"]  # Prepare for next page

        print(f"[SearchAfter] Completed: {total_docs} docs")
        top_domains = domain_counter.most_common(size)
        return [{"key": d, "doc_count": c} for d, c in top_domains]

    # default aggression for other fields
    query = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"term": {"tags.keyword": tag}},
                    {"range": {"@timestamp": {"gte": start_utc.isoformat(), "lte": end_utc.isoformat()}}}
                ]
            }
        },
        "aggs": {
            "top_terms": {
                "terms": {
                    "field": field_name,
                    "size": size
                }
            }
        }
    }

    response = client.search(index=index_name, body=query)
    buckets = response.get("aggregations", {}).get("top_terms", {}).get("buckets", [])

    enriched_buckets = []
    for b in buckets:
        entry = {"key": b["key"], "doc_count": b["doc_count"]}
        if field_name == "IP.keyword":
            try:
                doc = client.search(index=index_name, body={
                    "size": 1,
                    "_source": ["geoip.country_name", "geoip.region_code", "geoip_organization.as_org"],
                    "query": {
                        "bool": {
                            "must": [
                                {"term": {"IP.keyword": b["key"]}},
                                {"term": {"tags.keyword": tag}},
                                {"range": {"@timestamp": {"gte": start_utc.isoformat(), "lte": end_utc.isoformat()}}}
                            ]
                        }
                    }
                })
                hit = doc["hits"]["hits"][0]["_source"] if doc["hits"]["hits"] else {}
                region = hit.get("geoip", {}).get("region_code", "")
                country = hit.get("geoip", {}).get("country_name", "N/A")
                entry["country"] = f"{region}/{country}" if region else country
                entry["organization"] = hit.get("geoip_organization", {}).get("as_org", "N/A")


            except Exception as e:
                print(f"Error enriching IP {b['key']}: {e}")
                entry["country"] = "N/A"
                entry["organization"] = "N/A"
        enriched_buckets.append(entry)

    return enriched_buckets

def get_status_codes_for_ips(index_name, start_utc, end_utc, ip_list, tag):
    client = new_connection()
    ip_status_map = {}
    fixed_status_codes = ["200", "410", "301", "302", "499", "404", "403", "502", "204", "203", "400", "401", "500", "501", "304"]

    for ip in ip_list:
        ip_key = ip["key"]
        query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"term": {"tags.keyword": tag}},
                        {"term": {"IP.keyword": ip_key}},
                        {"range": {"@timestamp": {
                            "gte": start_utc.isoformat(),
                            "lte": end_utc.isoformat()
                        }}}
                    ]
                }
            },
            "aggs": {
                "status_codes": {
                    "terms": {
                        "field": "response.keyword",
                        "size": len(fixed_status_codes)
                    }
                }
            }
        }

        try:
            response = client.search(index=index_name, body=query)
            buckets = response.get("aggregations", {}).get("status_codes", {}).get("buckets", [])
            status_dict = {str(bucket["key"]): bucket["doc_count"] for bucket in buckets}
            ip_status_map[ip_key] = {code: status_dict.get(code, 0) for code in fixed_status_codes}
        except Exception:
            ip_status_map[ip_key] = {code: 0 for code in fixed_status_codes}

    return ip_status_map

# complete_table
def generate_combined_html_table(title, user_data, bot_data,
                                 user_heading="User", bot_heading="Bot",
                                 user_count_color=None, bot_count_color=None,
                                 country_color=None, org_color=None):
    table_style = "border: 1px solid #ccc; border-collapse: collapse; width: 100%; margin-bottom: 20px;"
    th_style = "background-color: #f2f2f2; text-align: left; padding: 8px; border: 1px solid #ccc;"
    td_style = "padding: 8px; border: 1px solid #ccc;"

    html = f"<h3>{title}</h3><table style='{table_style}'>"

    # columns
    html += f"<tr><th style='{th_style}'>{user_heading}</th><th style='{th_style}'>User Count</th>"
    if "country" in user_data[0] if user_data else {}:
        html += f"<th style='{th_style}'>Country</th><th style='{th_style}'>Organization</th>"
    html += f"<th style='{th_style}'>{bot_heading}</th><th style='{th_style}'>Bot Count</th></tr>"

    # rows
    max_len = max(len(user_data), len(bot_data))
    for i in range(max_len):
        u = user_data[i] if i < len(user_data) else {}
        b = bot_data[i] if i < len(bot_data) else {}

        user_key = u.get("key", "")
        user_count = u.get("doc_count", "")
        bot_key = b.get("key", "")
        bot_count = b.get("doc_count", "")

        user_count_style = f"{td_style} color:{user_count_color};" if user_count_color else td_style
        bot_count_style = f"{td_style} color:{bot_count_color};" if bot_count_color else td_style
        country_style = f"{td_style} color:{country_color};" if country_color else td_style
        org_style = f"{td_style} color:{org_color};" if org_color else td_style

        html += "<tr>"
        html += f"<td style='{td_style}'>{user_key}</td><td style='{user_count_style}'>{user_count}</td>"

        if "country" in u and "organization" in u:
            html += f"<td style='{country_style}'>{u.get('country', '')}</td>"
            html += f"<td style='{org_style}'>{u.get('organization', '')}</td>"

        html += f"<td style='{td_style}'>{bot_key}</td><td style='{bot_count_style}'>{bot_count}</td>"
        html += "</tr>"

    html += "</table>"
    return html

# useragent table
def generate_user_agent_table(title, user_agents):
    table_style = "border: 1px solid #ccc; border-collapse: collapse; width: 100%; margin-bottom: 20px;"
    th_style = "background-color: #f2f2f2; text-align: left; padding: 8px; border: 1px solid #ccc;"
    td_style = "padding: 8px; border: 1px solid #ccc;"

    html = f"<h3>{title}</h3><table style='{table_style}'>"
    html += f"<tr><th style='{th_style}'>User Agent</th><th style='{th_style}'>User Count</th></tr>"

    for ua in user_agents:
        html += f"<tr><td style='{td_style}'>{ua['key']}</td><td style='{td_style}'>{ua['doc_count']}</td></tr>"

    html += "</table>"
    return html

# table for top ip status codes
def generate_status_code_table(title, ip_status_map):
    fixed_status_codes = ["200", "202", "203", "204","301", "302", "304","400", "401", "403", "404", "410", "499","500", "501", "502"]
    headers = ["IP"] + fixed_status_codes
    table_style = "border: 1px solid #ccc; border-collapse: collapse; width: 100%; margin-bottom: 20px;"
    th_style = "background-color: #f2f2f2; text-align: left; padding: 8px; border: 1px solid #ccc;"
    td_style_base = "padding: 8px; border: 1px solid #ccc;"

    def style_for_code(code):
        try:
            code_int = int(code)
        except ValueError:
            return td_style_base
        if 200 <= code_int <= 299:
            return f"{td_style_base} color: green;"
        elif 400 <= code_int <= 499:
            return f"{td_style_base} color: goldenrod;"
        elif 500 <= code_int <= 599:
            return f"{td_style_base} color: red;"
        return td_style_base

    header_row = "".join(f"<th style='{th_style}'>{h}</th>" for h in headers)
    rows = ""

    for ip, codes in ip_status_map.items():
        row_cells = [f"<td style='{td_style_base}'>{ip}</td>"]
        for code in fixed_status_codes:
            count = codes.get(code, 0)
            cell_style = style_for_code(code)
            row_cells.append(f"<td style='{cell_style}'>{count}</td>")
        rows += f"<tr>{''.join(row_cells)}</tr>"

    return f"<h3>{title}</h3><table style='{table_style}'><tr>{header_row}</tr>{rows}</table>"

# html formatting in email
def generate_html_summary(timestamp_str, total_hits, user_hits, bot_hits, php_total, php_counts, 
                          user_ips, bot_ips, user_domains, bot_domains, user_locations, bot_locations, 
                          user_useragents, ip_status_summary=None):
    import re

    # Colorize Time Range
    match = re.search(r"(.*) @ (\d{2}:\d{2}:\d{2}\.\d{3}) to (.*) @ (\d{2}:\d{2}:\d{2}\.\d{3})", timestamp_str)
    if match:
        date1, time1, date2, time2 = match.groups()
        timestamp_colored = f"<span style='color:goldenrod'>{date1}</span> @ <span style='color:cyan'>{time1}</span> to " \
                            f"<span style='color:goldenrod'>{date2}</span> @ <span style='color:magenta'>{time2}</span> (IST)"
    else:
        timestamp_colored = timestamp_str

    html = f"""
    <html><body style='font-family: Arial, sans-serif;'>
    <h2>Ubuy Traffic Summary</h2>
    <p><strong>Time Range:</strong> {timestamp_colored}</p>

    <h3>Metric Summary</h3>
    <table border="1" cellpadding="5" cellspacing="0" style="border-collapse: collapse;">
        <tr><th style='color:black'>Metric</th><th style='color:black'>Value</th></tr>
        <tr><td>Total Hits</td><td style='color:black'>{total_hits}</td></tr>
        <tr><td>User Hits</td><td style='color:blue'>{user_hits}</td></tr>
        <tr><td>Bot Hits</td><td style='color:orange'>{bot_hits}</td></tr>
    </table>

    <h3>PHP Error Logs</h3>
    <table border="1" cellpadding="5" cellspacing="0" style="border-collapse: collapse;">
        <tr><td style='color:black'>Total</td><td style='color:black'>{php_total}</td></tr>
        <tr><td style='color:darkgray'>Notice</td><td style='color:darkgray'>{php_counts.get('notice', 0)}</td></tr>
        <tr><td style='color:goldenrod'>Warning</td><td style='color:goldenrod'>{php_counts.get('warning', 0)}</td></tr>
        <tr><td style='color:lightgray'>Deprecated</td><td style='color:lightgray'>{php_counts.get('deprecated', 0)}</td></tr>
        <tr><td style='color:red'>Fatal</td><td style='color:red'>{php_counts.get('fatal', 0)}</td></tr>
    </table>
    """
    
    html += generate_combined_html_table("Top 25 IPs", user_ips, bot_ips,
                                         user_heading="<span style='color:blue'>User IP</span>",
                                         bot_heading="<span style='color:orange'>Bot IP</span>",
                                         user_count_color="blue",
                                         bot_count_color="orange",
                                         country_color="magenta",
                                         org_color="cyan")

    if ip_status_summary:
        html += generate_status_code_table("Status Codes per IP", ip_status_summary)
    
    html += generate_combined_html_table("Top 25 Domains", user_domains, bot_domains)

    html += generate_combined_html_table("Top 25 Locations", user_locations, bot_locations,
                                         user_heading="<span style='color:magenta'>User Locations</span>",
                                         bot_heading="<span style='color:cyan'>Bot Locations</span>",
                                         user_count_color="blue",
                                         bot_count_color="black")

    html += generate_user_agent_table("Top 25 User Agents", user_useragents)

    

    html += "</body></html>"
    return html

# send_summary_to_email
def send_summary_to_email(subject, html_body):
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = EMAIL_SETTINGS["sender"]
        msg["To"] = EMAIL_SETTINGS["recipient"]

        # Optional CC
        cc = EMAIL_SETTINGS.get("cc", "")
        if cc:
            cc_list = [email.strip() for email in cc.split(",") if email.strip()]
            msg["Cc"] = ", ".join(cc_list)
        else:
            cc_list = []

        all_recipients = [EMAIL_SETTINGS["recipient"]] + cc_list

        msg.set_content("This email requires an HTML-compatible client.")
        msg.add_alternative(html_body, subtype='html')

        with smtplib.SMTP(EMAIL_SETTINGS["smtp_server"], EMAIL_SETTINGS["smtp_port"]) as server:
            server.starttls()
            server.login(EMAIL_SETTINGS["username"], EMAIL_SETTINGS["password"])
            server.send_message(msg, to_addrs=all_recipients)

        print("HTML email sent successfully.")
    except Exception as e:
        print(f"Email sending failed: {e}")

# push notification to slack
def send_summary_to_slack(title, user_data, bot_data, user_heading="", bot_heading="",
                          timestamp_str=None, total_hits=None, user_hits=None, bot_hits=None,
                          php_total=None, php_counts=None, ip_status_map=None):
    lines = []
    # initial summary block
    if timestamp_str and total_hits is not None and php_total is not None:
        lines.append(f"*{title}*\n```\n"
                     f"Time Range      : {timestamp_str} (IST)\n"
                     f"Total Hits      : {total_hits}\n"
                     f"User Hits       : {user_hits}\n"
                     f"Bot Hits        : {bot_hits}\n\n"
                     f"PHP Error Logs  : {php_total} total\n"
                     f"  Notices        : {php_counts.get('notice', 0)}\n"
                     f"  Warnings       : {php_counts.get('warning', 0)}\n"
                     f"  Deprecated     : {php_counts.get('deprecated', 0)}\n"
                     f"  Fatal Errors   : {php_counts.get('fatal', 0)}\n"
                     f"```")
        return "\n".join(lines)

    is_useragent_table = user_heading == "User Agents" and not bot_data
    is_ip_table = all("country" in d and "organization" in d for d in user_data)

    # table to handle useragent
    if is_useragent_table:
        MAX_UA_LENGTH = 60
        lines.append(f"*{title}*\n```\n{'User Agent':<{MAX_UA_LENGTH}} Count")
        lines.append("-" * (MAX_UA_LENGTH + 6))
        for item in user_data:
            ua = item.get("key", "")[:MAX_UA_LENGTH]
            lines.append(f"{ua.ljust(MAX_UA_LENGTH)} {str(item.get('doc_count', '')).rjust(5)}")
        lines.append("```")
        return "\n".join(lines)

    # handle status codes per IP
    if ip_status_map:
        fixed_status_codes = ["200", "202", "203", "204","301", "302", "304","400", "401", "403", "404", "410", "499","500", "501", "502"]
        header = f"{'IP':<15} " + " ".join(f"{code:<5}" for code in fixed_status_codes)
        lines.append(f"*{title}*\n```\n{header}")
        lines.append("-" * len(header))
        for ip, code_counts in ip_status_map.items():
            row = f"{ip:<15} " + " ".join(f"{str(code_counts.get(code, 0)):<5}" for code in fixed_status_codes)
            lines.append(row)
        lines.append("```")
        return "\n".join(lines)

    if is_ip_table:
        lines.append(f"*{title}*\n```\n{'User IP':<20} {'User Count':<12} {'Region/Country':<20} {'Org':<20} || {'Bot IP':<20} {'Bot Count':<10}")
    else:
        lines.append(f"*{title}*\n```\n{user_heading:<35} {'User Count':<10} || {bot_heading:<35} {'Bot Count':<10}")

    max_len = max(len(user_data), len(bot_data))
    for i in range(max_len):
        u = user_data[i] if i < len(user_data) else {}
        b = bot_data[i] if i < len(bot_data) else {}

        if is_ip_table:
            region_country = f"{u.get('region','')}/{u.get('country','')}" if u.get('country') else ''
            line = f"{u.get('key',''):<20} {u.get('doc_count',''):<12} {region_country:<20} {u.get('organization',''):<20} || {b.get('key',''):<20} {b.get('doc_count',''):<10}"
        else:
            line = f"{u.get('key',''):<35} {u.get('doc_count',''):<10} || {b.get('key',''):<35} {b.get('doc_count',''):<10}"
        lines.append(line)

    lines.append("```")
    return "\n".join(lines)

# combined table
def format_combined_table(title, user_data, bot_data):
    lines = [f"\n{title}:"]
    header = "User Hits".ljust(30) + "Count".ljust(10) + " | Bot Hits".ljust(30) + "Count"
    lines.append(header)
    lines.append("-" * 80)
    max_rows = max(len(user_data), len(bot_data))
    for i in range(max_rows):
        user_row = user_data[i] if i < len(user_data) else {}
        bot_row = bot_data[i] if i < len(bot_data) else {}
        user_key = user_row.get("key", "")
        user_count = user_row.get("doc_count", "")
        bot_key = bot_row.get("key", "")
        bot_count = bot_row.get("doc_count", "")
        line = f"{user_key[:30].ljust(30)} {str(user_count).ljust(10)} | {bot_key[:30].ljust(30)} {bot_count}"
        lines.append(line)
    return "\n".join(lines)

#main
if __name__ == "__main__":
    index = INDEX_ACCESS
    ist = pytz.timezone("Asia/Kolkata")
    now_ist = datetime.now(ist)

    # Round down to last complete 30-min mark and get 2-hour window
    minute = (now_ist.minute // 30) * 30
    rounded_now = now_ist.replace(minute=minute, second=0, microsecond=0)
    end_ist = rounded_now
    start_ist = end_ist - timedelta(hours=2)

    # convert time to UTC
    start_utc = start_ist.astimezone(pytz.utc)
    end_utc = end_ist.astimezone(pytz.utc)
    timestamp_str = format_timestamp_with_ms(start_ist) + " to " + format_timestamp_with_ms(end_ist)

    # summary data
    total_hits = get_hit_count(index, start_utc, end_utc)
    user_hits = get_hit_count(index, start_utc, end_utc, tag="user")
    bot_hits = get_hit_count(index, start_utc, end_utc, tag="bot")
    php_total, php_counts = get_php_error_summary(start_utc, end_utc)

    # aggregations
    user_ips = aggregate_fields_by_tag(index, start_utc, end_utc, "IP.keyword", "user", 25)
    bot_ips = aggregate_fields_by_tag(index, start_utc, end_utc, "IP.keyword", "bot", 25)
    user_domains = aggregate_fields_by_tag(index, start_utc, end_utc, "domain", "user", 25)
    bot_domains = aggregate_fields_by_tag(index, start_utc, end_utc, "domain", "bot", 25)
    user_locations = aggregate_fields_by_tag(index, start_utc, end_utc, "geoip.country_name.keyword", "user", 25)
    bot_locations = aggregate_fields_by_tag(index, start_utc, end_utc, "geoip.country_name.keyword", "bot", 25)

    # useragents
    user_useragents = aggregate_fields_by_tag(index, start_utc, end_utc, "user_agent.keyword", "user", 2000)
    user_useragents = [
        ua for ua in user_useragents
        if not any(ex in ua["key"] for ex in EXCLUDED_USER_AGENTS)
    ][:25]
    
    # status codes of IPs
    user_ip_status = get_status_codes_for_ips(index, start_utc, end_utc, user_ips, "user")
    bot_ip_status = get_status_codes_for_ips(index, start_utc, end_utc, bot_ips, "bot")
    combined_status = {**user_ip_status, **bot_ip_status}

    # console output
    summary_lines = [
        f"Time Range      : {timestamp_str} (IST)",
        f"Total Hits      : {total_hits}",
        f"User Hits       : {user_hits}",
        f"Bot Hits        : {bot_hits}",
        "",
        f"PHP Error Logs  : {php_total} total",
        f"  Notices        : {php_counts.get('notice', 0)}",
        f"  Warnings       : {php_counts.get('warning', 0)}",
        f"  Deprecated     : {php_counts.get('deprecated', 0)}",
        f"  Fatal Errors   : {php_counts.get('fatal', 0)}",
        format_combined_table("Top 25 User IPs", user_ips, bot_ips),
        format_combined_table("Top 25 Domains", user_domains, bot_domains),
        format_combined_table("Top 25 Locations", user_locations, bot_locations),
        send_summary_to_slack("Top 25 User Agents", [{"key": ua["key"], "doc_count": ua["doc_count"]} for ua in user_useragents], [])
    ]
    summary_text = "\n".join(summary_lines)
    print(summary_text)

    # HTML email
    html_summary = generate_html_summary(
        timestamp_str, total_hits, user_hits, bot_hits,
        php_total, php_counts,
        user_ips, bot_ips,
        user_domains, bot_domains,
        user_locations, bot_locations,
        user_useragents,
        ip_status_summary=combined_status
    )
    subject = f"Ubuy Traffic Summary: {timestamp_str}"
    send_summary_to_email(subject, html_summary)

    # Slack summary and reports
    try:
        requests.post(SLACK_WEBHOOK_URL, json={
            "text": send_summary_to_slack(
                "Traffic Summary",
                [], [],
                timestamp_str=timestamp_str,
                total_hits=total_hits,
                user_hits=user_hits,
                bot_hits=bot_hits,
                php_total=php_total,
                php_counts=php_counts
            )
        })
    except Exception as e:
        print(f"Slack post failed (summary): {e}")

    try:
        requests.post(SLACK_WEBHOOK_URL, json={"text": send_summary_to_slack("Top 25 IPs", user_ips, bot_ips, "User IPs", "Bot IPs")})
    except Exception as e:
        print(f"Slack post failed (IPs): {e}")

    try:
        requests.post(SLACK_WEBHOOK_URL, json={"text": send_summary_to_slack("Top 25 Domains", user_domains, bot_domains, "User Domains", "Bot Domains")})
    except Exception as e:
        print(f"Slack post failed (Domains): {e}")

    try:
        requests.post(SLACK_WEBHOOK_URL, json={"text": send_summary_to_slack("Top 25 Locations", user_locations, bot_locations, "User Locations", "Bot Locations")})
    except Exception as e:
        print(f"Slack post failed (Locations): {e}")
        
    try:
        requests.post(SLACK_WEBHOOK_URL, json={"text": send_summary_to_slack("Top 25 User Agents", user_useragents, [], "User Agents")})
    except:
        print(f"Slack post failed (User Agents): {e}")

    try:
        requests.post(SLACK_WEBHOOK_URL, json={"text": send_summary_to_slack("Status Codes per IP", [], [], ip_status_map=combined_status)})
    except Exception as e:
        pass
