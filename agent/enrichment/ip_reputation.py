"""Known-provider classification for IP addresses.

Matches org, isp, and as fields from ip-api.com against known providers
to classify IPs as cloud, CDN, SaaS, hosting, or suspicious.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class IpClassification(str, Enum):
    KNOWN_CLOUD = "known_cloud"
    KNOWN_CDN = "known_cdn"
    KNOWN_SAAS = "known_saas"
    KNOWN_HOSTING = "known_hosting"
    KNOWN_SECURITY = "known_security"
    SUSPICIOUS_HOSTING = "suspicious_hosting"
    UNCLASSIFIED = "unclassified"


@dataclass
class IpReputation:
    classification: IpClassification
    provider_name: str
    country: str
    city: str
    isp: str
    org: str
    asn: str
    is_hosting: bool
    is_proxy: bool
    reverse_dns: str | None = None


# (substring to match in lowercase org+isp+as, classification, provider_name)
_PROVIDER_PATTERNS: list[tuple[str, IpClassification, str]] = [
    # --- Cloud ---
    ("amazon", IpClassification.KNOWN_CLOUD, "Amazon Web Services"),
    ("aws", IpClassification.KNOWN_CLOUD, "Amazon Web Services"),
    ("microsoft azure", IpClassification.KNOWN_CLOUD, "Microsoft Azure"),
    ("microsoft corporation", IpClassification.KNOWN_CLOUD, "Microsoft Azure"),
    ("google cloud", IpClassification.KNOWN_CLOUD, "Google Cloud"),
    ("google llc", IpClassification.KNOWN_CLOUD, "Google Cloud"),
    ("oracle cloud", IpClassification.KNOWN_CLOUD, "Oracle Cloud"),
    ("oracle corporation", IpClassification.KNOWN_CLOUD, "Oracle Cloud"),
    ("alibaba cloud", IpClassification.KNOWN_CLOUD, "Alibaba Cloud"),
    ("tencent cloud", IpClassification.KNOWN_CLOUD, "Tencent Cloud"),
    # --- CDN ---
    ("cloudflare", IpClassification.KNOWN_CDN, "Cloudflare"),
    ("akamai", IpClassification.KNOWN_CDN, "Akamai"),
    ("fastly", IpClassification.KNOWN_CDN, "Fastly"),
    ("edgecast", IpClassification.KNOWN_CDN, "Edgecast"),
    ("limelight", IpClassification.KNOWN_CDN, "Limelight Networks"),
    ("stackpath", IpClassification.KNOWN_CDN, "StackPath"),
    ("keycdn", IpClassification.KNOWN_CDN, "KeyCDN"),
    ("bunnycdn", IpClassification.KNOWN_CDN, "BunnyCDN"),
    ("cdn77", IpClassification.KNOWN_CDN, "CDN77"),
    # --- SaaS ---
    ("apple inc", IpClassification.KNOWN_SAAS, "Apple"),
    ("github", IpClassification.KNOWN_SAAS, "GitHub"),
    ("anthropic", IpClassification.KNOWN_SAAS, "Anthropic"),
    ("openai", IpClassification.KNOWN_SAAS, "OpenAI"),
    ("slack", IpClassification.KNOWN_SAAS, "Slack"),
    ("dropbox", IpClassification.KNOWN_SAAS, "Dropbox"),
    ("salesforce", IpClassification.KNOWN_SAAS, "Salesforce"),
    ("zoom video", IpClassification.KNOWN_SAAS, "Zoom"),
    ("twilio", IpClassification.KNOWN_SAAS, "Twilio"),
    ("datadog", IpClassification.KNOWN_SAAS, "Datadog"),
    ("atlassian", IpClassification.KNOWN_SAAS, "Atlassian"),
    # --- Hosting ---
    ("digitalocean", IpClassification.KNOWN_HOSTING, "DigitalOcean"),
    ("linode", IpClassification.KNOWN_HOSTING, "Linode"),
    ("vultr", IpClassification.KNOWN_HOSTING, "Vultr"),
    ("hetzner", IpClassification.KNOWN_HOSTING, "Hetzner"),
    ("ovh", IpClassification.KNOWN_HOSTING, "OVH"),
    ("scaleway", IpClassification.KNOWN_HOSTING, "Scaleway"),
    ("contabo", IpClassification.KNOWN_HOSTING, "Contabo"),
    ("kamatera", IpClassification.KNOWN_HOSTING, "Kamatera"),
    ("hostinger", IpClassification.KNOWN_HOSTING, "Hostinger"),
    ("godaddy", IpClassification.KNOWN_HOSTING, "GoDaddy"),
    # --- Security ---
    ("crowdstrike", IpClassification.KNOWN_SECURITY, "CrowdStrike"),
    ("zscaler", IpClassification.KNOWN_SECURITY, "Zscaler"),
    ("palo alto", IpClassification.KNOWN_SECURITY, "Palo Alto Networks"),
    ("sentinelone", IpClassification.KNOWN_SECURITY, "SentinelOne"),
    ("fortinet", IpClassification.KNOWN_SECURITY, "Fortinet"),
]

# Reverse DNS suffixes that indicate a known provider
_RDNS_PATTERNS: list[tuple[str, IpClassification, str]] = [
    (".amazonaws.com", IpClassification.KNOWN_CLOUD, "Amazon Web Services"),
    (".azure.com", IpClassification.KNOWN_CLOUD, "Microsoft Azure"),
    (".googleusercontent.com", IpClassification.KNOWN_CLOUD, "Google Cloud"),
    (".google.com", IpClassification.KNOWN_SAAS, "Google"),
    (".cloudfront.net", IpClassification.KNOWN_CDN, "Amazon CloudFront"),
    (".cloudflare.com", IpClassification.KNOWN_CDN, "Cloudflare"),
    (".akamaiedge.net", IpClassification.KNOWN_CDN, "Akamai"),
    (".akamaitechnologies.com", IpClassification.KNOWN_CDN, "Akamai"),
    (".fastly.net", IpClassification.KNOWN_CDN, "Fastly"),
    (".apple.com", IpClassification.KNOWN_SAAS, "Apple"),
    (".icloud.com", IpClassification.KNOWN_SAAS, "Apple"),
    (".github.com", IpClassification.KNOWN_SAAS, "GitHub"),
    (".1e100.net", IpClassification.KNOWN_SAAS, "Google"),
]


def classify_ip(geo_data: dict, reverse_dns: str | None = None) -> IpReputation:
    """Classify an IP based on GeoIP data and optional reverse DNS.

    Args:
        geo_data: Dict from ip-api.com with keys: org, isp, as, country,
            city, hosting, proxy, etc.
        reverse_dns: Optional reverse DNS hostname for the IP.

    Returns:
        IpReputation with classification and provider info.
    """
    org = str(geo_data.get("org", ""))
    isp = str(geo_data.get("isp", ""))
    as_field = str(geo_data.get("as", ""))
    country = str(geo_data.get("country", ""))
    city = str(geo_data.get("city", ""))
    asn = str(geo_data.get("asn", "") or as_field)
    is_hosting = bool(geo_data.get("hosting", False))
    is_proxy = bool(geo_data.get("proxy", False))

    # Lowercase concatenation for matching
    search_text = f"{org} {isp} {as_field}".lower()

    classification = IpClassification.UNCLASSIFIED
    provider_name = ""

    # Match against known provider patterns
    for pattern, cls, name in _PROVIDER_PATTERNS:
        if pattern in search_text:
            classification = cls
            provider_name = name
            break

    # If no match from org/isp/as, try reverse DNS
    if classification == IpClassification.UNCLASSIFIED and reverse_dns:
        rdns_lower = reverse_dns.lower()
        for suffix, cls, name in _RDNS_PATTERNS:
            if rdns_lower.endswith(suffix):
                classification = cls
                provider_name = name
                break

    # Fallback: hosting=True but unknown provider = suspicious
    if classification == IpClassification.UNCLASSIFIED and is_hosting:
        classification = IpClassification.SUSPICIOUS_HOSTING
        provider_name = ""

    return IpReputation(
        classification=classification,
        provider_name=provider_name,
        country=country,
        city=city,
        isp=isp,
        org=org,
        asn=asn,
        is_hosting=is_hosting,
        is_proxy=is_proxy,
        reverse_dns=reverse_dns,
    )
