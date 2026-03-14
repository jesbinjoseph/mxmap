import re

MICROSOFT_KEYWORDS = [
    "mail.protection.outlook.com",
    "outlook.com",
    "microsoft",
    "office365",
    "onmicrosoft",
    "spf.protection.outlook.com",
    "sharepointonline",
]
GOOGLE_KEYWORDS = [
    "google",
    "googlemail",
    "gmail",
    "_spf.google.com",
    "aspmx.l.google.com",
]
AWS_KEYWORDS = ["amazonaws", "amazonses", "awsdns"]
INFOMANIAK_KEYWORDS = ["infomaniak", "ikmail.com", "mxpool.infomaniak"]

PROVIDER_KEYWORDS = {
    "microsoft": MICROSOFT_KEYWORDS,
    "google": GOOGLE_KEYWORDS,
    "aws": AWS_KEYWORDS,
    "infomaniak": INFOMANIAK_KEYWORDS,
}

FOREIGN_SENDER_KEYWORDS = {
    "mailchimp": ["mandrillapp.com", "mandrill", "mcsv.net"],
    "sendgrid": ["sendgrid"],
    "mailjet": ["mailjet"],
    "mailgun": ["mailgun"],
    "brevo": ["sendinblue", "brevo"],
    "mailchannels": ["mailchannels"],
    "smtp2go": ["smtp2go"],
    "nl2go": ["nl2go"],
    "hubspot": ["hubspotemail"],
    "knowbe4": ["knowbe4"],
    "hornetsecurity": ["hornetsecurity", "hornetdmarc"],
}

BFS_API_URL = "https://www.agvchapp.bfs.admin.ch/api/communes/snapshot"

SPARQL_URL = "https://query.wikidata.org/sparql"
SPARQL_QUERY = """
SELECT ?item ?itemLabel ?bfs ?website ?cantonLabel WHERE {
  ?item wdt:P31 wd:Q70208 .          # instance of: municipality of Switzerland
  ?item wdt:P771 ?bfs .              # Swiss municipality code (BFS number)
  FILTER NOT EXISTS {                  # exclude dissolved municipalities
    ?item wdt:P576 ?dissolved .
    FILTER(?dissolved <= NOW())
  }
  FILTER NOT EXISTS {                  # exclude municipalities with ended P31 statement
    ?item p:P31 ?stmt .
    ?stmt ps:P31 wd:Q70208 .
    ?stmt pq:P582 ?endTime .
    FILTER(?endTime <= NOW())
  }
  FILTER NOT EXISTS {                  # exclude municipalities replaced by a successor
    ?item wdt:P1366 ?successor .
  }
  OPTIONAL { ?item wdt:P856 ?website . }
  OPTIONAL { ?item wdt:P131+ ?canton .
             ?canton wdt:P31 wd:Q23058 . }
  SERVICE wikibase:label { bd:serviceParam wikibase:language "de,fr,it,rm,en" . }
}
ORDER BY xsd:integer(?bfs)
"""

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
TYPO3_RE = re.compile(r"linkTo_UnCryptMailto\(['\"]([^'\"]+)['\"]")
SKIP_DOMAINS = {
    "example.com",
    "example.ch",
    "sentry.io",
    "w3.org",
    "gstatic.com",
    "googleapis.com",
    "schema.org",
    # Generic email providers (not municipality-specific)
    "gmail.com",
    "hotmail.com",
    "hotmail.ch",
    "outlook.com",
    "gmx.ch",
    "bluewin.ch",
    "yahoo.com",
    # Shared hosting / CMS / web agencies
    "domain.com",
    "pregny-chambesy.ch",  # shared Abaco CMS template
    "netconsult.ch",
    "bbf.ch",
    "dp-wired.de",
    # Web framework / analytics
    "google.com",
    "group.calendar.google.com",
    # Generic / unrelated services
    "mail.com",
    "wordpress.org",
    "defiant.com",
    "schedulista.com",
    "zurich-airport.com",
    "avasad.ch",
}

SUBPAGES = [
    "/kontakt",
    "/contact",
    "/impressum",
    "/kontakt/",
    "/contact/",
    "/impressum/",
    "/de/kontakt",
    "/fr/contact",
    "/it/contatto",
    "/verwaltung",
    "/administration",
    "/autorites",
    "/gemeinde",
    "/commune",
    "/comune",
]

GATEWAY_KEYWORDS = {
    "seppmail": ["seppmail.cloud", "seppmail.com"],
    "cleanmail": ["cleanmail.ch", "cleanmail.safecenter.ch"],
    "barracuda": ["barracudanetworks.com", "barracuda.com"],
    "trendmicro": ["tmes.trendmicro.eu", "tmes.trendmicro.com"],
    "hornetsecurity": ["hornetsecurity.com", "hornetsecurity.ch"],
    "abxsec": ["abxsec.com"],
    "proofpoint": ["ppe-hosted.com"],
    "sophos": ["hydra.sophos.com"],
    "spamvor": ["spamvor.com"],
}

SWISS_ISP_ASNS: dict[int, str] = {
    559: "SWITCH",
    3303: "Swisscom",
    6730: "Sunrise UPC",
    6830: "Liberty Global (UPC/Sunrise)",
    12399: "Sunrise",
    13030: "Init7",
    13213: "Cyberlink AG",
    15576: "NTS",
    15600: "Quickline",
    15796: "Netzone AG",
    24889: "Datapark AG",
    29691: "Hostpoint / Green.ch",
    51786: "Infomaniak Network SA",
}

CANTON_ABBREVIATIONS = {
    "Kanton Zürich": "zh",
    "Kanton Bern": "be",
    "Kanton Luzern": "lu",
    "Kanton Uri": "ur",
    "Kanton Schwyz": "sz",
    "Kanton Obwalden": "ow",
    "Kanton Nidwalden": "nw",
    "Kanton Glarus": "gl",
    "Kanton Zug": "zg",
    "Kanton Freiburg": "fr",
    "Kanton Solothurn": "so",
    "Kanton Basel-Stadt": "bs",
    "Kanton Basel-Landschaft": "bl",
    "Kanton Schaffhausen": "sh",
    "Kanton Appenzell Ausserrhoden": "ar",
    "Kanton Appenzell Innerrhoden": "ai",
    "Kanton St. Gallen": "sg",
    "Kanton Graubünden": "gr",
    "Kanton Aargau": "ag",
    "Kanton Thurgau": "tg",
    "Kanton Tessin": "ti",
    "Kanton Waadt": "vd",
    "Kanton Wallis": "vs",
    "Kanton Neuenburg": "ne",
    "Kanton Genf": "ge",
    "Kanton Jura": "ju",
}

CANTON_SHORT_TO_FULL = {v: k for k, v in CANTON_ABBREVIATIONS.items()}

CONCURRENCY = 20
CONCURRENCY_POSTPROCESS = 10
CONCURRENCY_SMTP = 5
CONCURRENCY_TENANT = 5

DKIM_SELECTORS: dict[str, list[str]] = {
    "microsoft": ["selector1", "selector2"],
    "google": ["google", "google2048"],
}

DKIM_CNAME_KEYWORDS: dict[str, list[str]] = {
    "microsoft": ["onmicrosoft.com"],
    "google": ["domainkey.googlehosted.com", "domainkey.google.com"],
}

SMTP_BANNER_KEYWORDS = {
    "microsoft": [
        "microsoft esmtp mail service",
        "outlook.com",
        "protection.outlook.com",
    ],
    "google": [
        "mx.google.com",
        "google esmtp",
    ],
    "infomaniak": [
        "infomaniak",
    ],
    "aws": [
        "amazonaws",
        "amazonses",
    ],
}
