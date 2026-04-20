import re

# India: Local Government Directory API for municipality data
LGD_API_URL = "https://lgdirectory.gov.in/webservices/lgdws/statemaster"
# Keep old name as alias for backward compatibility in imports
BFS_API_URL = LGD_API_URL

SPARQL_URL = "https://query.wikidata.org/sparql"
SPARQL_QUERY = """
SELECT ?item ?itemLabel ?lgdCode ?website ?stateLabel WHERE {
  {
    ?item wdt:P31 wd:Q515 .            # instance of: city
  } UNION {
    ?item wdt:P31 wd:Q1115575 .        # instance of: municipal corporation (India)
  } UNION {
    ?item wdt:P31 wd:Q2555896 .        # instance of: municipality of India
  } UNION {
    ?item wdt:P31 wd:Q1371849 .        # instance of: nagar panchayat
  }
  ?item wdt:P17 wd:Q668 .              # country: India
  ?item wdt:P4890 ?lgdCode .           # LGD code
  FILTER NOT EXISTS {
    ?item wdt:P576 ?dissolved .
    FILTER(?dissolved <= NOW())
  }
  OPTIONAL { ?item wdt:P856 ?website . }
  OPTIONAL { ?item wdt:P131 ?state .
             ?state wdt:P31 wd:Q131541 . }
  SERVICE wikibase:label { bd:serviceParam wikibase:language "en,hi" . }
}
ORDER BY xsd:integer(?lgdCode)
"""

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
TYPO3_RE = re.compile(
    r"linkTo_UnCryptMailto\((?:['\"]|%27|%22)([^'\"]+?)(?:['\"]|%27|%22)"
)
SKIP_DOMAINS = {
    "example.com",
    "sentry.io",
    "w3.org",
    "gstatic.com",
    "googleapis.com",
    "schema.org",
    # Generic email providers (not municipality-specific)
    "gmail.com",
    "hotmail.com",
    "outlook.com",
    "yahoo.com",
    "yahoo.co.in",
    "rediffmail.com",
    # Generic Indian portals
    "india.gov.in",
    "digitalindia.gov.in",
    "mygov.in",
    # Web framework / analytics
    "google.com",
    "group.calendar.google.com",
    # Generic / unrelated services
    "mail.com",
    "wordpress.org",
    "defiant.com",
    "domain.com",
}

SUBPAGES = [
    "/contact",
    "/contact-us",
    "/contactus",
    "/about",
    "/about-us",
    "/contact/",
    "/contact-us/",
    "/about/",
    "/directory",
    "/officials",
    "/administration",
    "/departments",
    "/en/contact",
    "/hi/contact",
]

# Indian state/UT codes (ISO 3166-2:IN)
STATE_ABBREVIATIONS = {
    "Andhra Pradesh": "ap",
    "Arunachal Pradesh": "ar",
    "Assam": "as",
    "Bihar": "br",
    "Chhattisgarh": "cg",
    "Goa": "ga",
    "Gujarat": "gj",
    "Haryana": "hr",
    "Himachal Pradesh": "hp",
    "Jharkhand": "jh",
    "Karnataka": "ka",
    "Kerala": "kl",
    "Madhya Pradesh": "mp",
    "Maharashtra": "mh",
    "Manipur": "mn",
    "Meghalaya": "ml",
    "Mizoram": "mz",
    "Nagaland": "nl",
    "Odisha": "od",
    "Punjab": "pb",
    "Rajasthan": "rj",
    "Sikkim": "sk",
    "Tamil Nadu": "tn",
    "Telangana": "tg",
    "Tripura": "tr",
    "Uttar Pradesh": "up",
    "Uttarakhand": "uk",
    "West Bengal": "wb",
    # Union Territories
    "Andaman and Nicobar Islands": "an",
    "Chandigarh": "ch",
    "Dadra and Nagar Haveli and Daman and Diu": "dd",
    "Delhi": "dl",
    "Jammu and Kashmir": "jk",
    "Ladakh": "la",
    "Lakshadweep": "ld",
    "Puducherry": "py",
}

# Keep old name as alias for backward compat
CANTON_ABBREVIATIONS = STATE_ABBREVIATIONS

STATE_SHORT_TO_FULL = {v: k for k, v in STATE_ABBREVIATIONS.items()}
CANTON_SHORT_TO_FULL = STATE_SHORT_TO_FULL

CONCURRENCY_POSTPROCESS = 10
