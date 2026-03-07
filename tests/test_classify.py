from mail_sovereignty.classify import (
    classify,
    classify_from_mx,
    classify_from_spf,
    spf_mentions_providers,
)


# ── classify() ──────────────────────────────────────────────────────


class TestClassify:
    def test_microsoft_mx(self):
        assert classify(["bern-ch.mail.protection.outlook.com"], "") == "microsoft"

    def test_google_mx(self):
        assert (
            classify(["aspmx.l.google.com", "alt1.aspmx.l.google.com"], "") == "google"
        )

    def test_infomaniak_mx(self):
        assert classify(["mxpool.infomaniak.com"], "") == "infomaniak"

    def test_aws_mx(self):
        assert classify(["inbound-smtp.us-east-1.amazonaws.com"], "") == "aws"

    def test_sovereign_mx(self):
        assert classify(["mail.example.ch"], "") == "sovereign"

    def test_spf_fallback_when_no_mx(self):
        assert (
            classify([], "v=spf1 include:spf.protection.outlook.com -all")
            == "microsoft"
        )

    def test_no_mx_no_spf(self):
        assert classify([], "") == "unknown"

    def test_mx_takes_precedence_over_spf(self):
        result = classify(
            ["mail.example.ch"],
            "v=spf1 include:spf.protection.outlook.com -all",
        )
        assert result == "sovereign"

    def test_cname_detects_microsoft(self):
        result = classify(
            ["mail.example.ch"],
            "",
            mx_cnames={"mail.example.ch": "mail.protection.outlook.com"},
        )
        assert result == "microsoft"

    def test_cname_none_stays_sovereign(self):
        assert classify(["mail.example.ch"], "", mx_cnames=None) == "sovereign"

    def test_cname_empty_stays_sovereign(self):
        assert classify(["mail.example.ch"], "", mx_cnames={}) == "sovereign"

    def test_direct_mx_takes_precedence_over_cname(self):
        result = classify(
            ["mail.protection.outlook.com"],
            "",
            mx_cnames={"mail.protection.outlook.com": "something.else.com"},
        )
        assert result == "microsoft"

    def test_swiss_isp_asn(self):
        result = classify(
            ["mail1.rzobt.ch"],
            "",
            mx_asns={3303},
        )
        assert result == "swiss-isp"

    def test_swiss_isp_does_not_override_hostname_match(self):
        result = classify(
            ["mail.protection.outlook.com"],
            "",
            mx_asns={3303},
        )
        assert result == "microsoft"

    def test_swiss_isp_does_not_override_cname_match(self):
        result = classify(
            ["mail.example.ch"],
            "",
            mx_cnames={"mail.example.ch": "mail.protection.outlook.com"},
            mx_asns={3303},
        )
        assert result == "microsoft"

    def test_non_swiss_isp_asn_stays_sovereign(self):
        result = classify(
            ["mail.example.ch"],
            "",
            mx_asns={99999},
        )
        assert result == "sovereign"

    def test_empty_asns_stays_sovereign(self):
        result = classify(
            ["mail.example.ch"],
            "",
            mx_asns=set(),
        )
        assert result == "sovereign"


# ── classify_from_mx() ──────────────────────────────────────────────


class TestClassifyFromMx:
    def test_empty_returns_none(self):
        assert classify_from_mx([]) is None

    def test_microsoft(self):
        assert classify_from_mx(["mail.protection.outlook.com"]) == "microsoft"

    def test_google(self):
        assert classify_from_mx(["aspmx.l.google.com"]) == "google"

    def test_unrecognized_returns_sovereign(self):
        assert classify_from_mx(["mail.custom.ch"]) == "sovereign"

    def test_case_insensitive(self):
        assert classify_from_mx(["MAIL.PROTECTION.OUTLOOK.COM"]) == "microsoft"


# ── classify_from_spf() ─────────────────────────────────────────────


class TestClassifyFromSpf:
    def test_empty_returns_none(self):
        assert classify_from_spf("") is None

    def test_none_returns_none(self):
        assert classify_from_spf(None) is None

    def test_microsoft(self):
        assert (
            classify_from_spf("v=spf1 include:spf.protection.outlook.com -all")
            == "microsoft"
        )

    def test_unrecognized_returns_none(self):
        assert classify_from_spf("v=spf1 include:custom.ch -all") is None


# ── spf_mentions_providers() ─────────────────────────────────────────


class TestSpfMentionsProviders:
    def test_empty_returns_empty(self):
        assert spf_mentions_providers("") == set()

    def test_single_provider(self):
        result = spf_mentions_providers(
            "v=spf1 include:spf.protection.outlook.com -all"
        )
        assert result == {"microsoft"}

    def test_multiple_providers(self):
        result = spf_mentions_providers(
            "v=spf1 include:spf.protection.outlook.com include:_spf.google.com -all"
        )
        assert result == {"microsoft", "google"}

    def test_detects_mailchimp(self):
        result = spf_mentions_providers(
            "v=spf1 include:servers.mcsv.net include:spf.mandrillapp.com -all"
        )
        assert "mailchimp" in result

    def test_detects_sendgrid(self):
        result = spf_mentions_providers("v=spf1 include:sendgrid.net -all")
        assert result == {"sendgrid"}

    def test_mixed_main_and_foreign(self):
        result = spf_mentions_providers(
            "v=spf1 include:spf.protection.outlook.com include:spf.mandrillapp.com -all"
        )
        assert result == {"microsoft", "mailchimp"}

    def test_foreign_sender_not_in_classify(self):
        assert classify([], "v=spf1 include:spf.mandrillapp.com -all") == "unknown"

    def test_foreign_sender_not_in_classify_from_spf(self):
        assert classify_from_spf("v=spf1 include:spf.mandrillapp.com -all") is None
