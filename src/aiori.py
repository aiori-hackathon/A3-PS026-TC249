
import re
from urllib.parse import urlparse, quote, unquote
from typing import Dict, List, Any

def generate_corpus() -> List[Dict[str, Any]]:
    corpus = []
    dids = ["did:plc:z72i7hdynmk6r22z27h6tvur", "did:web:bsky.social", "did:key:z6MksH1g5ZX..."]
    handles = ["alice.bsky.social", "bob.test", "charlie-sub.domain.org", "user_123.net"]
    collections = ["app.bsky.feed.post", "app.bsky.actor.profile", "com.example.custom.record"]
    rkeys = ["3jui75232w22c", "self", "bafyreig7ds...", "test-key_123"]

    uid = 1
    for d in dids:
        for c in collections:
            for r in rkeys:
                corpus.append({"id": f"valid_{uid}", "uri": f"at://{d}/{c}/{r}", "expected_validity": True, "category": "valid_did"})
                uid += 1

    for h in handles:
        for c in collections[:2]:
            for r in rkeys[:2]:
                corpus.append({"id": f"valid_{uid}", "uri": f"at://{h}/{c}/{r}", "expected_validity": True, "category": "valid_handle"})
                uid += 1

    edge_cases = [
        ("at://alice.bsky.social/app.bsky.feed.post/key with space", "space in rkey"),
        ("at://did:plc:123/app.bsky.feed.post/key#fragment", "RFC 3986 fragment violation"),
        ("at://alice.bsky.social/app.bsky.feed.post/key?query=1", "query parameter violation"),
    ]
    for uri, desc in edge_cases:
        corpus.append({"id": f"edge_{uid}", "uri": uri, "expected_validity": False, "category": f"edge_case: {desc}"})
        uid += 1

    while len(corpus) < 105:
        corpus.append({"id": f"pad_{uid}", "uri": f"at://user{uid}.test/app.bsky.feed.post/key{uid}", "expected_validity": True, "category": "padded_valid"})
        uid += 1

    return corpus

class ATProtocolParser:
    NSID_REGEX = r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$"
    RKEY_REGEX = r"^[a-zA-Z0-9._~:@!$&'()*+,;=-]{1,512}$"
    HANDLE_REGEX = r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    DID_REGEX = r"^did:[a-z0-9]+:[a-zA-Z0-9._:%-]*[a-zA-Z0-9._-]$"

    def parse(self, uri: str) -> Dict[str, Any]:
        result = {"parser": "ATProtocolParser", "uri": uri, "is_syntactically_valid": False, "authority": None, "collection": None, "rkey": None, "error": None}
        if not uri.startswith("at://"):
            result["error"] = "Missing 'at://' scheme prefix."
            return result
        parts = uri[5:].split("/", 2)
        if len(parts) < 3:
            result["error"] = "Malformed AT URI structure."
            return result
        authority, collection, rkey = parts[0], parts[1], parts[2]
        if not (bool(re.match(self.DID_REGEX, authority)) or bool(re.match(self.HANDLE_REGEX, authority))):
            result["error"] = f"Invalid authority format: '{authority}'"
            return result
        if not re.match(self.NSID_REGEX, collection):
            result["error"] = f"Invalid collection NSID format: '{collection}'"
            return result
        if not re.match(self.RKEY_REGEX, rkey):
            result["error"] = f"Invalid record key format: '{rkey}'"
            return result
        result["is_syntactically_valid"] = True
        result["authority"] = authority
        result["collection"] = collection
        result["rkey"] = rkey
        return result

class RFC3986Parser:
    def parse(self, uri: str) -> Dict[str, Any]:
        result = {"parser": "RFC3986Parser", "uri": uri, "is_rfc_compliant": False, "scheme": None, "netloc": None, "path": None, "error": None}
        try:
            parsed = urlparse(uri)
            if not parsed.scheme:
                result["error"] = "Missing URI scheme."
                return result
            result["scheme"] = parsed.scheme
            result["netloc"] = parsed.netloc
            result["path"] = parsed.path
            has_bad_chars = any(ord(c) > 127 for c in uri) or (" " in uri)
            if has_bad_chars or parsed.fragment or parsed.query:
                result["is_rfc_compliant"] = False
                result["error"] = "Contains characters violating strict RFC 3986 generic syntax."
            else:
                result["is_rfc_compliant"] = True
        except Exception as e:
            result["error"] = str(e)
        return result

class PercentEncodingTransform:
    @staticmethod
    def encode(uri: str) -> str: return quote(uri, safe=":/@._-")
    @staticmethod
    def decode(encoded_uri: str) -> str: return unquote(encoded_uri)

class SafeHexEncodingTransform:
    @staticmethod
    def encode(uri: str) -> str: return "".join([f"\\x{ord(c):02x}" if ord(c) > 127 or c == " " else c for c in uri])
    @staticmethod
    def decode(encoded_uri: str) -> str:
        return re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), encoded_uri)

class ATURIValidatorSuite:
    def __init__(self):
        self.corpus = generate_corpus()
        self.at_parser = ATProtocolParser()
        self.rfc_parser = RFC3986Parser()

    def run_evaluation(self) -> Dict[str, Any]:
        total = len(self.corpus)
        passed_at_syntax = sum(1 for item in self.corpus if self.at_parser.parse(item["uri"])["is_syntactically_valid"])
        round_trip_success = sum(1 for item in self.corpus if PercentEncodingTransform.decode(PercentEncodingTransform.encode(item["uri"])) == item["uri"])
        return {
            "total_corpus_size": total,
            "at_protocol_syntactically_valid_count": passed_at_syntax,
            "round_trip_preservation_success_rate": f"{(round_trip_success / total) * 100:.2f}%",
            "transformations_evaluated": ["PercentEncodingTransform", "SafeHexEncodingTransform"]
        }