import pandas as pd
from sklearn.ensemble import IsolationForest

from .bloom_filter import BloomFilter
from .utils import normalize_indicator, indicator_features


class ThreatDetector:
    def __init__(self, threat_set, bloom, model):
        self.threat_set = threat_set
        self.bloom = bloom
        self.model = model
        self.feature_names = [
            "length", "entropy", "digit_ratio", "letter_ratio",
            "special_ratio", "dot_count", "slash_count", "hyphen_count",
            "at_count", "query_char_count", "max_label_length",
            "subdomain_count", "has_ip_like_host"
        ]

    @classmethod
    def from_files(cls, threat_file, training_file):
        threat_df = pd.read_csv(threat_file)
        threats = {
            normalize_indicator(x)
            for x in threat_df["indicator"].dropna().astype(str)
            if normalize_indicator(x)
        }

        bloom = BloomFilter(expected_items=max(len(threats), 100), bits_per_item=12)
        for item in threats:
            bloom.add(item)

        train_df = pd.read_csv(training_file)
        X = pd.DataFrame(
            [indicator_features(x) for x in train_df["indicator"].astype(str)]
        )
        model = IsolationForest(
            n_estimators=200,
            contamination=0.08,
            random_state=42
        )
        model.fit(X)
        return cls(threats, bloom, model)

    def _feature_row(self, indicator):
        f = indicator_features(indicator)
        return pd.DataFrame([[f[name] for name in self.feature_names]],
                            columns=self.feature_names)

    def ai_analyze(self, indicator):
        normalized = normalize_indicator(indicator)
        X = self._feature_row(indicator)
        pred = int(self.model.predict(X)[0])
        score = float(self.model.decision_function(X)[0])
        return {
            "normalized": normalized,
            "prediction": "NORMAL" if pred == 1 else "ANOMALOUS",
            "score": score,
            "features": indicator_features(indicator)
        }

    def scan(self, indicator):
        normalized = normalize_indicator(indicator)
        bloom_candidate = self.bloom.might_contain(normalized)
        exact_match = normalized in self.threat_set if bloom_candidate else False
        ai = self.ai_analyze(indicator)

        if exact_match:
            action = "BLOCK / QUARANTINE / INVESTIGATE according to security policy"
        elif bloom_candidate:
            action = "SEND TO EXACT VERIFICATION"
        elif ai["prediction"] == "ANOMALOUS":
            action = "FLAG FOR ANALYST REVIEW"
        else:
            action = "ALLOW / CONTINUE MONITORING"

        return {
            "indicator": str(indicator),
            "normalized": normalized,
            "bloom_result": "POSSIBLY PRESENT" if bloom_candidate else "DEFINITELY NOT PRESENT",
            "exact_result": "KNOWN THREAT" if exact_match else "NOT IN THREAT DATABASE",
            "ai_result": ai["prediction"],
            "bloom_candidate": bloom_candidate,
            "exact_match": exact_match,
            "action": action,
            "features": ai["features"]
        }

    def batch_scan(self, indicators):
        return [self.scan(x) for x in indicators]
