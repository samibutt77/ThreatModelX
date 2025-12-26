from typing import List, Dict, Any

# STRIDE categories
STRIDE_CATEGORIES = [
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege"
]

# DREAD weights (can be adjusted)
DREAD_WEIGHTS = {
    "Damage": 0.3,
    "Reproducibility": 0.2,
    "Exploitability": 0.2,
    "AffectedUsers": 0.2,
    "Discoverability": 0.1
}

class ThreatEngine:
    def __init__(self):
        # Templates: optional mapping of component types to likely STRIDE threats
        self.templates = {}  # e.g., {"api": ["Information Disclosure", "Spoofing"]}

    def analyze(self, model) -> List[Dict[str, Any]]:
        """
        Main method: takes a SystemModel and returns a list of threats with DREAD scores.
        """
        threats = []

        # Analyze components
        for comp in model.components:
            likely = self.templates.get(comp.type, STRIDE_CATEGORIES)
            for s in likely:
                t = self._score_threat(comp, s)
                threats.append(t)

        # Analyze data flows
        for flow in model.dataflows:
            t = self._score_flow_threat(flow)
            threats.append(t)

        # Rank by DREAD score
        threats.sort(key=lambda x: x['dread_score'], reverse=True)
        return threats

    def _score_threat(self, comp, stride_category: str) -> Dict[str, Any]:
        """
        Compute a simple DREAD score for a component based on STRIDE category.
        """
        # Base scores for STRIDE categories
        base = 0
        if stride_category == 'Information Disclosure':
            base = 4
        elif stride_category == 'Denial of Service':
            base = 4
        elif stride_category == 'Spoofing':
            base = 3
        elif stride_category == 'Tampering':
            base = 3
        elif stride_category == 'Elevation of Privilege':
            base = 3
        elif stride_category == 'Repudiation':
            base = 2

        # DREAD sub-scores (0-10)
        dmg = min(10, base + 3)
        repro = min(10, base)
        exploit = min(10, base + 1)
        affected = min(10, 5 if comp.type in ('api', 'component', 'class', 'function') else 2)
        discover = min(10, 7 if comp.type == 'api' else 3)

        dread_score = (
            dmg * DREAD_WEIGHTS['Damage'] +
            repro * DREAD_WEIGHTS['Reproducibility'] +
            exploit * DREAD_WEIGHTS['Exploitability'] +
            affected * DREAD_WEIGHTS['AffectedUsers'] +
            discover * DREAD_WEIGHTS['Discoverability']
        ) / sum(DREAD_WEIGHTS.values())

        return {
            'component': comp.id,
            'component_type': comp.type,
            'stride': stride_category,
            'dread_score': round(dread_score, 2),
            'dread_subscores': {
                'Damage': dmg,
                'Reproducibility': repro,
                'Exploitability': exploit,
                'AffectedUsers': affected,
                'Discoverability': discover
            },
            'suggested_mitigation': self.suggest_mitigation(stride_category, comp)
        }

    def _score_flow_threat(self, flow) -> Dict[str, Any]:
        """
        Compute a DREAD score for a data flow.
        """
        # Flows are often at risk of Information Disclosure or Tampering
        dmg = 6
        repro = 4
        exploit = 4
        affected = 4
        discover = 6

        dread_score = (
            dmg * DREAD_WEIGHTS['Damage'] +
            repro * DREAD_WEIGHTS['Reproducibility'] +
            exploit * DREAD_WEIGHTS['Exploitability'] +
            affected * DREAD_WEIGHTS['AffectedUsers'] +
            discover * DREAD_WEIGHTS['Discoverability']
        ) / sum(DREAD_WEIGHTS.values())

        return {
            'component': f"flow_{flow.source}_to_{flow.target}",
            'component_type': 'dataflow',
            'stride': 'Information Disclosure',
            'dread_score': round(dread_score, 2),
            'dread_subscores': {
                'Damage': dmg,
                'Reproducibility': repro,
                'Exploitability': exploit,
                'AffectedUsers': affected,
                'Discoverability': discover
            },
            'suggested_mitigation': "Encrypt the data in transit and validate endpoints"
        }

    def suggest_mitigation(self, stride_category: str, comp) -> str:
        """
        Suggest mitigation based on component type, STRIDE category, and trust boundaries.
        """
        if stride_category == "Spoofing":
            if comp.type in ("api", "function"):
                return "Use OAuth2/JWT authentication for this API/function"
            else:
                return "Enforce authentication for user or system access"

        elif stride_category == "Tampering":
            if comp.type == "datastore":
                return f"Enable integrity checks and encryption at rest for {comp.id}"
            elif comp.type == "dataflow":
                return f"Sign and validate messages in flow {comp.id}"
            else:
                return "Use code signing and integrity verification"

        elif stride_category == "Repudiation":
            return "Enable audit logging and immutable logs for all actions"

        elif stride_category == "Information Disclosure":
            if comp.type == "datastore":
                return f"Encrypt sensitive data in {comp.id} and apply access control"
            elif comp.type == "api":
                return "Enforce HTTPS and input/output validation"
            else:
                return "Restrict sensitive data exposure"

        elif stride_category == "Denial of Service":
            if comp.type == "api":
                return f"Rate-limit API calls and implement retries for {comp.id}"
            else:
                return "Implement resource limits and redundancy"

        elif stride_category == "Elevation of Privilege":
            if comp.type in ("function", "class"):
                return f"Apply least privilege and RBAC in {comp.id}"
            else:
                return "Review access permissions"

        else:
            return "Apply general security best practices"
