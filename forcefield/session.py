"""Multi-turn session risk tracking -- detect slow-burn attacks across conversation turns.

Extracted from services/common/session_risk_tracker.py (production gateway).
Zero external dependencies (stdlib only).

Detects multi-step attack sequences:
- System prompt extraction -> injection
- Role-play setup -> policy bypass
- Incremental policy boundary testing
- Context manipulation for later exploitation
- Authority escalation chains
- Crescendo attacks (benign -> malicious)
- Distraction then inject
- Context window stuffing
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class TurnAnalysis:
    """Analysis result for a single conversation turn."""
    turn_number: int
    timestamp: float
    prompt_hash: str
    risk_score: float
    flags: List[str]
    detector_codes: List[str]
    response_was_refused: bool = False


@dataclass
class SessionRiskProfile:
    """Cumulative risk profile for a user session."""
    session_id: str
    user_id: Optional[str]
    created_at: float
    last_activity: float
    turns: List[TurnAnalysis] = field(default_factory=list)
    cumulative_risk: float = 0.0
    escalation_level: int = 0  # 0=normal, 1=elevated, 2=high, 3=critical
    blocked_count: int = 0
    suspicious_patterns: List[str] = field(default_factory=list)
    prompt_history: List[str] = field(default_factory=list)

    def is_expired(self, ttl_seconds: int = 3600) -> bool:
        return (time.time() - self.last_activity) > ttl_seconds


# ---------------------------------------------------------------------------
# Multi-turn pattern analyzer
# ---------------------------------------------------------------------------

ATTACK_SEQUENCES: Dict[str, Dict] = {
    "system_prompt_extraction_injection": {
        "sequence": [
            r"(system\s+prompt|instruction|guideline|rule)",
            r"(ignore|forget|override|bypass)",
        ],
        "window_turns": 5,
        "severity": 0.9,
    },
    "role_play_bypass": {
        "sequence": [
            r"(pretend|roleplay|imagine|act\s+as)",
            r"(unrestricted|no\s+rules|no\s+limits|evil|jailbroken)",
        ],
        "window_turns": 3,
        "severity": 0.85,
    },
    "incremental_policy_testing": {
        "sequence": [
            r"(can\s+you|are\s+you\s+able|would\s+you)",
            r"(what\s+if|but\s+what|how\s+about)",
            r"(just\s+this\s+once|hypothetically|in\s+theory)",
        ],
        "window_turns": 6,
        "severity": 0.7,
    },
    "context_manipulation": {
        "sequence": [
            r"(remember|note\s+that|keep\s+in\s+mind)",
            r"(earlier|before|as\s+we\s+discussed)",
            r"(so\s+therefore|which\s+means|hence)",
        ],
        "window_turns": 10,
        "severity": 0.75,
    },
    "authority_escalation": {
        "sequence": [
            r"(i\s+am|i'm\s+a|my\s+role)",
            r"(admin|developer|authorized|permission)",
            r"(access|show|reveal|override)",
        ],
        "window_turns": 5,
        "severity": 0.8,
    },
    "crescendo_attack": {
        "sequence": [
            r"(tell\s+me\s+about|explain|describe|what\s+is)",
            r"(more\s+detail|specifically|in\s+particular|elaborate)",
            r"(step[\s-]by[\s-]step|exactly\s+how|detailed\s+instructions?|specific\s+steps)",
        ],
        "window_turns": 8,
        "severity": 0.65,
    },
    "distraction_then_inject": {
        "sequence": [
            r"(thanks|thank\s+you|great|good\s+job|helpful)",
            r"(by\s+the\s+way|also|one\s+more\s+thing|quick\s+question)",
            r"(ignore|forget|disregard|override|bypass|system\s+prompt)",
        ],
        "window_turns": 6,
        "severity": 0.85,
    },
    "context_window_stuffing": {
        "sequence": [
            r"(repeat|write|generate|output)\s+(the\s+following|this\s+text|this\s+phrase).*\d+\s+times",
            r"(now|then|after\s+that|next)\s+(ignore|forget|disregard|new\s+instruction)",
        ],
        "window_turns": 4,
        "severity": 0.9,
    },
}

SUSPICIOUS_PATTERNS: Dict[str, str] = {
    "system_prompt_inquiry": r"(what\s+(are|is)\s+your|tell\s+me\s+your).*(instruction|prompt|rule|guideline)",
    "injection_attempt": r"(ignore|forget|disregard).*(previous|prior|above|instruction)",
    "jailbreak_keyword": r"(DAN|jailbreak|unfiltered|uncensored|no\s+restrictions)",
    "model_confusion": r"(you\s+are|pretend\s+to\s+be|act\s+as).*(different|another|new)",
    "delimiter_injection": r"(<\|.*?\|>|\[SYSTEM\]|\[ADMIN\]|<<<|>>>)",
    "encoding_probe": r"(base64|rot13|hex|unicode|decode|encode).*",
    "indirect_injection_marker": r"(instructions?\s+for\s+(the\s+)?ai|when\s+(the\s+)?(ai|assistant|model)\s+reads?)",
    "payload_splitting": r"(part\s+\d+\s+of\s+\d+|combine\s+(the\s+)?(previous|above)\s+(parts?|fragments?))",
}

# Pre-compile
_COMPILED_SUSPICIOUS = {
    name: re.compile(pattern, re.IGNORECASE)
    for name, pattern in SUSPICIOUS_PATTERNS.items()
}
_COMPILED_SEQUENCES: Dict[str, List[re.Pattern]] = {
    name: [re.compile(p, re.IGNORECASE) for p in cfg["sequence"]]
    for name, cfg in ATTACK_SEQUENCES.items()
}


def _check_sequence(history: List[str], patterns: List[re.Pattern]) -> bool:
    idx = 0
    for turn in history:
        if idx >= len(patterns):
            break
        if patterns[idx].search(turn):
            idx += 1
    return idx >= len(patterns)


def _analyze_turn(prompt: str, history: List[str]) -> Tuple[List[str], float]:
    detected: List[str] = []
    risk_increment = 0.0

    for name, pat in _COMPILED_SUSPICIOUS.items():
        if pat.search(prompt):
            detected.append(f"SUSPICIOUS_{name.upper()}")
            risk_increment += 0.15

    full_history = history + [prompt]
    for seq_name, seq_cfg in ATTACK_SEQUENCES.items():
        window = seq_cfg["window_turns"]
        relevant = full_history[-window:] if len(full_history) >= window else full_history
        if _check_sequence(relevant, _COMPILED_SEQUENCES[seq_name]):
            detected.append(f"SEQUENCE_{seq_name.upper()}")
            risk_increment += seq_cfg["severity"]

    return detected, risk_increment


# ---------------------------------------------------------------------------
# Escalation thresholds
# ---------------------------------------------------------------------------

ESCALATION_THRESHOLDS = {1: 0.3, 2: 0.6, 3: 0.85}


# ---------------------------------------------------------------------------
# Session tracker
# ---------------------------------------------------------------------------

class SessionTracker:
    """Track cumulative risk across user sessions.

    Args:
        session_ttl: Session expiry in seconds.
        decay_factor: Risk decay multiplier for consecutive benign turns.
        min_turns_for_decay: Number of benign turns before decay kicks in.
    """

    def __init__(
        self,
        session_ttl: int = 3600,
        max_sessions: int = 100_000,
        decay_factor: float = 0.95,
        min_turns_for_decay: int = 3,
    ):
        self.sessions: Dict[str, SessionRiskProfile] = {}
        self.session_ttl = session_ttl
        self.max_sessions = max_sessions
        self.decay_factor = decay_factor
        self.min_turns_for_decay = min_turns_for_decay

    def get_or_create(self, session_id: str, user_id: Optional[str] = None) -> SessionRiskProfile:
        if len(self.sessions) > self.max_sessions * 0.9:
            self._cleanup_expired()
        if session_id not in self.sessions or self.sessions[session_id].is_expired(self.session_ttl):
            self.sessions[session_id] = SessionRiskProfile(
                session_id=session_id,
                user_id=user_id,
                created_at=time.time(),
                last_activity=time.time(),
            )
        return self.sessions[session_id]

    def record_turn(
        self,
        session_id: str,
        prompt: str,
        risk_score: float = 0.0,
        detector_codes: Optional[List[str]] = None,
        user_id: Optional[str] = None,
        response_refused: bool = False,
    ) -> Dict:
        """Record a conversation turn and return updated session analysis."""
        session = self.get_or_create(session_id, user_id)

        patterns_detected, context_risk = _analyze_turn(prompt, session.prompt_history)
        turn_risk = min(1.0, risk_score + context_risk)

        turn = TurnAnalysis(
            turn_number=len(session.turns) + 1,
            timestamp=time.time(),
            prompt_hash=hashlib.sha256(prompt.encode()).hexdigest()[:16],
            risk_score=turn_risk,
            flags=patterns_detected,
            detector_codes=detector_codes or [],
            response_was_refused=response_refused,
        )
        session.turns.append(turn)

        session.prompt_history.append(prompt)
        if len(session.prompt_history) > 10:
            session.prompt_history = session.prompt_history[-10:]

        self._update_cumulative_risk(session, turn)
        old_level = session.escalation_level
        session.escalation_level = self._calc_escalation(session)

        if response_refused:
            session.blocked_count += 1
            session.cumulative_risk = min(1.0, session.cumulative_risk + 0.1)

        session.last_activity = time.time()

        return {
            "session_id": session_id,
            "turn_number": turn.turn_number,
            "turn_risk": turn_risk,
            "cumulative_risk": session.cumulative_risk,
            "escalation_level": session.escalation_level,
            "patterns_detected": patterns_detected,
            "requires_enhanced_scrutiny": session.escalation_level >= 1,
            "recommend_block": session.escalation_level >= 3,
            "blocked_count": session.blocked_count,
        }

    def should_block(self, session_id: str) -> bool:
        if session_id not in self.sessions:
            return False
        s = self.sessions[session_id]
        return s.escalation_level >= 3 or s.blocked_count >= 5 or (s.cumulative_risk > 0.9 and len(s.turns) > 3)

    def get_analysis(self, session_id: str) -> Optional[Dict]:
        if session_id not in self.sessions:
            return None
        s = self.sessions[session_id]
        return {
            "session_id": session_id,
            "user_id": s.user_id,
            "total_turns": len(s.turns),
            "cumulative_risk": s.cumulative_risk,
            "escalation_level": s.escalation_level,
            "blocked_count": s.blocked_count,
            "suspicious_patterns": s.suspicious_patterns,
            "high_risk_turns": sum(1 for t in s.turns if t.risk_score > 0.6),
        }

    def _update_cumulative_risk(self, session: SessionRiskProfile, turn: TurnAnalysis) -> None:
        recent = session.turns[-self.min_turns_for_decay:]
        benign_streak = sum(1 for t in recent if t.risk_score < 0.3)
        if benign_streak >= self.min_turns_for_decay:
            session.cumulative_risk *= self.decay_factor
        session.cumulative_risk = min(1.0, session.cumulative_risk + turn.risk_score * 0.3)
        for flag in turn.flags:
            if flag not in session.suspicious_patterns:
                session.suspicious_patterns.append(flag)

    def _calc_escalation(self, session: SessionRiskProfile) -> int:
        for level in (3, 2, 1):
            if session.cumulative_risk >= ESCALATION_THRESHOLDS[level]:
                return level
        return 0

    def _cleanup_expired(self) -> None:
        expired = [sid for sid, s in self.sessions.items() if s.is_expired(self.session_ttl)]
        for sid in expired:
            del self.sessions[sid]

    def get_stats(self) -> Dict:
        if not self.sessions:
            return {"active_sessions": 0, "avg_cumulative_risk": 0.0, "escalated_sessions": 0}
        return {
            "active_sessions": len(self.sessions),
            "avg_cumulative_risk": sum(s.cumulative_risk for s in self.sessions.values()) / len(self.sessions),
            "escalated_sessions": sum(1 for s in self.sessions.values() if s.escalation_level > 0),
            "high_risk_sessions": sum(1 for s in self.sessions.values() if s.cumulative_risk > 0.7),
        }
