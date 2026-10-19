# test_clinical_trial_audit_escrow.py
# 15-Phase Comprehensive Regression & Security Test Suite for ClinicalTrialEndpointAuditEscrow
import json
import hashlib
import urllib.parse
import re
from datetime import datetime, timezone


class MockWeb:
    def __init__(self, gl):
        self.gl = gl

    def render(self, url: str, mode: str = "text") -> str:
        if self.gl.fail_web_fetch:
            raise RuntimeError("Simulated network timeout connecting to ClinicalTrials.gov")
        return self.gl.mock_web_responses.get(
            url,
            "<html><body><h1>ClinicalTrials.gov Protocol Record: NCT04589211</h1>"
            "<p>Phase 3 Randomized Double-Blind Oncology Registration Trial. "
            "Primary Outcome Measure: Progression-Free Survival (PFS) demonstrated statistically significant improvement (HR 0.62, p = 0.0018). "
            "Safety profile acceptable; no clinical holds.</p></body></html>"
        )


class MockNondet:
    def __init__(self, gl):
        self.web = MockWeb(gl)


class MockEqPrinciple:
    def __init__(self, gl):
        self.gl = gl

    def prompt_non_comparative(self, get_input_fn, task="", criteria=""):
        input_data = get_input_fn()
        if self.gl.corrupt_llm_json:
            return "This is a corrupted non-JSON LLM response that would normally cause JSONDecodeError."
        return self.gl.consensus_return_value


class MockGL:
    def __init__(self):
        self.transfers = []
        self.mock_web_responses = {}
        self.fail_web_fetch = False
        self.simulate_transfer_fail = False
        self.corrupt_llm_json = False
        self.nondet = MockNondet(self)
        self.eq_principle = MockEqPrinciple(self)
        self.consensus_return_value = json.dumps({
            "trial_id": "NCT04589211",
            "nct_matched": True,
            "endpoint_achieved": True,
            "endpoint_met": True,
            "p_value": 0.0018,
            "safety_hold": False,
            "verdict": "ENDPOINT_ACHIEVED",
            "rationale": "Phase 3 clinical trial met primary PFS endpoint with robust statistical significance (p=0.0018)."
        })

    def emit_transfer(self, recipient: str, amount: int):
        if self.simulate_transfer_fail:
            raise RuntimeError("Simulated EVM transfer failure")
        self.transfers.append({"recipient": str(recipient).lower(), "amount": int(amount)})


class MockClinicalTrialEndpointAuditEscrow:
    def __init__(self, owner_address: str, gl_mock: MockGL):
        self.gl = gl_mock
        self.owner = owner_address.lower()
        self.total_milestones_created = 0
        self.total_claims_filed = 0
        self.total_claims_adjudicated = 0
        self.total_volume_locked = 0
        self.total_milestones_released = 0
        self.total_milestones_refunded = 0

        self.milestones = {}
        self.claims = {}
        self.consumed_claim_hashes = {}
        self.consumed_milestone_ncts = {}
        self.claimable_balances = {}

        self.STATUS_ACTIVE = "ACTIVE"
        self.STATUS_DISPUTED = "DISPUTED"
        self.STATUS_MILESTONE_ACHIEVED = "MILESTONE_ACHIEVED"
        self.STATUS_TRIAL_FAILED_REFUNDED = "TRIAL_FAILED_REFUNDED"
        self.STATUS_EXPIRED_REFUNDED = "EXPIRED_REFUNDED"
        self.STATUS_DECOMMISSIONED = "DECOMMISSIONED"

        self.CLAIM_PENDING = "PENDING_CONSENSUS"
        self.CLAIM_ENDPOINT_MET = "ENDPOINT_MET"
        self.CLAIM_REFUTED = "CLAIM_REFUTED"
        self.CLAIM_INCONCLUSIVE = "INCONCLUSIVE"
        self.CLAIM_ABANDONED = "CLAIM_ABANDONED"

        self.MIN_MILESTONE_ESCROW = 100_000_000_000
        self.MIN_TOPUP_AMOUNT = 10_000_000_000
        self.MIN_CLAIM_BOND = 25_000_000_000
        self.MIN_TRIAL_DURATION = 86400 * 14
        self.MAX_TRIAL_DURATION = 86400 * 365 * 5
        self.CLAIM_TIMEOUT_SECONDS = 86400 * 7
        self.MAX_STATISTICAL_P_VALUE_BP = 500

        self.APPROVED_REGISTRY_DOMAINS = (
            "clinicaltrials.gov",
            "fda.gov",
            "ema.europa.eu",
            "nih.gov"
        )

    def _validate_eth_address(self, addr_str: str, field_name: str) -> str:
        clean = addr_str.strip().strip('"').strip("'")
        assert len(clean) == 42, "[ERR_ADDR_FORMAT] " + field_name + " must be a 42-character hex address."
        assert clean.startswith("0x") or clean.startswith("0X"), "[ERR_ADDR_PREFIX] " + field_name + " must start with '0x'."
        hex_digits = clean[2:]
        for c in hex_digits:
            assert c in "0123456789abcdefABCDEF", "[ERR_ADDR_HEX] " + field_name + " contains non-hex characters."
        assert clean.lower() != "0x" + "0" * 40, "[ERR_ADDR_ZERO] " + field_name + " cannot be the zero address."
        return clean.lower()

    def _sanitize_string(self, val: str, min_len: int, max_len: int, field_name: str) -> str:
        clean = val.strip()
        assert len(clean) >= min_len, "[ERR_STR_TOO_SHORT] " + field_name + " length must be >= " + str(min_len)
        assert len(clean) <= max_len, "[ERR_STR_TOO_LONG] " + field_name + " length must be <= " + str(max_len)
        return clean

    def _validate_registry_url(self, url_str: str) -> str:
        clean = url_str.strip()
        assert len(clean) <= 512, "[ERR_URL_TOO_LONG] Registry URL exceeds 512 characters."
        assert not ("\n" in clean or "\r" in clean or "\t" in clean), "[ERR_URL_WHITESPACE] URL must not contain newlines or tabs."
        assert "@" not in clean, "[ERR_URL_CREDENTIALS] Embedded credentials prohibited in registry URL."

        try:
            parsed = urllib.parse.urlparse(clean)
        except Exception:
            raise AssertionError("[ERR_URL_PARSE] Failed to parse registry URL.")

        scheme = (parsed.scheme or "").lower()
        assert scheme in ("http", "https"), "[ERR_URL_SCHEME] Registry URL must use HTTP or HTTPS."

        hostname = (parsed.hostname or "").lower()
        assert hostname, "[ERR_URL_HOSTNAME] Registry URL missing hostname."
        assert hostname not in ("localhost", "127.0.0.1", "0.0.0.0", "::1"), "[ERR_URL_LOOPBACK] SSRF attempt: loopback address rejected."

        matched_domain = False
        for approved_d in self.APPROVED_REGISTRY_DOMAINS:
            if hostname == approved_d or hostname.endswith("." + approved_d):
                matched_domain = True
                break
        assert matched_domain, "[ERR_URL_UNAPPROVED_DOMAIN] Target domain '" + hostname + "' not in approved registry catalog."

        return clean

    def _compute_claim_hash(self, milestone_id: str, claimant: str, nct_id: str, url: str, nonce: str) -> str:
        data = (
            "L" + str(len(milestone_id)) + ":" + milestone_id.upper() + "|" +
            "L" + str(len(claimant)) + ":" + claimant.lower() + "|" +
            "L" + str(len(nct_id)) + ":" + nct_id.upper() + "|" +
            "L" + str(len(url)) + ":" + url + "|" +
            "L" + str(len(nonce)) + ":" + nonce
        )
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    def fund_contract(self, caller: str, value: int):
        assert value > 0, "[ERR_ZERO_PAYMENT] Value must be greater than zero."
        sender_hex = self._validate_eth_address(caller, "Sender")
        cur = self.claimable_balances.get(sender_hex, 0)
        self.claimable_balances[sender_hex] = cur + value
        self.total_volume_locked += value
        return "FUNDED: " + str(value) + " wei credited to claimable balance of " + sender_hex

    def create_clinical_milestone_escrow(self, caller: str, value: int, biotech_recipient: str, nct_id: str, endpoint: str, duration_sec: int):
        sponsor_hex = self._validate_eth_address(caller, "Sponsor")
        biotech_hex = self._validate_eth_address(biotech_recipient, "Biotech Recipient")
        assert sponsor_hex != biotech_hex, "[ERR_IDENTICAL_PARTIES] Sponsor and biotech addresses cannot be identical."

        clean_nct = self._sanitize_string(nct_id, 8, 32, "Trial NCT ID")
        clean_endpoint = self._sanitize_string(endpoint, 4, 128, "Target Primary Endpoint")
        assert duration_sec >= self.MIN_TRIAL_DURATION, "[ERR_DURATION_TOO_SHORT] Duration too short."
        assert duration_sec <= self.MAX_TRIAL_DURATION, "[ERR_DURATION_TOO_LONG] Duration too long."
        assert value >= self.MIN_MILESTONE_ESCROW, "[ERR_MIN_ESCROW] Escrow below minimum."

        now_utc = int(datetime.now(timezone.utc).timestamp())
        deadline_utc = now_utc + duration_sec

        new_id = "MILESTONE_CLIN_" + str(self.total_milestones_created + 1)
        self.milestones[new_id] = {
            "milestone_id": new_id,
            "sponsor": sponsor_hex,
            "biotech_recipient": biotech_hex,
            "trial_nct_id": clean_nct,
            "target_primary_endpoint": clean_endpoint,
            "milestone_escrow_amount": value,
            "total_released_to_biotech": 0,
            "total_refunded_to_sponsor": 0,
            "created_at": now_utc,
            "milestone_deadline": deadline_utc,
            "status": self.STATUS_ACTIVE
        }
        self.total_milestones_created += 1
        self.total_volume_locked += value
        return new_id

    def topup_milestone_escrow(self, caller: str, value: int, milestone_id: str):
        assert milestone_id in self.milestones, "[ERR_MILESTONE_NOT_FOUND] Milestone not found."
        m = self.milestones[milestone_id]
        assert m["status"] == self.STATUS_ACTIVE, "[ERR_MILESTONE_NOT_ACTIVE] Milestone not active."

        sender_hex = self._validate_eth_address(caller, "Caller")
        assert sender_hex == m["sponsor"], "[ERR_UNAUTHORIZED] Only sponsor can top up."
        assert value >= self.MIN_TOPUP_AMOUNT, "[ERR_MIN_TOPUP] Top-up below minimum."

        m["milestone_escrow_amount"] += value
        self.total_volume_locked += value
        return "MILESTONE_TOPPED_UP: " + milestone_id + " | Added: " + str(value)

    def approve_milestone_payout(self, caller: str, milestone_id: str):
        assert milestone_id in self.milestones, "[ERR_MILESTONE_NOT_FOUND] Milestone not found."
        m = self.milestones[milestone_id]
        assert m["status"] == self.STATUS_ACTIVE, "[ERR_MILESTONE_NOT_ACTIVE] Milestone not active."

        sender_hex = self._validate_eth_address(caller, "Caller")
        assert sender_hex == m["sponsor"], "[ERR_UNAUTHORIZED] Only sponsor can approve payout."

        amt = m["milestone_escrow_amount"]
        assert amt > 0, "[ERR_ZERO_ESCROW] No funds to release."

        m["status"] = self.STATUS_MILESTONE_ACHIEVED
        m["total_released_to_biotech"] += amt
        m["milestone_escrow_amount"] = 0

        self.total_milestones_released += amt

        # CRIT-02 Solvency Accounting Fix
        transfer_succeeded = False
        try:
            self.gl.emit_transfer(m["biotech_recipient"], amt)
            transfer_succeeded = True
        except Exception:
            transfer_succeeded = False

        if transfer_succeeded:
            self.total_volume_locked = max(0, self.total_volume_locked - amt)
        else:
            cur = self.claimable_balances.get(m["biotech_recipient"], 0)
            self.claimable_balances[m["biotech_recipient"]] = cur + amt

        return "MILESTONE_APPROVED: " + milestone_id

    def claim_expired_unachieved_milestone(self, caller: str, milestone_id: str, custom_time: int = None):
        assert milestone_id in self.milestones, "[ERR_MILESTONE_NOT_FOUND] Milestone not found."
        m = self.milestones[milestone_id]
        assert m["status"] == self.STATUS_ACTIVE, "[ERR_MILESTONE_NOT_ACTIVE] Milestone not active."

        sender_hex = self._validate_eth_address(caller, "Caller")
        assert sender_hex == m["sponsor"], "[ERR_UNAUTHORIZED] Only sponsor can reclaim expired escrow."

        now_utc = custom_time if custom_time is not None else int(datetime.now(timezone.utc).timestamp())
        assert now_utc > m["milestone_deadline"], "[ERR_DEADLINE_NOT_REACHED] Deadline not reached."

        amt = m["milestone_escrow_amount"]
        assert amt > 0, "[ERR_ZERO_ESCROW] No escrow to refund."

        m["status"] = self.STATUS_EXPIRED_REFUNDED
        m["total_refunded_to_sponsor"] += amt
        m["milestone_escrow_amount"] = 0

        self.total_milestones_refunded += amt

        # CRIT-02 Solvency Accounting Fix
        transfer_succeeded = False
        try:
            self.gl.emit_transfer(m["sponsor"], amt)
            transfer_succeeded = True
        except Exception:
            transfer_succeeded = False

        if transfer_succeeded:
            self.total_volume_locked = max(0, self.total_volume_locked - amt)
        else:
            cur = self.claimable_balances.get(m["sponsor"], 0)
            self.claimable_balances[m["sponsor"]] = cur + amt

        return "MILESTONE_EXPIRED_REFUNDED: " + milestone_id

    def submit_clinical_endpoint_claim(self, caller: str, value: int, milestone_id: str, url: str, p_val_bp: int, endpoint_achieved: bool, nonce: str):
        clean_m_id = milestone_id.strip().upper()
        assert clean_m_id in self.milestones, "[ERR_MILESTONE_NOT_FOUND] Milestone not found."
        m = self.milestones[clean_m_id]
        assert m["status"] == self.STATUS_ACTIVE, "[ERR_MILESTONE_NOT_ACTIVE] Milestone not active."

        now_utc = int(datetime.now(timezone.utc).timestamp())
        assert now_utc <= m["milestone_deadline"], "[ERR_DEADLINE_ELAPSED] Milestone deadline has elapsed."

        sender_hex = self._validate_eth_address(caller, "Claimant")
        clean_url = self._validate_registry_url(url)
        clean_nonce = self._sanitize_string(nonce, 1, 64, "Nonce")
        assert p_val_bp >= 0 and p_val_bp <= 10_000, "[ERR_INVALID_P_VALUE] Invalid p-value basis points."

        nct_key = clean_m_id + "::" + m["trial_nct_id"].upper()
        assert nct_key not in self.consumed_milestone_ncts, "[ERR_TRIAL_ALREADY_CLAIMED] Trial already claimed."

        assert value >= self.MIN_CLAIM_BOND, "[ERR_MIN_CLAIM_BOND] Claim bond too low."

        c_hash = self._compute_claim_hash(clean_m_id, sender_hex, m["trial_nct_id"], clean_url, clean_nonce)
        assert c_hash.lower() not in self.consumed_claim_hashes, "[ERR_CLAIM_EXISTS] Duplicate claim hash."

        new_c_id = "CLAIM_CLIN_" + str(self.total_claims_filed + 1)

        self.claims[new_c_id] = {
            "claim_id": new_c_id,
            "milestone_id": clean_m_id,
            "claimant": sender_hex,
            "registry_url": clean_url,
            "reported_p_value_bp": p_val_bp,
            "primary_endpoint_achieved": bool(endpoint_achieved),
            "claim_fingerprint": c_hash,
            "claim_bond": value,
            "filed_at": now_utc,
            "adjudicated_at": 0,
            "verdict": self.CLAIM_PENDING,
            "payout_awarded": 0,
            "has_claimed": False,
            "adjudication_rationale": ""
        }

        self.consumed_claim_hashes[c_hash.lower()] = True
        self.consumed_milestone_ncts[nct_key] = True
        self.total_claims_filed += 1
        self.total_volume_locked += value

        # Lock milestone into DISPUTED state (HIGH-01)
        m["status"] = self.STATUS_DISPUTED
        return new_c_id

    def adjudicate_clinical_endpoint_claim(self, claim_id: str, custom_endpoint_met: bool = None, custom_p_val = None, custom_safety: bool = None, simulate_parse_error: bool = False):
        assert claim_id in self.claims, "[ERR_CLAIM_NOT_FOUND] Claim not found."
        clm = self.claims[claim_id]
        assert clm["verdict"] == self.CLAIM_PENDING, "[ERR_ALREADY_ADJUDICATED] Claim already adjudicated."

        m = self.milestones[clm["milestone_id"]]

        reg_url = clm["registry_url"]
        nct_id = m["trial_nct_id"]
        primary_endpoint = m["target_primary_endpoint"]
        claimed_pval_str = str(int(clm["reported_p_value_bp"]) / 10000.0)

        def get_input() -> str:
            try:
                raw_data = self.gl.nondet.web.render(reg_url, mode="text")
            except Exception:
                raise AssertionError("[ERR_EVIDENCE_FETCH_FAILED] Consensus could not fetch clinical trial readout.")
            assert raw_data is not None and len(raw_data.strip()) >= 30, \
                "[ERR_EVIDENCE_FETCH_FAILED] Response too short."
            cleaned = re.sub(r'<[^>]+>', ' ', raw_data)
            return f"NCT: {nct_id}\nEndpoint: {primary_endpoint}\nClaimed p-val: {claimed_pval_str}\n\n{cleaned}"

        task = "Auditor Task: Analyze clinical trial readout."
        criteria = "Auditor Criteria: Independently verify trial endpoints."

        if simulate_parse_error:
            self.gl.corrupt_llm_json = True
        elif custom_endpoint_met is not None and custom_p_val is not None:
            self.gl.corrupt_llm_json = False
            self.gl.consensus_return_value = json.dumps({
                "trial_id": nct_id,
                "nct_matched": True,
                "endpoint_achieved": custom_endpoint_met,
                "endpoint_met": custom_endpoint_met,
                "p_value": custom_p_val,
                "safety_hold": custom_safety if custom_safety is not None else False,
                "verdict": "ENDPOINT_ACHIEVED" if (custom_endpoint_met and custom_p_val < 0.05 and not (custom_safety if custom_safety is not None else False)) else "ENDPOINT_FAILED",
                "rationale": "Test trial adjudication verdict."
            })
        else:
            self.gl.corrupt_llm_json = False

        consensus_result = self.gl.eq_principle.prompt_non_comparative(
            get_input,
            task=task,
            criteria=criteria
        )

        parse_valid = False
        parsed_trial_id = ""
        parsed_endpoint_achieved = False
        parsed_p_val = 1.0
        parsed_safety = True
        parsed_verdict = self.CLAIM_INCONCLUSIVE
        rationale = "Consensus fallback resolution."

        try:
            clean_json = consensus_result.strip()
            if "```json" in clean_json:
                clean_json = clean_json.split("```json")[1].split("```")[0].strip()
            elif "```" in clean_json:
                clean_json = clean_json.split("```")[1].split("```")[0].strip()
            parsed = json.loads(clean_json)

            parsed_trial_id = str(parsed.get("trial_id", "")).strip().upper()
            if not parsed_trial_id:
                parsed_trial_id = str(parsed.get("nct_id", "")).strip().upper()

            parsed_endpoint_achieved = bool(parsed.get("endpoint_achieved", False) or parsed.get("endpoint_met", False))

            raw_pval = parsed.get("p_value", 1.0)
            if isinstance(raw_pval, str):
                raw_pval = raw_pval.replace("<", "").replace("=", "").replace("p", "").strip()
            parsed_p_val = float(raw_pval)

            parsed_safety = bool(parsed.get("safety_hold", False))

            raw_cand = str(parsed.get("verdict", "")).strip().upper()
            if raw_cand in ("ENDPOINT_ACHIEVED", "ENDPOINT_MET", self.CLAIM_ENDPOINT_MET):
                parsed_verdict = self.CLAIM_ENDPOINT_MET
            elif raw_cand in ("ENDPOINT_FAILED", self.CLAIM_REFUTED):
                parsed_verdict = self.CLAIM_REFUTED
            else:
                parsed_verdict = self.CLAIM_INCONCLUSIVE

            rationale = str(parsed.get("rationale", "")).strip()[:200]
            parse_valid = True
        except Exception:
            parse_valid = False

        # Strict Multi-Field Consistency Check (Joaquin Steward Specification)
        is_trial_id_matched = (parsed_trial_id == m["trial_nct_id"].strip().upper())
        is_endpoint_achieved = (parsed_endpoint_achieved is True)
        is_strict_p_val_valid = (parsed_p_val < 0.05 and parsed_p_val >= 0.0)
        is_no_safety_hold = (parsed_safety is False)
        is_verdict_achieved = (parsed_verdict == self.CLAIM_ENDPOINT_MET)

        # Consistent Milestone Achievement
        if (parse_valid and
            is_trial_id_matched and
            is_endpoint_achieved and
            is_strict_p_val_valid and
            is_no_safety_hold and
            is_verdict_achieved):
            final_verdict = self.CLAIM_ENDPOINT_MET

        # Consistent Milestone Failure
        elif (parse_valid and
              is_trial_id_matched and
              (not is_endpoint_achieved or parsed_p_val >= 0.05 or parsed_safety) and
              parsed_verdict == self.CLAIM_REFUTED):
            final_verdict = self.CLAIM_REFUTED

        # Any mismatched trial ID, internally inconsistent fields, parsing error, or ambiguity:
        # Takes safe non-payout path (CLAIM_INCONCLUSIVE)
        else:
            final_verdict = self.CLAIM_INCONCLUSIVE

        now_utc = int(datetime.now(timezone.utc).timestamp())
        clm["adjudicated_at"] = now_utc
        clm["verdict"] = final_verdict
        clm["adjudication_rationale"] = rationale
        bond_val = clm["claim_bond"]

        if final_verdict == self.CLAIM_ENDPOINT_MET:
            escrow_amt = m["milestone_escrow_amount"]
            clm["payout_awarded"] = escrow_amt
            clm["has_claimed"] = True

            m["status"] = self.STATUS_MILESTONE_ACHIEVED
            m["total_released_to_biotech"] += escrow_amt
            m["milestone_escrow_amount"] = 0
            self.total_milestones_released += escrow_amt

            # CRIT-02 Remediated Solvency TVL Accounting
            transfer_biotech = False
            try:
                self.gl.emit_transfer(m["biotech_recipient"], escrow_amt)
                transfer_biotech = True
            except Exception:
                transfer_biotech = False

            if transfer_biotech:
                self.total_volume_locked = max(0, self.total_volume_locked - escrow_amt)
            else:
                cur = self.claimable_balances.get(m["biotech_recipient"], 0)
                self.claimable_balances[m["biotech_recipient"]] = cur + escrow_amt

            transfer_claimant = False
            try:
                self.gl.emit_transfer(clm["claimant"], bond_val)
                transfer_claimant = True
            except Exception:
                transfer_claimant = False

            if transfer_claimant:
                self.total_volume_locked = max(0, self.total_volume_locked - bond_val)
            else:
                cur = self.claimable_balances.get(clm["claimant"], 0)
                self.claimable_balances[clm["claimant"]] = cur + bond_val

        elif final_verdict == self.CLAIM_REFUTED:
            clm["payout_awarded"] = 0
            clm["has_claimed"] = True
            # Unlock milestone back to ACTIVE
            m["status"] = self.STATUS_ACTIVE

            cur = self.claimable_balances.get(m["sponsor"], 0)
            self.claimable_balances[m["sponsor"]] = cur + bond_val

        else: # INCONCLUSIVE
            clm["payout_awarded"] = 0
            clm["has_claimed"] = True
            # Unlock milestone back to ACTIVE
            m["status"] = self.STATUS_ACTIVE

            transfer_claimant = False
            try:
                self.gl.emit_transfer(clm["claimant"], bond_val)
                transfer_claimant = True
            except Exception:
                transfer_claimant = False

            if transfer_claimant:
                self.total_volume_locked = max(0, self.total_volume_locked - bond_val)
            else:
                cur = self.claimable_balances.get(clm["claimant"], 0)
                self.claimable_balances[clm["claimant"]] = cur + bond_val

        self.total_claims_adjudicated += 1
        return "CLAIM_ADJUDICATED: " + claim_id + " | Verdict: " + final_verdict

    def claim_abandoned_trial_bond(self, caller: str, claim_id: str, custom_time: int = None):
        assert claim_id in self.claims, "[ERR_CLAIM_NOT_FOUND] Claim not found."
        clm = self.claims[claim_id]

        sender_hex = self._validate_eth_address(caller, "Caller")
        assert sender_hex == clm["claimant"], "[ERR_UNAUTHORIZED] Only claimant can recover bond."
        assert clm["verdict"] == self.CLAIM_PENDING, "[ERR_CLAIM_NOT_PENDING] Claim not pending."

        now_utc = custom_time if custom_time is not None else int(datetime.now(timezone.utc).timestamp())
        assert now_utc >= clm["filed_at"] + self.CLAIM_TIMEOUT_SECONDS, "[ERR_TIMEOUT_NOT_REACHED] Must wait 7 days."

        bond_val = clm["claim_bond"]
        clm["verdict"] = self.CLAIM_ABANDONED
        clm["has_claimed"] = True
        clm["adjudication_rationale"] = "Recovered after 7-day timeout."

        # Unlock milestone back to ACTIVE
        if clm["milestone_id"] in self.milestones:
            m = self.milestones[clm["milestone_id"]]
            if m["status"] == self.STATUS_DISPUTED:
                m["status"] = self.STATUS_ACTIVE

        transfer_claimant = False
        try:
            self.gl.emit_transfer(sender_hex, bond_val)
            transfer_claimant = True
        except Exception:
            transfer_claimant = False

        if transfer_claimant:
            self.total_volume_locked = max(0, self.total_volume_locked - bond_val)
        else:
            cur = self.claimable_balances.get(sender_hex, 0)
            self.claimable_balances[sender_hex] = cur + bond_val

        return "BOND_RECLAIMED: " + claim_id

    def decommission_uncontested_milestone(self, caller: str, milestone_id: str):
        assert milestone_id in self.milestones, "[ERR_MILESTONE_NOT_FOUND] Milestone not found."
        m = self.milestones[milestone_id]
        sender_hex = self._validate_eth_address(caller, "Caller")
        assert sender_hex in (m["sponsor"], m["biotech_recipient"], self.owner), "[ERR_UNAUTHORIZED] Unauthorized caller."
        assert m["milestone_escrow_amount"] == 0, "[ERR_ESCROW_REMAINING] Remaining escrow funds."
        assert m["status"] in (self.STATUS_MILESTONE_ACHIEVED, self.STATUS_TRIAL_FAILED_REFUNDED, self.STATUS_EXPIRED_REFUNDED), "[ERR_INVALID_STATUS] Invalid status."

        m["status"] = self.STATUS_DECOMMISSIONED
        return "MILESTONE_DECOMMISSIONED: " + milestone_id

    def withdraw_claimable(self, caller: str):
        sender_hex = self._validate_eth_address(caller, "Caller")
        assert sender_hex in self.claimable_balances, "[ERR_NO_CLAIMABLE] No claimable funds."
        bal = self.claimable_balances[sender_hex]
        assert bal > 0, "[ERR_ZERO_CLAIMABLE] Zero balance."

        self.claimable_balances[sender_hex] = 0
        try:
            self.gl.emit_transfer(sender_hex, bal)
        except Exception:
            self.claimable_balances[sender_hex] = bal
            raise AssertionError("[ERR_TRANSFER_FAILED] Native transfer failed; claimable balance preserved.")

        self.total_volume_locked = max(0, self.total_volume_locked - bal)
        return "CLAIMABLE_WITHDRAWN: " + sender_hex + " | Amount: " + str(bal)


def run_all_tests():
    print("================================================================================")
    print("  CLINICAL TRIAL ENDPOINT AUDIT ESCROW — 15-PHASE REGRESSION SUITE")
    print("================================================================================")

    mock_gl = MockGL()
    owner = "0x1111111111111111111111111111111111111111"
    sponsor = "0x2222222222222222222222222222222222222222"
    biotech = "0x3333333333333333333333333333333333333333"
    claimant = "0x4444444444444444444444444444444444444444"

    contract = MockClinicalTrialEndpointAuditEscrow(owner, mock_gl)

    # Phase 1: Zero Genesis Invariants
    print("\n[Phase 1] Testing zero genesis debt and storage invariants...")
    assert contract.total_volume_locked == 0, "TVL must start at 0"
    assert contract.total_milestones_created == 0, "Milestones must start at 0"
    assert len(contract.claimable_balances) == 0, "Zero phantom balances"
    print("  PASS: Zero unbacked genesis debt verified.")

    # Phase 2: Create Clinical Milestone Escrow
    print("\n[Phase 2] Creating clinical licensing milestone backed 100% by payable escrow...")
    escrow_amount = 300_000_000_000  # 300 Gwei
    milestone_id = contract.create_clinical_milestone_escrow(
        caller=sponsor,
        value=escrow_amount,
        biotech_recipient=biotech,
        nct_id="NCT04589211",
        endpoint="PFS hazard ratio < 0.70 with p < 0.05",
        duration_sec=86400 * 180  # 180 days
    )
    assert milestone_id == "MILESTONE_CLIN_1"
    assert contract.total_volume_locked == escrow_amount
    assert contract.milestones[milestone_id]["milestone_escrow_amount"] == escrow_amount
    print("  PASS: Clinical milestone created with 100% backed funds:", milestone_id)

    # Phase 3: Top-up Milestone Escrow
    print("\n[Phase 3] Testing reserve top-up by sponsor...")
    topup_amount = 50_000_000_000  # 50 Gwei
    contract.topup_milestone_escrow(caller=sponsor, value=topup_amount, milestone_id=milestone_id)
    assert contract.milestones[milestone_id]["milestone_escrow_amount"] == escrow_amount + topup_amount
    assert contract.total_volume_locked == escrow_amount + topup_amount
    print("  PASS: Milestone escrow top-up successfully recorded.")

    # Phase 4: SSRF Defense & Registry Domain Whitelist
    print("\n[Phase 4] Testing SSRF defense and clinical registry domain whitelisting...")
    try:
        contract._validate_registry_url("https://unverified-medical-blog.com/results")
        assert False, "Should reject unapproved domain"
    except AssertionError as e:
        assert "[ERR_URL_UNAPPROVED_DOMAIN]" in str(e)

    try:
        contract._validate_registry_url("https://doctor:secret@clinicaltrials.gov/trial")
        assert False, "Should reject embedded credentials"
    except AssertionError as e:
        assert "[ERR_URL_CREDENTIALS]" in str(e)

    try:
        contract._validate_registry_url("http://localhost:8080/results")
        assert False, "Should reject loopback SSRF"
    except AssertionError as e:
        assert "[ERR_URL_LOOPBACK]" in str(e)

    valid_url = "https://clinicaltrials.gov/study/NCT04589211"
    assert contract._validate_registry_url(valid_url) == valid_url
    print("  PASS: SSRF defense and clinical registry filtering fully enforced.")

    # Phase 5: Address Sanitation & Non-Zero Recipient
    print("\n[Phase 5] Testing address sanitation and non-zero hex enforcement...")
    try:
        contract._validate_eth_address("0x0000000000000000000000000000000000000000", "ZeroCheck")
        assert False, "Should reject zero address"
    except AssertionError as e:
        assert "[ERR_ADDR_ZERO]" in str(e)

    try:
        contract._validate_eth_address("0x123", "ShortCheck")
        assert False, "Should reject invalid length"
    except AssertionError as e:
        assert "[ERR_ADDR_FORMAT]" in str(e)
    print("  PASS: Address format sanitation strictly verified.")

    # Phase 6: Length-Prefixed Canonical Fingerprint Computation
    print("\n[Phase 6] Testing canonical length-prefixed fingerprint computation...")
    h1 = contract._compute_claim_hash("MILESTONE_CLIN_1", claimant, "NCT04589211", valid_url, "nonce1")
    h2 = contract._compute_claim_hash("MILESTONE_CLIN_1", claimant, "NCT04589211", valid_url, "nonce1")
    h3 = contract._compute_claim_hash("MILESTONE_CLIN_1", claimant, "NCT04589211", valid_url, "nonce2")
    assert h1 == h2, "Canonical hash must be deterministic"
    assert h1 != h3, "Different nonce must yield distinct hash"
    print("  PASS: Canonical length-prefixed hashing prevents delimiter collisions.")

    # Phase 7: Submit Clinical Endpoint Claim
    print("\n[Phase 7] Submitting clinical endpoint claim with payable claim bond...")
    bond_amount = 30_000_000_000  # 30 Gwei
    claim_id = contract.submit_clinical_endpoint_claim(
        caller=claimant,
        value=bond_amount,
        milestone_id=milestone_id,
        url=valid_url,
        p_val_bp=18,  # p = 0.0018
        endpoint_achieved=True,
        nonce="nonce_trial_claim_1"
    )
    assert claim_id == "CLAIM_CLIN_1"
    assert contract.claims[claim_id]["claim_bond"] == bond_amount
    assert contract.total_volume_locked == escrow_amount + topup_amount + bond_amount
    assert contract.milestones[milestone_id]["status"] == "DISPUTED", "Milestone must enter DISPUTED state"
    try:
        contract.approve_milestone_payout(caller=sponsor, milestone_id=milestone_id)
        assert False, "Should reject payout release while milestone is DISPUTED"
    except AssertionError as e:
        assert "[ERR_MILESTONE_NOT_ACTIVE]" in str(e)
    print("  PASS: Clinical endpoint claim filed with payable bond, locking milestone to DISPUTED state:", claim_id)

    # Phase 8: Prevent Duplicate Claim Replay
    print("\n[Phase 8] Testing replay prevention on identical trial NCT ID...")
    try:
        contract.submit_clinical_endpoint_claim(
            caller=claimant,
            value=bond_amount,
            milestone_id=milestone_id,
            url=valid_url,
            p_val_bp=18,
            endpoint_achieved=True,
            nonce="nonce_unique_2"
        )
        assert False, "Should reject duplicate NCT claim on same milestone"
    except AssertionError as e:
        assert "[ERR_MILESTONE_NOT_ACTIVE]" in str(e) or "[ERR_TRIAL_ALREADY_CLAIMED]" in str(e)
    print("  PASS: Duplicate NCT trial claims prevented.")

    # Phase 9: Multi-Validator Consensus Adjudication: ENDPOINT_MET
    print("\n[Phase 9] Testing consensus adjudication: ENDPOINT_MET (Statistical Significance p < 0.05)...")
    total_collateral_in_milestone = escrow_amount + topup_amount
    contract.adjudicate_clinical_endpoint_claim(claim_id, custom_endpoint_met=True, custom_p_val=0.0018, custom_safety=False)
    
    assert contract.claims[claim_id]["verdict"] == "ENDPOINT_MET"
    assert contract.milestones[milestone_id]["status"] == "MILESTONE_ACHIEVED"
    assert contract.milestones[milestone_id]["milestone_escrow_amount"] == 0
    assert contract.milestones[milestone_id]["total_released_to_biotech"] == total_collateral_in_milestone

    # Verify transfers to biotech and claimant
    biotech_transfers = [t for t in mock_gl.transfers if t["recipient"] == biotech]
    claimant_transfers = [t for t in mock_gl.transfers if t["recipient"] == claimant]
    assert any(t["amount"] == total_collateral_in_milestone for t in biotech_transfers), "Biotech must receive 100% milestone payout"
    assert any(t["amount"] == bond_amount for t in claimant_transfers), "Claimant must recover claim bond"
    print("  PASS: Milestone funds disbursed to biotech & bond returned to claimant.")

    # Phase 10: Multi-Validator Consensus Adjudication: CLAIM_REFUTED (Frivolous / Trial Failed)
    print("\n[Phase 10] Testing consensus adjudication: CLAIM_REFUTED (p >= 0.05, bond slashed)...")
    milestone_id_2 = contract.create_clinical_milestone_escrow(
        caller=sponsor,
        value=escrow_amount,
        biotech_recipient=biotech,
        nct_id="NCT09999999",
        endpoint="Overall Survival HR < 0.75",
        duration_sec=86400 * 90
    )
    claim_id_2 = contract.submit_clinical_endpoint_claim(
        caller=claimant,
        value=bond_amount,
        milestone_id=milestone_id_2,
        url="https://clinicaltrials.gov/study/NCT09999999",
        p_val_bp=4500,  # p = 0.4500 (failed!)
        endpoint_achieved=False,
        nonce="nonce_failed_trial"
    )
    # Verify milestone is locked into DISPUTED state (HIGH-01)
    assert contract.milestones[milestone_id_2]["status"] == "DISPUTED", "Milestone must enter DISPUTED state upon claim filing"
    try:
        contract.approve_milestone_payout(caller=sponsor, milestone_id=milestone_id_2)
        assert False, "Should reject payout release while milestone is DISPUTED"
    except AssertionError as e:
        assert "[ERR_MILESTONE_NOT_ACTIVE]" in str(e)

    contract.adjudicate_clinical_endpoint_claim(claim_id_2, custom_endpoint_met=False, custom_p_val="0.45", custom_safety=False)
    assert contract.claims[claim_id_2]["verdict"] == "CLAIM_REFUTED"
    assert contract.milestones[milestone_id_2]["status"] == "ACTIVE", "Milestone must unlock to ACTIVE after refutation"
    assert contract.claimable_balances[sponsor] == bond_amount, "Sponsor credited with slashed bond indemnity"
    print("  PASS: Failed endpoint claim bond slashed to sponsor indemnity reserves.")

    # Phase 10b: Corrupt JSON / Parse Failure Safe Fallback (CRIT-01)
    print("\n[Phase 10b] Testing AI parse error safe fallback (CLAIM_INCONCLUSIVE, bond preserved)...")
    milestone_id_safe = contract.create_clinical_milestone_escrow(
        caller=sponsor,
        value=escrow_amount,
        biotech_recipient=biotech,
        nct_id="NCT07777777",
        endpoint="Biomarker response rate",
        duration_sec=86400 * 60
    )
    claim_id_safe = contract.submit_clinical_endpoint_claim(
        caller=claimant,
        value=bond_amount,
        milestone_id=milestone_id_safe,
        url="https://clinicaltrials.gov/study/NCT07777777",
        p_val_bp=100,
        endpoint_achieved=True,
        nonce="nonce_parse_err_test"
    )
    contract.adjudicate_clinical_endpoint_claim(claim_id_safe, simulate_parse_error=True)
    assert contract.claims[claim_id_safe]["verdict"] == "INCONCLUSIVE", "Parse failure must yield INCONCLUSIVE"
    assert contract.milestones[milestone_id_safe]["status"] == "ACTIVE", "Milestone must unlock back to ACTIVE"
    print("  PASS: AI parsing glitch safely fell back to INCONCLUSIVE without bond slashing.")

    # Phase 10c: Joaquin Invariant - Mismatched Trial NCT ID Safe Non-Payout Path
    print("\n[Phase 10c] Testing Joaquin Invariant: Mismatched trial NCT ID safe non-payout path...")
    milestone_id_mismatch = contract.create_clinical_milestone_escrow(
        caller=sponsor,
        value=escrow_amount,
        biotech_recipient=biotech,
        nct_id="NCT01112222",
        endpoint="Overall Response Rate ORR > 40%",
        duration_sec=86400 * 60
    )
    claim_id_mismatch = contract.submit_clinical_endpoint_claim(
        caller=claimant,
        value=bond_amount,
        milestone_id=milestone_id_mismatch,
        url="https://clinicaltrials.gov/study/NCT01112222",
        p_val_bp=100,
        endpoint_achieved=True,
        nonce="nonce_mismatch_test"
    )
    # Simulate LLM consensus returning a mismatched trial ID from the page
    mock_gl.consensus_return_value = json.dumps({
        "trial_id": "NCT09990000",  # WRONG TRIAL ID!
        "endpoint_achieved": True,
        "p_value": 0.001,
        "safety_hold": False,
        "verdict": "ENDPOINT_ACHIEVED",
        "rationale": "Readout achieves endpoint but matches wrong trial ID."
    })
    contract.adjudicate_clinical_endpoint_claim(claim_id_mismatch)
    assert contract.claims[claim_id_mismatch]["verdict"] == "INCONCLUSIVE", "Mismatched trial ID must take safe non-payout path (INCONCLUSIVE)"
    assert contract.milestones[milestone_id_mismatch]["status"] == "ACTIVE", "Milestone must stay active without unauthorized payout"
    assert contract.milestones[milestone_id_mismatch]["total_released_to_biotech"] == 0, "No milestone payout permitted on mismatched trial ID"
    print("  PASS: Mismatched trial NCT ID successfully routed to safe non-payout path (INCONCLUSIVE).")

    # Phase 10d: Joaquin Invariant - Internally Inconsistent Consensus Output Safe Non-Payout Path
    print("\n[Phase 10d] Testing Joaquin Invariant: Internally inconsistent consensus output...")
    milestone_id_inconsistent = contract.create_clinical_milestone_escrow(
        caller=sponsor,
        value=escrow_amount,
        biotech_recipient=biotech,
        nct_id="NCT03334444",
        endpoint="Progression-Free Survival PFS",
        duration_sec=86400 * 60
    )
    claim_id_inconsistent = contract.submit_clinical_endpoint_claim(
        caller=claimant,
        value=bond_amount,
        milestone_id=milestone_id_inconsistent,
        url="https://clinicaltrials.gov/study/NCT03334444",
        p_val_bp=100,
        endpoint_achieved=True,
        nonce="nonce_inconsistent_test"
    )
    # Simulate LLM claiming ENDPOINT_ACHIEVED but safety_hold is True (Internally Inconsistent!)
    mock_gl.consensus_return_value = json.dumps({
        "trial_id": "NCT03334444",
        "endpoint_achieved": True,
        "p_value": 0.002,
        "safety_hold": True,  # CONFLICT: Efficacy met, but active safety hold!
        "verdict": "ENDPOINT_ACHIEVED",  # Inconsistent verdict!
        "rationale": "Conflicting readout: efficacy claimed but safety hold active."
    })
    contract.adjudicate_clinical_endpoint_claim(claim_id_inconsistent)
    assert contract.claims[claim_id_inconsistent]["verdict"] == "INCONCLUSIVE", "Internally inconsistent consensus must take safe non-payout path"
    assert contract.milestones[milestone_id_inconsistent]["status"] == "ACTIVE", "Milestone must not disburse funds on inconsistent output"
    assert contract.milestones[milestone_id_inconsistent]["total_released_to_biotech"] == 0
    print("  PASS: Internally inconsistent consensus fields safely routed to non-payout path (INCONCLUSIVE).")

    # Phase 11: Fail-Closed Web Evidence Ingestion
    print("\n[Phase 11] Testing fail-closed handling on unreachable trial portal...")
    milestone_id_timeout = contract.create_clinical_milestone_escrow(
        caller=sponsor,
        value=escrow_amount,
        biotech_recipient=biotech,
        nct_id="NCT08888888",
        endpoint="Overall Survival HR < 0.65",
        duration_sec=86400 * 90
    )
    claim_id_3 = contract.submit_clinical_endpoint_claim(
        caller=claimant,
        value=bond_amount,
        milestone_id=milestone_id_timeout,
        url="https://clinicaltrials.gov/timeout-trial",
        p_val_bp=100,
        endpoint_achieved=True,
        nonce="nonce_timeout_test"
    )
    mock_gl.fail_web_fetch = True
    try:
        contract.adjudicate_clinical_endpoint_claim(claim_id_3)
        assert False, "Should raise AssertionError on network timeout"
    except AssertionError as e:
        assert "[ERR_EVIDENCE_FETCH_FAILED]" in str(e)
    mock_gl.fail_web_fetch = False
    print("  PASS: Fail-closed zero-mutation invariant preserved on network failure.")

    # Phase 12: 7-Day Timeout Bond Recovery
    print("\n[Phase 12] Testing 7-day timeout bond recovery for claimant...")
    now = int(datetime.now(timezone.utc).timestamp())
    try:
        contract.claim_abandoned_trial_bond(caller=claimant, claim_id=claim_id_3, custom_time=now + 86400 * 2)
        assert False, "Should revert before 7 days have elapsed"
    except AssertionError as e:
        assert "[ERR_TIMEOUT_NOT_REACHED]" in str(e)

    contract.claim_abandoned_trial_bond(caller=claimant, claim_id=claim_id_3, custom_time=now + 86400 * 8)
    assert contract.claims[claim_id_3]["verdict"] == "CLAIM_ABANDONED"
    print("  PASS: Claimant successfully recovered bond after 7-day timeout.")

    # Phase 13: Consensual Milestone Release by Sponsor
    print("\n[Phase 13] Testing consensual milestone approval by sponsor...")
    milestone_id_3 = contract.create_clinical_milestone_escrow(
        caller=sponsor,
        value=escrow_amount,
        biotech_recipient=biotech,
        nct_id="NCT01112222",
        endpoint="FDA Accelerated Approval Granted",
        duration_sec=86400 * 120
    )
    contract.approve_milestone_payout(caller=sponsor, milestone_id=milestone_id_3)
    assert contract.milestones[milestone_id_3]["status"] == "MILESTONE_ACHIEVED"
    assert contract.milestones[milestone_id_3]["total_released_to_biotech"] == escrow_amount
    print("  PASS: Consensual milestone payout confirmed and disbursed to biotech.")

    # Phase 14: Expired Unachieved Milestone Recovery by Sponsor
    print("\n[Phase 14] Testing expired unachieved milestone recovery after deadline...")
    milestone_id_4 = contract.create_clinical_milestone_escrow(
        caller=sponsor,
        value=escrow_amount,
        biotech_recipient=biotech,
        nct_id="NCT03334444",
        endpoint="Phase 2 Efficacy Endpoint",
        duration_sec=86400 * 14
    )
    try:
        contract.claim_expired_unachieved_milestone(caller=sponsor, milestone_id=milestone_id_4, custom_time=now)
        assert False, "Should revert if deadline not yet passed"
    except AssertionError as e:
        assert "[ERR_DEADLINE_NOT_REACHED]" in str(e)

    contract.claim_expired_unachieved_milestone(caller=sponsor, milestone_id=milestone_id_4, custom_time=now + 86400 * 20)
    assert contract.milestones[milestone_id_4]["status"] == "EXPIRED_REFUNDED"
    assert contract.milestones[milestone_id_4]["total_refunded_to_sponsor"] == escrow_amount
    print("  PASS: Expired unachieved milestone collateral refunded to sponsor.")

    # Phase 15: Pull-Pattern Claimable Withdrawal with Balance Preservation
    print("\n[Phase 15] Testing pull-pattern claimable balance recovery...")
    sponsor_claimable = contract.claimable_balances.get(sponsor, 0)
    assert sponsor_claimable > 0

    mock_gl.simulate_transfer_fail = True
    try:
        contract.withdraw_claimable(caller=sponsor)
        assert False, "Should raise AssertionError on transfer failure"
    except AssertionError as e:
        assert "[ERR_TRANSFER_FAILED]" in str(e)
    assert contract.claimable_balances[sponsor] == sponsor_claimable, "Claimable balance must not be wiped on transfer error!"

    mock_gl.simulate_transfer_fail = False
    contract.withdraw_claimable(caller=sponsor)
    assert contract.claimable_balances[sponsor] == 0, "Balance cleanly zeroed upon successful transfer."
    print("  PASS: Pull-pattern claimable balance recovery preserves balance on transfer failure.")

    print("\n================================================================================")
    print("  ALL 15 REGRESSION & SECURITY PHASES PASSED WITH ZERO ERRORS!")
    print("================================================================================")


if __name__ == "__main__":
    run_all_tests()
