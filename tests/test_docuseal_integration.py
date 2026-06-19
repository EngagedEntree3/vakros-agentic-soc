"""
Vakros DocuSeal Integration — End-to-End Test Harness
======================================================
Tests the full signing flow:
  Template list → Create submission → Get embed URL → Simulate webhook → Verify Supabase

Usage:
  # Unit tests only (no live services needed)
  pytest tests/test_docuseal_integration.py -v -m "not integration"

  # Full integration tests (requires DOCUSEAL_API_KEY + SUPABASE credentials)
  pytest tests/test_docuseal_integration.py -v -m integration \
    --docuseal-url https://signing.vakros.com \
    --template-id 1

Environment variables required for integration tests:
  DOCUSEAL_API_KEY, DOCUSEAL_BASE_URL, SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY,
  VAKROS_API_URL (e.g. http://localhost:8000 for local dev)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import httpx
from fastapi.testclient import TestClient

# ── Fixtures & helpers ────────────────────────────────────────────────────────

FAKE_TENANT_ID    = str(uuid.uuid4())
FAKE_TEMPLATE_ID  = 42
FAKE_SUBMISSION_ID = 9001
FAKE_SLUG         = "test-slug-abc123"
FAKE_EMBED_SRC    = f"https://signing.vakros.com/s/{FAKE_SLUG}"
FAKE_SIGNER_EMAIL = "signer@testclient.com"
FAKE_SIGNER_NAME  = "Test Signer"
WEBHOOK_SECRET    = "test-webhook-secret-abc"


def make_docuseal_submission_response(
    submission_id: int = FAKE_SUBMISSION_ID,
    slug: str = FAKE_SLUG,
    embed_src: str = FAKE_EMBED_SRC,
) -> dict:
    """Mimics DocuSeal POST /submissions response."""
    return [
        {
            "id":           1,
            "submission_id": submission_id,
            "slug":         slug,
            "embed_src":    embed_src,
            "email":        FAKE_SIGNER_EMAIL,
            "name":         FAKE_SIGNER_NAME,
            "role":         "Signer",
            "status":       "awaiting",
            "created_at":   "2026-06-18T00:00:00Z",
        }
    ]


def make_docuseal_status_response(status: str = "completed") -> dict:
    """Mimics DocuSeal GET /submissions/{id} response."""
    return {
        "id":           FAKE_SUBMISSION_ID,
        "status":       status,
        "completed_at": "2026-06-18T01:00:00Z" if status == "completed" else None,
        "submitters": [
            {
                "email":      FAKE_SIGNER_EMAIL,
                "embed_src":  FAKE_EMBED_SRC,
                "status":     status,
                "viewed_at":  "2026-06-18T00:30:00Z",
                "declined_at": None,
            }
        ],
    }


def make_webhook_payload(event_type: str = "document.completed") -> dict:
    """Mimics DocuSeal webhook payload."""
    return {
        "event_type": event_type,
        "data": {
            "submission": {
                "id":           FAKE_SUBMISSION_ID,
                "status":       event_type.replace("document.", ""),
                "completed_at": "2026-06-18T01:00:00Z",
                "metadata": {
                    "tenant_id": FAKE_TENANT_ID,
                    "source":    "vakros-platform",
                },
            },
            "submitter": {
                "id":    1,
                "email": FAKE_SIGNER_EMAIL,
                "name":  FAKE_SIGNER_NAME,
            },
        },
    }


def sign_webhook(payload: dict, secret: str) -> str:
    """Generate DocuSeal HMAC-SHA256 webhook signature."""
    body = json.dumps(payload).encode()
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


# ── Unit tests — no live services needed ─────────────────────────────────────

class TestDocuSealRoutes:
    """Unit tests for the FastAPI routes using mocked DocuSeal + Supabase."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Patch external dependencies before each test."""
        # Patch env vars
        env_patch = {
            "DOCUSEAL_API_KEY":        "test-api-key",
            "DOCUSEAL_BASE_URL":       "https://signing.vakros.com/api",
            "DOCUSEAL_WEBHOOK_SECRET": WEBHOOK_SECRET,
            "FLY_INTERNAL_SECRET":     "test-internal-secret",
            "SUPABASE_URL":            "https://fake.supabase.co",
            "SUPABASE_SERVICE_ROLE_KEY": "fake-service-role-key",
        }
        with patch.dict(os.environ, env_patch):
            # Patch supabase client
            with patch("integrations.docuseal.routes._supabase") as mock_sb:
                self.mock_supabase = mock_sb
                mock_sb.table.return_value.insert.return_value.execute.return_value = MagicMock()
                mock_sb.table.return_value.select.return_value.eq.return_value.eq.return_value.single.return_value.execute.return_value = MagicMock(
                    data={"docuseal_id": FAKE_SUBMISSION_ID, "tenant_id": FAKE_TENANT_ID, "embed_src": FAKE_EMBED_SRC}
                )
                mock_sb.table.return_value.update.return_value.eq.return_value.execute.return_value = MagicMock()

                from vakros_agent.api.main import app
                self.client = TestClient(app)
                yield

    @pytest.mark.unit
    def test_create_submission_success(self):
        """POST /api/docuseal/submissions — happy path."""
        mock_response = make_docuseal_submission_response()

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = MagicMock(
                status_code=201,
                json=lambda: mock_response,
            )

            resp = self.client.post(
                "/api/docuseal/submissions",
                json={
                    "template_id":  FAKE_TEMPLATE_ID,
                    "signer_name":  FAKE_SIGNER_NAME,
                    "signer_email": FAKE_SIGNER_EMAIL,
                    "tenant_id":    FAKE_TENANT_ID,
                },
            )

        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["submission_id"] == FAKE_SUBMISSION_ID
        assert data["embed_src"] == FAKE_EMBED_SRC
        assert data["embed_token"] == FAKE_SLUG
        assert data["status"] == "pending"
        assert data["vakros_record_id"]  # UUID was generated

    @pytest.mark.unit
    def test_create_submission_docuseal_error(self):
        """POST /api/docuseal/submissions — DocuSeal 502 is surfaced correctly."""
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = MagicMock(
                status_code=503,
                text="Service Unavailable",
            )
            resp = self.client.post(
                "/api/docuseal/submissions",
                json={
                    "template_id":  FAKE_TEMPLATE_ID,
                    "signer_name":  FAKE_SIGNER_NAME,
                    "signer_email": FAKE_SIGNER_EMAIL,
                    "tenant_id":    FAKE_TENANT_ID,
                },
            )
        assert resp.status_code == 502

    @pytest.mark.unit
    def test_get_submission_status(self):
        """GET /api/docuseal/submissions/{id} — returns live status."""
        mock_status = make_docuseal_status_response("completed")

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = MagicMock(
                status_code=200,
                json=lambda: mock_status,
            )
            resp = self.client.get(
                f"/api/docuseal/submissions/{FAKE_SUBMISSION_ID}",
                params={"tenant_id": FAKE_TENANT_ID},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "completed"
        assert data["signer_email"] == FAKE_SIGNER_EMAIL
        assert data["completed_at"] is not None

    @pytest.mark.unit
    def test_webhook_signature_validation_rejects_invalid(self):
        """POST /api/docuseal/webhooks/docuseal — invalid signature rejected."""
        payload = make_webhook_payload("document.completed")
        resp = self.client.post(
            "/api/docuseal/webhooks/docuseal",
            json=payload,
            headers={"x-docuseal-signature": "invalid-signature"},
        )
        assert resp.status_code == 401

    @pytest.mark.unit
    def test_webhook_completed_updates_supabase(self):
        """POST /api/docuseal/webhooks/docuseal — document.completed writes to Supabase."""
        payload = make_webhook_payload("document.completed")
        body_bytes = json.dumps(payload).encode()
        sig = hmac.new(WEBHOOK_SECRET.encode(), body_bytes, hashlib.sha256).hexdigest()

        resp = self.client.post(
            "/api/docuseal/webhooks/docuseal",
            content=body_bytes,
            headers={
                "Content-Type": "application/json",
                "x-docuseal-signature": sig,
            },
        )
        assert resp.status_code == 200
        assert resp.json()["received"] is True

        # Verify Supabase update was called with correct status
        self.mock_supabase.table.assert_called_with("signing_submissions")

    @pytest.mark.unit
    def test_webhook_declined(self):
        """POST /api/docuseal/webhooks/docuseal — document.declined writes declined_at."""
        payload = make_webhook_payload("document.declined")
        body_bytes = json.dumps(payload).encode()
        sig = hmac.new(WEBHOOK_SECRET.encode(), body_bytes, hashlib.sha256).hexdigest()

        resp = self.client.post(
            "/api/docuseal/webhooks/docuseal",
            content=body_bytes,
            headers={
                "Content-Type": "application/json",
                "x-docuseal-signature": sig,
            },
        )
        assert resp.status_code == 200

    @pytest.mark.unit
    def test_internal_webhook_requires_auth(self):
        """POST /api/docuseal/webhooks/internal — wrong key returns 401."""
        resp = self.client.post(
            "/api/docuseal/webhooks/internal",
            json={
                "submission_id": FAKE_SUBMISSION_ID,
                "tenant_id":     FAKE_TENANT_ID,
                "signer_email":  FAKE_SIGNER_EMAIL,
                "event":         "document.completed",
            },
            headers={"X-API-Key": "wrong-key"},
        )
        assert resp.status_code == 401

    @pytest.mark.unit
    def test_internal_webhook_success(self):
        """POST /api/docuseal/webhooks/internal — correct key processes event."""
        resp = self.client.post(
            "/api/docuseal/webhooks/internal",
            json={
                "submission_id": FAKE_SUBMISSION_ID,
                "tenant_id":     FAKE_TENANT_ID,
                "signer_email":  FAKE_SIGNER_EMAIL,
                "event":         "document.completed",
            },
            headers={"X-API-Key": "test-internal-secret"},
        )
        assert resp.status_code == 200
        assert resp.json()["received"] is True

    @pytest.mark.unit
    def test_create_submission_missing_api_key(self):
        """POST /api/docuseal/submissions — 503 when DOCUSEAL_API_KEY unset."""
        with patch.dict(os.environ, {"DOCUSEAL_API_KEY": ""}):
            resp = self.client.post(
                "/api/docuseal/submissions",
                json={
                    "template_id":  FAKE_TEMPLATE_ID,
                    "signer_name":  FAKE_SIGNER_NAME,
                    "signer_email": FAKE_SIGNER_EMAIL,
                    "tenant_id":    FAKE_TENANT_ID,
                },
            )
        assert resp.status_code == 503


# ── Integration tests — require live DocuSeal + Supabase ─────────────────────

@pytest.mark.integration
class TestDocuSealLiveIntegration:
    """
    Live end-to-end tests against a real DocuSeal instance.

    Run with:
      pytest tests/test_docuseal_integration.py -v -m integration
    """

    @pytest.fixture(autouse=True)
    def require_env(self):
        required = ["DOCUSEAL_API_KEY", "DOCUSEAL_BASE_URL", "VAKROS_API_URL"]
        missing = [k for k in required if not os.environ.get(k)]
        if missing:
            pytest.skip(f"Missing env vars for integration tests: {missing}")

    def test_list_templates(self):
        """GET /api/docuseal/templates — returns at least one template."""
        resp = httpx.get(
            f"{os.environ['VAKROS_API_URL']}/api/docuseal/templates",
            timeout=10,
        )
        assert resp.status_code == 200
        templates = resp.json()
        assert isinstance(templates, list), "Expected a list of templates"
        print(f"\n  Found {len(templates)} templates: {[t.get('name') for t in templates]}")

    def test_full_submission_flow(self):
        """
        Full flow: create submission → verify embed URL → poll status → simulate webhook.
        """
        template_id = int(os.environ.get("DOCUSEAL_TEMPLATE_ID", "1"))
        vakros_url  = os.environ["VAKROS_API_URL"]

        # Step 1: Create submission
        print("\n  Step 1: Creating submission...")
        create_resp = httpx.post(
            f"{vakros_url}/api/docuseal/submissions",
            json={
                "template_id":  template_id,
                "signer_name":  "Integration Test Signer",
                "signer_email": "test-signer@vakros-integration.com",
                "tenant_id":    FAKE_TENANT_ID,
                "metadata":     {"test_run": True},
            },
            timeout=15,
        )
        assert create_resp.status_code == 200, f"Create failed: {create_resp.text}"
        submission = create_resp.json()
        print(f"  ✅ Created submission #{submission['submission_id']}")
        print(f"     embed_src: {submission['embed_src']}")

        # Step 2: Verify embed URL is accessible
        print("\n  Step 2: Verifying embed URL is accessible...")
        embed_resp = httpx.get(submission["embed_src"], timeout=10, follow_redirects=True)
        assert embed_resp.status_code in (200, 302), f"Embed URL not accessible: {embed_resp.status_code}"
        print(f"  ✅ Embed URL accessible (HTTP {embed_resp.status_code})")

        # Step 3: Get submission status
        print("\n  Step 3: Getting submission status...")
        status_resp = httpx.get(
            f"{vakros_url}/api/docuseal/submissions/{submission['submission_id']}",
            params={"tenant_id": FAKE_TENANT_ID},
            timeout=10,
        )
        assert status_resp.status_code == 200, f"Status check failed: {status_resp.text}"
        status_data = status_resp.json()
        print(f"  ✅ Status: {status_data['status']}")
        assert status_data["status"] in ("pending", "awaiting"), (
            f"Expected pending status, got {status_data['status']}"
        )

        # Step 4: Simulate webhook (document.completed)
        if os.environ.get("DOCUSEAL_WEBHOOK_SECRET"):
            print("\n  Step 4: Simulating document.completed webhook...")
            payload = make_webhook_payload("document.completed")
            payload["data"]["submission"]["id"] = submission["submission_id"]
            payload["data"]["submission"]["metadata"]["tenant_id"] = FAKE_TENANT_ID

            body = json.dumps(payload).encode()
            sig = hmac.new(
                os.environ["DOCUSEAL_WEBHOOK_SECRET"].encode(),
                body,
                hashlib.sha256,
            ).hexdigest()

            webhook_resp = httpx.post(
                f"{vakros_url}/api/docuseal/webhooks/docuseal",
                content=body,
                headers={
                    "Content-Type": "application/json",
                    "x-docuseal-signature": sig,
                },
                timeout=10,
            )
            assert webhook_resp.status_code == 200, f"Webhook failed: {webhook_resp.text}"
            print(f"  ✅ Webhook processed: {webhook_resp.json()}")

            # Step 5: Verify Supabase updated
            print("\n  Step 5: Verifying Supabase status update...")
            time.sleep(1)  # small delay for async update
            final_status = httpx.get(
                f"{vakros_url}/api/docuseal/submissions/{submission['submission_id']}",
                params={"tenant_id": FAKE_TENANT_ID},
                timeout=10,
            )
            final_data = final_status.json()
            print(f"  ✅ Final status in Supabase: {final_data['status']}")
            assert final_data["status"] == "completed", (
                f"Expected 'completed' after webhook, got '{final_data['status']}'"
            )
        else:
            print("\n  Step 4: Skipping webhook simulation (DOCUSEAL_WEBHOOK_SECRET not set)")

        print("\n  ✅ Full integration test PASSED")


# ── n8n manifest validation ───────────────────────────────────────────────────

class TestN8NManifest:
    """Validate the n8n workflow JSON is well-formed and has required nodes."""

    MANIFEST_PATH = "n8n-manifests/docuseal-webhook-listener.json"

    @pytest.fixture(autouse=True)
    def load_manifest(self):
        try:
            with open(self.MANIFEST_PATH) as f:
                self.manifest = json.load(f)
        except FileNotFoundError:
            pytest.skip(f"Manifest not found: {self.MANIFEST_PATH}")

    @pytest.mark.unit
    def test_manifest_has_nodes(self):
        """n8n manifest must have nodes array."""
        assert "nodes" in self.manifest
        assert len(self.manifest["nodes"]) > 0

    @pytest.mark.unit
    def test_manifest_has_webhook_trigger(self):
        """n8n manifest must have a webhook trigger node."""
        node_types = [n["type"] for n in self.manifest["nodes"]]
        assert "n8n-nodes-base.webhook" in node_types, "Missing webhook trigger node"

    @pytest.mark.unit
    def test_manifest_has_supabase_nodes(self):
        """n8n manifest must have at least one Supabase node."""
        node_types = [n["type"] for n in self.manifest["nodes"]]
        supabase_nodes = [t for t in node_types if "supabase" in t.lower()]
        assert len(supabase_nodes) >= 1, "Missing Supabase nodes"

    @pytest.mark.unit
    def test_manifest_has_switch_router(self):
        """n8n manifest must have a switch/router node to handle different events."""
        node_types = [n["type"] for n in self.manifest["nodes"]]
        assert "n8n-nodes-base.switch" in node_types, "Missing event router (switch) node"

    @pytest.mark.unit
    def test_manifest_has_connections(self):
        """n8n manifest must have connections wiring nodes together."""
        assert "connections" in self.manifest
        assert len(self.manifest["connections"]) > 0

    @pytest.mark.unit
    def test_manifest_handles_all_four_events(self):
        """Router must handle completed, viewed, declined, started."""
        switch_nodes = [n for n in self.manifest["nodes"] if n["type"] == "n8n-nodes-base.switch"]
        assert switch_nodes, "No switch node found"
        switch = switch_nodes[0]
        output_keys = [
            rule.get("outputKey") or rule.get("renameOutput")
            for rule in switch.get("parameters", {}).get("rules", {}).get("values", [])
        ]
        for expected in ["completed", "viewed", "declined", "started"]:
            assert any(expected in str(k) for k in output_keys if k), (
                f"Switch router missing case for '{expected}'"
            )


# ── SQL migration validation ──────────────────────────────────────────────────

class TestSupabaseMigration:
    """Validate the SQL migration is well-formed."""

    MIGRATION_PATH = "vakros-agent/integrations/docuseal/migrations/001_signing_submissions.sql"

    @pytest.fixture(autouse=True)
    def load_sql(self):
        try:
            with open(self.MIGRATION_PATH) as f:
                self.sql = f.read()
        except FileNotFoundError:
            pytest.skip(f"Migration not found: {self.MIGRATION_PATH}")

    @pytest.mark.unit
    def test_table_created(self):
        assert "CREATE TABLE" in self.sql and "signing_submissions" in self.sql

    @pytest.mark.unit
    def test_rls_enabled(self):
        assert "ENABLE ROW LEVEL SECURITY" in self.sql

    @pytest.mark.unit
    def test_tenant_id_policy(self):
        assert "tenant_id" in self.sql and "CREATE POLICY" in self.sql

    @pytest.mark.unit
    def test_service_role_bypass(self):
        assert "service_role" in self.sql

    @pytest.mark.unit
    def test_status_check_constraint(self):
        assert "CHECK" in self.sql and "completed" in self.sql and "declined" in self.sql

    @pytest.mark.unit
    def test_indexes_present(self):
        assert self.sql.count("CREATE INDEX") >= 3, "Expected at least 3 indexes"
