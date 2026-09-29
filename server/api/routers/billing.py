"""Billing & subscription management."""
import uuid
import hmac
import hashlib
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Body, Query, Request, Header
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, func

from server.modules.persistence.database import get_db
from server.models.core import BillingPlan, BillingSubscription, APIEndpoint, User, TestRun
from server.modules.auth.rbac import RBAC, require_admin

router = APIRouter(tags=["Billing"])
logger = logging.getLogger(__name__)

DEFAULT_PLANS = [
    {"name": "Free",       "tier": "FREE",       "max_endpoints": 50,   "max_users": 2,  "max_scans_per_month": 5,   "features": ["api_inventory","basic_tests"],                                              "price_monthly_usd": 0.0},
    {"name": "Starter",    "tier": "STARTER",    "max_endpoints": 500,  "max_users": 10, "max_scans_per_month": 50,  "features": ["api_inventory","basic_tests","compliance_reports","slack","jira"],          "price_monthly_usd": 49.0},
    {"name": "Pro",        "tier": "PRO",        "max_endpoints": 5000, "max_users": 50, "max_scans_per_month": 500, "features": ["api_inventory","all_tests","compliance_reports","all_integrations","source_code_scan","cicd","nuclei","workflows"], "price_monthly_usd": 199.0},
    {"name": "Enterprise", "tier": "ENTERPRISE", "max_endpoints": -1,   "max_users": -1, "max_scans_per_month": -1,  "features": ["all"],                                                                      "price_monthly_usd": 0.0},
]


@router.post("/seed-plans")
async def seed_plans(payload: dict = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    """Idempotently create default billing plans."""
    created = 0
    for plan_data in DEFAULT_PLANS:
        existing = await db.execute(select(BillingPlan).where(BillingPlan.name == plan_data["name"]))
        if not existing.scalar_one_or_none():
            db.add(BillingPlan(id=str(uuid.uuid4()), **plan_data))
            created += 1
    await db.commit()
    return {"created": created, "message": "Plans seeded"}


@router.get("/plans")
async def list_plans(payload: dict = Depends(RBAC.require_auth), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(BillingPlan))
    plans = result.scalars().all()
    return {"plans": [
        {"id": p.id, "name": p.name, "tier": p.tier, "max_endpoints": p.max_endpoints,
         "max_users": p.max_users, "max_scans_per_month": p.max_scans_per_month,
         "features": p.features, "price_monthly_usd": p.price_monthly_usd}
        for p in plans
    ]}


@router.get("/subscription/{account_id}")
async def get_subscription(account_id: int, payload: dict = Depends(RBAC.require_auth), db: AsyncSession = Depends(get_db)):
    if payload.get("role", "").upper() != "ADMIN" and payload.get("account_id") != account_id:
        raise HTTPException(403, "Access denied to another account's subscription")
    result = await db.execute(select(BillingSubscription).where(BillingSubscription.account_id == account_id))
    sub = result.scalar_one_or_none()
    if not sub:
        raise HTTPException(404, "No subscription found")
    plan_result = await db.execute(select(BillingPlan).where(BillingPlan.id == sub.plan_id))
    plan = plan_result.scalar_one_or_none()
    return {"subscription_id": sub.id, "account_id": account_id, "status": sub.status,
            "plan": {"id": plan.id, "name": plan.name, "tier": plan.tier} if plan else None,
            "scans_used_this_month": sub.scans_used_this_month,
            "current_period_end": sub.current_period_end}


@router.post("/subscription/{account_id}/assign")
async def assign_plan(account_id: int, plan_id: str = Body(..., embed=True),
                      payload: dict = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    plan_result = await db.execute(select(BillingPlan).where(BillingPlan.id == plan_id))
    plan = plan_result.scalar_one_or_none()
    if not plan:
        raise HTTPException(404, "Plan not found")
    now = datetime.now(timezone.utc)
    existing = await db.execute(select(BillingSubscription).where(BillingSubscription.account_id == account_id))
    if existing.scalar_one_or_none():
        await db.execute(update(BillingSubscription).where(BillingSubscription.account_id == account_id)
                         .values(plan_id=plan_id, status="ACTIVE",
                                 current_period_start=now, current_period_end=now + timedelta(days=30)))
    else:
        db.add(BillingSubscription(id=str(uuid.uuid4()), account_id=account_id, plan_id=plan_id,
                                   status="ACTIVE", current_period_start=now,
                                   current_period_end=now + timedelta(days=30)))
    await db.commit()
    return {"account_id": account_id, "plan": plan.name, "status": "ACTIVE"}


@router.post("/subscription/{account_id}/cancel")
async def cancel_subscription(account_id: int, payload: dict = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    await db.execute(update(BillingSubscription).where(BillingSubscription.account_id == account_id)
                     .values(status="CANCELLED"))
    await db.commit()
    return {"account_id": account_id, "status": "CANCELLED"}


@router.get("/usage/{account_id}")
async def get_usage(account_id: int, payload: dict = Depends(RBAC.require_auth), db: AsyncSession = Depends(get_db)):
    if payload.get("role", "").upper() != "ADMIN" and payload.get("account_id") != account_id:
        raise HTTPException(403, "Access denied to another account's usage")
    ep_count    = (await db.execute(select(func.count()).select_from(APIEndpoint).where(APIEndpoint.account_id == account_id))).scalar()
    user_count  = (await db.execute(select(func.count()).select_from(User).where(User.account_id == account_id))).scalar()
    scan_count  = (await db.execute(select(func.count()).select_from(TestRun).where(TestRun.account_id == account_id))).scalar()
    return {"account_id": account_id, "endpoints": ep_count, "users": user_count, "test_runs": scan_count}


@router.post("/webhook/stripe")
async def stripe_webhook(
    request: Request,
    stripe_signature: str = Header(None, alias="stripe-signature"),
    db: AsyncSession = Depends(get_db),
):
    """
    Stripe webhook endpoint.  Verifies the stripe-signature header using
    STRIPE_WEBHOOK_SECRET and handles subscription lifecycle events.
    """
    from server.config import settings
    raw_body = await request.body()

    # ── Signature verification ────────────────────────────────────────────────
    webhook_secret = settings.STRIPE_WEBHOOK_SECRET
    if webhook_secret and stripe_signature:
        try:
            # Stripe signature format: t=<ts>,v1=<sig>
            parts = {k: v for k, v in (p.split("=", 1) for p in stripe_signature.split(","))}
            timestamp = parts.get("t", "")
            expected_sig = parts.get("v1", "")
            signed_payload = f"{timestamp}.{raw_body.decode()}"
            computed = hmac.new(
                webhook_secret.encode(), signed_payload.encode(), hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(computed, expected_sig):
                raise HTTPException(400, "Invalid Stripe signature")
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(400, f"Signature verification failed: {e}")

    # ── Parse event ───────────────────────────────────────────────────────────
    try:
        import json
        event = json.loads(raw_body)
    except Exception:
        raise HTTPException(400, "Invalid JSON payload")

    event_type = event.get("type", "")
    data_obj   = event.get("data", {}).get("object", {})
    stripe_sub_id = data_obj.get("subscription") or data_obj.get("id", "")

    # ── checkout.session.completed ────────────────────────────────────────────
    if event_type == "checkout.session.completed":
        client_ref = data_obj.get("client_reference_id")  # account_id passed at checkout
        if client_ref and stripe_sub_id:
            await db.execute(
                update(BillingSubscription)
                .where(BillingSubscription.account_id == int(client_ref))
                .values(status="ACTIVE", stripe_subscription_id=stripe_sub_id)
            )
            await db.commit()
            logger.info("Stripe checkout completed for account %s", client_ref)

    # ── invoice.payment_succeeded ─────────────────────────────────────────────
    elif event_type == "invoice.payment_succeeded":
        if stripe_sub_id:
            # Reset monthly scan counter on successful renewal
            await db.execute(
                update(BillingSubscription)
                .where(BillingSubscription.stripe_subscription_id == stripe_sub_id)
                .values(status="ACTIVE", scans_used_this_month=0,
                        current_period_start=datetime.now(timezone.utc),
                        current_period_end=datetime.now(timezone.utc) + timedelta(days=30))
            )
            await db.commit()
            logger.info("Payment succeeded for subscription %s", stripe_sub_id)

    # ── customer.subscription.deleted ────────────────────────────────────────
    elif event_type == "customer.subscription.deleted":
        if stripe_sub_id:
            await db.execute(
                update(BillingSubscription)
                .where(BillingSubscription.stripe_subscription_id == stripe_sub_id)
                .values(status="CANCELLED")
            )
            await db.commit()
            logger.info("Subscription cancelled: %s", stripe_sub_id)

    # ── customer.subscription.updated ────────────────────────────────────────
    elif event_type == "customer.subscription.updated":
        status_map = {"active": "ACTIVE", "past_due": "PAST_DUE",
                      "canceled": "CANCELLED", "unpaid": "PAST_DUE"}
        new_status = status_map.get(data_obj.get("status", ""), None)
        if stripe_sub_id and new_status:
            await db.execute(
                update(BillingSubscription)
                .where(BillingSubscription.stripe_subscription_id == stripe_sub_id)
                .values(status=new_status)
            )
            await db.commit()

    return {"received": True, "event_type": event_type}
