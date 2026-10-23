"""
Demonstration Session Management & Event Pipeline Service for CyberOracle Intelligence
Provides isolated, session-scoped demonstration states, idempotent view resets,
and uniform event processing across simulation modules (Attack Studio & Custom Attack URLs).
"""

import uuid
import logging
from django.db import transaction
from django.utils import timezone
from .models import DemonstrationSession, RequestLog, IPRiskProfile

logger = logging.getLogger('monitor.demo_service')


def get_or_create_demo_session(user=None, session_id=None, auto_create=True) -> DemonstrationSession:
    """
    Retrieve or create the active DemonstrationSession.
    Isolates sessions per authenticated user.
    If anonymous or unauthenticated, scopes by session_id or global fallback.
    """
    qs = DemonstrationSession.objects.filter(is_active=True)
    if user and getattr(user, 'is_authenticated', False):
        qs = qs.filter(user=user)
    elif session_id:
        qs = qs.filter(session_id=session_id)
    else:
        qs = qs.filter(user__isnull=True)

    active_session = qs.order_by('-created_at').first()

    if not active_session and auto_create:
        new_id = f"demo_{uuid.uuid4().hex[:12]}"
        active_session = DemonstrationSession.objects.create(
            session_id=new_id,
            user=user if (user and getattr(user, 'is_authenticated', False)) else None,
            is_active=True,
            description="Active Adversary Emulation Demonstration"
        )
        logger.info(f"[CyberOracle Demo] Initialized active demonstration session: {new_id} for user: {user}")

    return active_session


def reset_demo_session(user=None, session_id=None) -> tuple:
    """
    Safely, idempotently, and securely reset the active demonstration session:
    1. Scopes the operation strictly to the authenticated user's current session.
    2. Marks active session as closed and inactive.
    3. Deactivates its events in the active demo view (demo_active=False).
    4. Generates a fresh new DemonstrationSession.
    5. Preserves all historical records, production alerts, and other users' sessions.
    Returns: (new_session: DemonstrationSession, archived_count: int)
    """
    with transaction.atomic():
        qs = DemonstrationSession.objects.filter(is_active=True)
        if user and getattr(user, 'is_authenticated', False):
            qs = qs.filter(user=user)
        elif session_id:
            qs = qs.filter(session_id=session_id)
        else:
            qs = qs.filter(user__isnull=True)

        active_sessions = list(qs)
        archived_count = 0
        now = timezone.now()

        for s in active_sessions:
            s.is_active = False
            s.closed_at = now
            s.save(update_fields=['is_active', 'closed_at'])

            # Archive events for active display without deleting historical rows
            cnt = RequestLog.objects.filter(demo_session=s, demo_active=True).update(demo_active=False)
            archived_count += cnt

        # Create new isolated demonstration session
        new_id = f"demo_{uuid.uuid4().hex[:12]}"
        new_session = DemonstrationSession.objects.create(
            session_id=new_id,
            user=user if (user and getattr(user, 'is_authenticated', False)) else None,
            is_active=True,
            description="Fresh Adversary Emulation Demonstration Session"
        )
        logger.info(
            f"[CyberOracle Demo] Reset session for user: {user}. Archived {archived_count} events. "
            f"New session: {new_id}"
        )

    return new_session, archived_count
