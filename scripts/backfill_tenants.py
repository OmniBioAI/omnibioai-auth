"""Plan or run tenant provisioning for every Auth user; never deletes orphans."""
import argparse
import json
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.config import settings
from app.db.models import User
from app.db.session import SessionLocal


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--dry-run', action='store_true', help='print planned changes (the default)')
    mode.add_argument('--execute', action='store_true', help='perform changes')
    args = parser.parse_args()
    dry_run = not args.execute
    headers = {'X-Tenant-Provisioning-Token': settings.TENANT_PROVISIONING_SERVICE_TOKEN}
    with SessionLocal() as db:
        user_ids = [str(row[0]) for row in db.query(User.id).order_by(User.id).all()]
    for user_id in user_ids:
        try:
            response = httpx.post(
                settings.WORKBENCH_SERVICE_URL.rstrip('/') + f'/api/storage/internal/tenants/{user_id}/ensure',
                json={'dry_run': dry_run}, headers=headers,
                timeout=settings.TENANT_PROVISIONING_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            print(json.dumps(response.json(), sort_keys=True))
        except Exception as exc:
            print(json.dumps({'user_id': user_id, 'status': 'error', 'reason': str(exc)}, sort_keys=True))
    try:
        response = httpx.get(
            settings.BILLING_SERVICE_URL.rstrip('/') + '/internal/tenants/references',
            headers=headers, timeout=settings.TENANT_PROVISIONING_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        referenced = {str(value) for value in response.json().get('user_ids', [])}
        orphans = sorted(referenced - set(user_ids), key=lambda value: (not value.isdigit(), int(value) if value.isdigit() else value))
        print(json.dumps({'billing_orphan_user_ids': orphans, 'action': 'report_only'}, sort_keys=True))
    except Exception as exc:
        print(json.dumps({'billing_orphan_check': 'error', 'reason': str(exc)}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
