"""Scheduled entry point: python -m api.sync_mailboxes [--budget-seconds 240]."""
import argparse
import json
import os


def main():
    parser = argparse.ArgumentParser(description='Advance saved mailbox cursors fairly across the team.')
    parser.add_argument('--budget-seconds', type=int, default=240)
    args = parser.parse_args()
    if not 30 <= args.budget_seconds <= 900:
        parser.error('Use a budget between 30 and 900 seconds')
    # A scheduled process must not start its own repeating in-process scheduler.
    os.environ['PSA_DISABLE_SCHEDULER'] = 'true'
    from . import api as service
    from .mail_jobs import sync_mailboxes
    with service.app.app_context():
        result = sync_mailboxes(service, budget_seconds=args.budget_seconds)
    print(json.dumps(result))
    return 1 if result['errors'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
