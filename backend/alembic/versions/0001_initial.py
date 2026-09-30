"""0001_initial

Revision ID: 0001_initial
Revises: 
Create Date: 2026-10-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0001_initial'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Users table
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('password_hash', sa.String(length=255), nullable=False),
        sa.Column('role', sa.String(length=32), nullable=False, server_default='user'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)

    # 2. Targets table
    op.create_table(
        'targets',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('owner_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('base_url', sa.String(length=1024), nullable=False),
        sa.Column('scope_hosts', sa.JSON(), nullable=False),
        sa.Column('ownership_status', sa.String(length=32), nullable=False, server_default='unverified'),
        sa.Column('ownership_token', sa.String(length=64), nullable=False),
        sa.Column('verified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['owner_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )

    # 3. Target Accounts table
    op.create_table(
        'target_accounts',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('target_id', sa.Integer(), nullable=False),
        sa.Column('role_label', sa.String(length=32), nullable=False),
        sa.Column('privilege_level', sa.Integer(), nullable=False),
        sa.Column('login_url', sa.String(length=1024), nullable=False),
        sa.Column('username', sa.String(length=255), nullable=False),
        sa.Column('password_encrypted', sa.String(length=1024), nullable=False),
        sa.Column('username_selector', sa.String(length=255), nullable=False),
        sa.Column('password_selector', sa.String(length=255), nullable=False),
        sa.Column('submit_selector', sa.String(length=255), nullable=False),
        sa.Column('dismiss_selectors', sa.JSON(), nullable=False),
        sa.Column('success_url_contains', sa.String(length=255), nullable=True),
        sa.Column('identifiers', sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(['target_id'], ['targets.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('target_id', 'role_label', name='uq_target_role_label')
    )

    # 4. Scans table
    op.create_table(
        'scans',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('owner_id', sa.Integer(), nullable=False),
        sa.Column('target_id', sa.Integer(), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='queued'),
        sa.Column('options', sa.JSON(), nullable=False),
        sa.Column('progress_percent', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('progress_stage', sa.String(length=64), nullable=False, server_default='queued'),
        sa.Column('error_message', sa.String(length=1024), nullable=True),
        sa.Column('cancel_requested', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('summary', sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(['owner_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['target_id'], ['targets.id'], ondelete='RESTRICT'),
        sa.PrimaryKeyConstraint('id')
    )

    # 5. Scan Events table
    op.create_table(
        'scan_events',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=False),
        sa.Column('level', sa.String(length=16), nullable=False, server_default='info'),
        sa.Column('stage', sa.String(length=64), nullable=False),
        sa.Column('message', sa.String(length=1024), nullable=False),
        sa.Column('percent', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_scan_events_scan_id_id', 'scan_events', ['scan_id', 'id'])

    # 6. Endpoints table
    op.create_table(
        'endpoints',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=False),
        sa.Column('account_label', sa.String(length=32), nullable=False),
        sa.Column('method', sa.String(length=16), nullable=False),
        sa.Column('url', sa.String(length=2048), nullable=False),
        sa.Column('signature', sa.String(length=512), nullable=False),
        sa.Column('resource_type', sa.String(length=32), nullable=False),
        sa.Column('status_code', sa.Integer(), nullable=False),
        sa.Column('content_type', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )

    # 7. Findings table
    op.create_table(
        'findings',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=False),
        sa.Column('fingerprint', sa.String(length=32), nullable=False),
        sa.Column('type', sa.String(length=64), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=False),
        sa.Column('confidence', sa.Integer(), nullable=False),
        sa.Column('cvss_score', sa.Float(), nullable=False),
        sa.Column('cvss_vector', sa.String(length=128), nullable=False),
        sa.Column('cwe', sa.String(length=32), nullable=False),
        sa.Column('owasp', sa.String(length=64), nullable=False),
        sa.Column('method', sa.String(length=16), nullable=False),
        sa.Column('url', sa.String(length=2048), nullable=False),
        sa.Column('signature', sa.String(length=512), nullable=False),
        sa.Column('source_role', sa.String(length=32), nullable=False),
        sa.Column('tested_role', sa.String(length=32), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('remediation', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='open'),
        sa.Column('note', sa.Text(), nullable=True),
        sa.Column('evidence', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_findings_scan_id', 'findings', ['scan_id'])
    op.create_index('ix_findings_fingerprint', 'findings', ['fingerprint'])

    # 8. Audit Logs table
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('action', sa.String(length=64), nullable=False),
        sa.Column('resource_type', sa.String(length=64), nullable=True),
        sa.Column('resource_id', sa.Integer(), nullable=True),
        sa.Column('ip', sa.String(length=64), nullable=True),
        sa.Column('details', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )


def downgrade() -> None:
    op.drop_table('audit_logs')
    op.drop_index('ix_findings_fingerprint', table_name='findings')
    op.drop_index('ix_findings_scan_id', table_name='findings')
    op.drop_table('findings')
    op.drop_table('endpoints')
    op.drop_index('ix_scan_events_scan_id_id', table_name='scan_events')
    op.drop_table('scan_events')
    op.drop_table('scans')
    op.drop_table('target_accounts')
    op.drop_table('targets')
    op.drop_index(op.f('ix_users_email'), table_name='users')
    op.drop_table('users')
