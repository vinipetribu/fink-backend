"""Create isolated SecureAI Lab event and anomaly run tables.

Revision ID: 20261117_lab_events
Revises: 20260914_argon2id
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = '20261117_lab_events'
down_revision = '20260914_argon2id'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'lab_events',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('occurred_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('origin', sa.String(16), nullable=False),
        sa.Column('event_type', sa.String(64), nullable=False),
        sa.Column('operation', sa.String(160), nullable=False),
        sa.Column('result', sa.String(32), nullable=False),
        sa.Column('duration_ms', sa.Float(), nullable=True),
        sa.Column('run_id', UUID(as_uuid=True), nullable=True),
        sa.CheckConstraint("origin IN ('observed', 'synthetic')", name='ck_lab_events_origin'),
        sa.CheckConstraint('duration_ms IS NULL OR duration_ms >= 0', name='ck_lab_events_duration'),
    )
    op.create_index('ix_lab_events_origin_occurred_at', 'lab_events', ['origin', 'occurred_at'])
    op.create_index('ix_lab_events_type_result_occurred_at', 'lab_events', ['event_type', 'result', 'occurred_at'])
    op.create_table(
        'lab_anomaly_runs',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('origin', sa.String(16), nullable=False),
        sa.Column('catalog', sa.String(64), nullable=False),
        sa.Column('model_versions', JSONB(), nullable=False),
        sa.Column('state', sa.String(16), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('finished_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('processed_volume', sa.Integer(), nullable=True),
        sa.Column('metrics_version', sa.Integer(), nullable=False),
        sa.Column('metrics', JSONB(), nullable=False),
        sa.CheckConstraint("origin IN ('observed', 'synthetic')", name='ck_lab_anomaly_runs_origin'),
        sa.CheckConstraint("state IN ('completed', 'failed', 'timed_out')", name='ck_lab_anomaly_runs_state'),
        sa.CheckConstraint('processed_volume IS NULL OR processed_volume >= 0', name='ck_lab_anomaly_runs_volume'),
        sa.CheckConstraint('finished_at >= started_at', name='ck_lab_anomaly_runs_time'),
    )
    op.create_index('ix_lab_anomaly_runs_origin_finished_at', 'lab_anomaly_runs', ['origin', 'finished_at'])


def downgrade() -> None:
    op.drop_table('lab_anomaly_runs')
    op.drop_table('lab_events')
