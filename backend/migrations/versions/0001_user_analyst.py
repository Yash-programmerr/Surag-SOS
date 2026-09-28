"""Initial user and analyst data model.

Revision ID: 0001_user_analyst
Revises:
"""
from alembic import op

from app.db import Base

revision = "0001_user_analyst"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    connection = op.get_bind()
    if connection.dialect.name == "postgresql":
        op.execute("CREATE EXTENSION IF NOT EXISTS postgis")
    Base.metadata.create_all(connection)
    if connection.dialect.name == "postgresql":
        op.execute("CREATE OR REPLACE FUNCTION reject_audit_changes() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit events are immutable'; END $$")
        op.execute("CREATE TRIGGER audit_immutable BEFORE UPDATE OR DELETE ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_audit_changes()")


def downgrade():
    connection = op.get_bind()
    if connection.dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS audit_immutable ON audit_events")
        op.execute("DROP FUNCTION IF EXISTS reject_audit_changes()")
    Base.metadata.drop_all(connection)
