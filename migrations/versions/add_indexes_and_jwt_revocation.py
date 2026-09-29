"""
Add indexes for performance and JWT revocation table.

Revision ID: add_indexes_and_jwt_revocation
Revises: bc36458285db
Create Date: 2026-03-10 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_indexes_and_jwt_revocation'
down_revision = 'bc36458285db'
branch_labels = None
depends_on = None

def upgrade():
    # Add indexes for RequestLog table
    op.create_index(
        'idx_requestlog_ip_endpoint',
        'request_logs',
        ['source_ip', 'endpoint_id']
    )
    op.create_index(
        'idx_requestlog_created',
        'request_logs',
        ['created_at']
    )
    
    # Add index for APIEndpoint table
    op.create_index(
        'idx_apiendpoint_path',
        'api_endpoints',
        ['path_pattern']
    )
    
    # Create JWT revocation table
    op.create_table(
        'jwt_revoked_tokens',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('token_jti', sa.String(255), nullable=False),
        sa.Column('account_id', sa.BigInteger(), nullable=True),
        sa.Column('user_id', sa.String(36), nullable=True),
        sa.Column('revoked_at', sa.DateTime(timezone=True), server_default=sa.text('now()')),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('token_jti')
    )
    op.create_index('idx_jwt_revoked_tokens_jti', 'jwt_revoked_tokens', ['token_jti'])
    op.create_index('idx_jwt_revoked_tokens_account', 'jwt_revoked_tokens', ['account_id'])
    op.create_index('idx_jwt_revoked_tokens_user', 'jwt_revoked_tokens', ['user_id'])
    
    # Add encrypted fields to AuditLog
    op.add_column('audit_logs', sa.Column('details_encrypted', sa.Text(), nullable=True))
    op.add_column('audit_logs', sa.Column('ip_address_encrypted', sa.String(100), nullable=True))


def downgrade():
    # Remove indexes
    op.drop_index('idx_requestlog_ip_endpoint', table_name='request_logs')
    op.drop_index('idx_requestlog_created', table_name='request_logs')
    op.drop_index('idx_apiendpoint_path', table_name='api_endpoints')
    
    # Drop JWT revocation table
    op.drop_index('idx_jwt_revoked_tokens_jti', table_name='jwt_revoked_tokens')
    op.drop_index('idx_jwt_revoked_tokens_account', table_name='jwt_revoked_tokens')
    op.drop_index('idx_jwt_revoked_tokens_user', table_name='jwt_revoked_tokens')
    op.drop_table('jwt_revoked_tokens')
    
    # Remove encrypted columns from AuditLog
    op.drop_column('audit_logs', 'details_encrypted')
    op.drop_column('audit_logs', 'ip_address_encrypted')