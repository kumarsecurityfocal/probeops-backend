"""Add compatibility columns

Revision ID: add_compatibility_columns
Revises: 691e893eef87
Create Date: 2025-05-10 10:20:35.123456

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'add_compatibility_columns'
down_revision = '691e893eef87'
branch_labels = None
depends_on = None


def upgrade():
    # Add compatibility columns if they don't exist
    
    # Check if password_hash column exists, if not add it
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    columns = [col['name'] for col in inspector.get_columns('users')]
    
    if 'password_hash' not in columns:
        with op.batch_alter_table('users', schema=None) as batch_op:
            batch_op.add_column(sa.Column('password_hash', sa.String(256), nullable=True))
            # Copy data from hashed_password to password_hash for compatibility
            conn.execute(sa.text('UPDATE users SET password_hash = hashed_password'))
    
    # No need to add is_admin column as we're using the role column instead
    # The is_admin property in the model returns true if role == 'admin'


def downgrade():
    # We don't remove the compatibility columns during downgrade
    # as they're needed for backward compatibility
    pass