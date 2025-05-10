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
    """Add compatibility columns and copy data"""
    
    # First, check if the password_hash column exists to avoid errors if already migrated
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    has_password_hash = False
    has_is_admin = False
    
    for column in inspector.get_columns('users'):
        if column['name'] == 'password_hash':
            has_password_hash = True
        if column['name'] == 'is_admin':
            has_is_admin = True
    
    # Add the password_hash column if it doesn't exist
    if not has_password_hash:
        op.add_column('users', sa.Column('password_hash', sa.String(256), nullable=True))
        # Copy data from hashed_password to password_hash
        op.execute(
            """
            UPDATE users 
            SET password_hash = hashed_password
            WHERE password_hash IS NULL AND hashed_password IS NOT NULL
            """
        )
    
    # Add the is_admin column if it doesn't exist
    if not has_is_admin:
        op.add_column('users', sa.Column('is_admin', sa.Boolean(), nullable=True))
        # Set is_admin based on role
        op.execute(
            """
            UPDATE users 
            SET is_admin = (role = 'admin')
            WHERE is_admin IS NULL
            """
        )


def downgrade():
    """Remove compatibility columns"""
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    
    # Check if columns exist before trying to remove them
    if 'password_hash' in [c['name'] for c in inspector.get_columns('users')]:
        op.drop_column('users', 'password_hash')
    
    if 'is_admin' in [c['name'] for c in inspector.get_columns('users')]:
        op.drop_column('users', 'is_admin')