"""Add exam absence model

Revision ID: dfb213f1f44f
Revises: 
Create Date: 2025-01-01 09:16:48.783413

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'dfb213f1f44f'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('exam_absence',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('day', sa.Integer(), nullable=False),
    sa.Column('reason', sa.String(length=500), nullable=False),
    sa.Column('marked_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('exam_absence')
    # ### end Alembic commands ###