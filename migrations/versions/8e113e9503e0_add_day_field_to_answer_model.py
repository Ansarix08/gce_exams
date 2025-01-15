"""Add day field to Answer model

Revision ID: 8e113e9503e0
Revises: 7778848fdbd4
Create Date: 2025-01-14 00:35:29.339633

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '8e113e9503e0'
down_revision = '7778848fdbd4'
branch_labels = None
depends_on = None


def upgrade():
    # Create a temporary table with the new schema
    op.create_table('answer_new',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('question_id', sa.Integer(), nullable=False),
        sa.Column('selected_answer', sa.String(length=1), nullable=False),
        sa.Column('selection_date', sa.Date(), nullable=False),
        sa.Column('day', sa.Integer(), nullable=False, server_default='1'),
        sa.ForeignKeyConstraint(['question_id'], ['question.id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'question_id', 'day', name='unique_user_question_day')
    )
    
    # Copy data from the old table to the new table
    op.execute('INSERT INTO answer_new (id, user_id, question_id, selected_answer, selection_date, day) '
               'SELECT id, user_id, question_id, selected_answer, selection_date, 1 FROM answer')
    
    # Drop the old table
    op.drop_table('answer')
    
    # Rename the new table to the original name
    op.rename_table('answer_new', 'answer')


def downgrade():
    with op.batch_alter_table('answer', schema=None) as batch_op:
        batch_op.drop_constraint('unique_user_question_day', type_='unique')
        batch_op.drop_column('day')
