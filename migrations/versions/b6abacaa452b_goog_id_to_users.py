"""goog id to users

Revision ID: b6abacaa452b
Revises: e34ea0efcd81
Create Date: 2020-05-18 13:35:45.040615

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b6abacaa452b'
down_revision = 'e34ea0efcd81'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('user', sa.Column('googid', sa.String(), nullable=True))
    op.create_index(op.f('ix_user_googid'), 'user', ['googid'], unique=True)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_user_googid'), table_name='user')
    op.drop_column('user', 'googid')
    # ### end Alembic commands ###