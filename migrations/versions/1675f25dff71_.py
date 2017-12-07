"""empty message

Revision ID: 1675f25dff71
Revises: 
Create Date: 2017-12-05 15:39:10.069365

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '1675f25dff71'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('user', sa.Column('password_hash', sa.String(length=64), nullable=True))
    op.drop_constraint('user_username_key', 'user', type_='unique')
    op.create_unique_constraint(None, 'user', ['password_hash'])
    op.drop_column('user', 'username')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('user', sa.Column('username', sa.VARCHAR(length=64), autoincrement=False, nullable=True))
    op.drop_constraint(None, 'user', type_='unique')
    op.create_unique_constraint('user_username_key', 'user', ['username'])
    op.drop_column('user', 'password_hash')
    # ### end Alembic commands ###
