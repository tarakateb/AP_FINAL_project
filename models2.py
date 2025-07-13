from datetime import datetime
from sqlalchemy import create_engine, String, DateTime, ForeignKey
from sqlalchemy.orm import sessionmaker, DeclarativeBase, Mapped, mapped_column, relationship

engine = create_engine('sqlite:///messenger2.db')
Session = sessionmaker(bind=engine)

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = 'User'
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(unique=True)
    password: Mapped[str] = mapped_column()
    phone_number: Mapped[str] = mapped_column()
    profile_picture: Mapped[str] = mapped_column(nullable=True)

    contacts: Mapped[list["Contact"]] = relationship("Contact", foreign_keys="[Contact.user_id]", back_populates="user", cascade="all, delete")
    groups: Mapped[list["GroupMember"]] = relationship("GroupMember", back_populates="user", cascade="all, delete")

class Message(Base):
    __tablename__ = 'messages'
    id: Mapped[int] = mapped_column(primary_key=True)
    sender_username: Mapped[str] = mapped_column()
    receiver_username: Mapped[str] = mapped_column(nullable=True)
    group_id: Mapped[int] = mapped_column(ForeignKey('groups.id'), nullable=True)
    message: Mapped[str] = mapped_column()
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Contact(Base):
    __tablename__ = 'contacts'
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('User.id', ondelete="CASCADE"), nullable=False)
    contact_user_id: Mapped[int] = mapped_column(ForeignKey('User.id', ondelete="CASCADE"), nullable=False)

    user: Mapped["User"] = relationship("User", foreign_keys=[user_id], back_populates="contacts")
    contact_user: Mapped["User"] = relationship("User", foreign_keys=[contact_user_id])

class Group(Base):
    __tablename__ = 'groups'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(unique=True)

    members: Mapped[list["GroupMember"]] = relationship("GroupMember", back_populates="group", cascade="all, delete")

class GroupMember(Base):
    __tablename__ = 'group_members'
    id: Mapped[int] = mapped_column(primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("groups.id"), nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey("User.id"), nullable=False)

    group: Mapped["Group"] = relationship("Group", back_populates="members")
    user: Mapped["User"] = relationship("User", back_populates="groups")

Base.metadata.create_all(engine)

