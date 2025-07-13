import socket
import threading
from sqlalchemy.orm import sessionmaker
from models2 import User, Contact, Group, GroupMember
from sqlalchemy import create_engine

engine = create_engine("sqlite:///messenger2.db")
Session = sessionmaker(bind=engine)

class Server:
    def __init__(self, host='127.0.0.1', port=12345):
        self.HOST = host
        self.PORT = port
        self.clients = {}
        self.lock = threading.Lock()
        self.start()

    def send_contact_list(self, client_socket, username):
        with Session() as session:
            user = session.query(User).filter_by(username=username).first()
            if not user:
                return
            contacts = (
                session.query(User.username)
                .join(Contact, Contact.contact_user_id == User.id)
                .filter(Contact.user_id == user.id)
                .all()
            )
            contact_names = [c[0] for c in contacts]
        message = "CONTACTLIST|" + "|".join(contact_names)
        try:
            client_socket.send(message.encode('utf-8'))
        except:
            pass

    def broadcast_username_change(self, old_username, new_username, sender_socket):
        with self.lock:
            for client, user in self.clients.items():
                if client != sender_socket:
                    try:
                        client.send(f"UPDATEUSERNAME|{old_username}|{new_username}".encode('utf-8'))
                    except:
                        client.close()
                        self.clients.pop(client, None)

    def send_group_history(self, client_socket, group_name):
        with Session() as session:
            group = session.query(Group).filter_by(name=group_name).first()
            if not group:
                return
            messages = (
                session.query(Message)
                .filter_by(group_id=group.id)
                .order_by(Message.timestamp)
                .all()
            )
            for msg in messages:
                try:
                    line = f"GROUPMSG|{msg.sender_username}|{group_name}|{msg.message}"
                    client_socket.send(line.encode('utf-8'))
                except:
                    pass

    def handle_client(self, client_socket):
        try:
            username = client_socket.recv(2048).decode('utf-8')
            with self.lock:
                self.clients[client_socket] = username

            self.send_contact_list(client_socket, username)
            self.broadcast_all_group_lists()
            while True:
                message = client_socket.recv(2048).decode('utf-8')
                if not message:
                    break

                if message.startswith("FROM|"):
                    str, sender, str2, recipient, content = message.split("|", 4)
                    with Session() as session:
                        sender_user = session.query(User).filter_by(username=sender).first()
                        recipient_user = session.query(User).filter_by(username=recipient).first()
                        if sender_user and recipient_user:
                            contact_exists = session.query(Contact).filter_by(
                                user_id=sender_user.id, contact_user_id=recipient_user.id
                            ).first()
                            if contact_exists:
                                for client, user in self.clients.items():
                                    if user == recipient:
                                        client.send(message.encode('utf-8'))
                                        break

                elif message.startswith("ADDCONTACT"):
                    string, contact_username, phone = message.split("|")
                    with Session() as session:
                        user = session.query(User).filter_by(username=username).first()
                        target_user = session.query(User).filter_by(username=contact_username, phone_number=phone).first()
                        if user and target_user:
                            existing_contact = session.query(Contact).filter_by(
                                user_id=user.id, contact_user_id=target_user.id
                            ).first()
                            if not existing_contact:
                                contact = Contact(user_id=user.id, contact_user_id=target_user.id)
                                session.add(contact)

                            reverse_contact = session.query(Contact).filter_by(
                                user_id=target_user.id, contact_user_id=user.id
                            ).first()
                            if not reverse_contact:
                                reverse = Contact(user_id=target_user.id, contact_user_id=user.id)
                                session.add(reverse)

                            session.commit()

                            client_socket.send(f"CONTACTADDED|{contact_username}".encode('utf-8'))
                            self.send_contact_list(client_socket, username)

                            with self.lock:
                                for client, user_name in self.clients.items():
                                    if user_name == contact_username:
                                        try:
                                            client.send(f"CONTACTADDED|{username}".encode('utf-8'))
                                            self.send_contact_list(client, contact_username)
                                        except:
                                            pass
                                        break
                        else:
                            client_socket.send(f"CONTACTFAILED|User not found.".encode('utf-8'))

                elif message.startswith("GROUPMSG|"):
                    parts = message.split("|")
                    sender = parts[1]
                    group_name = parts[2]
                    content = "|".join(parts[3:])

                    with Session() as session:
                        group = session.query(Group).filter_by(name=group_name).first()
                        if group:
                            member_ids = session.query(GroupMember.user_id).filter_by(group_id=group.id).all()
                            members = session.query(User.username).filter(User.id.in_([m[0] for m in member_ids])).all()
                            member_usernames = [m[0] for m in members]

                            for client, user in self.clients.items():
                                if user in member_usernames and user != sender:
                                    try:
                                        client.send(message.encode('utf-8'))
                                    except:
                                        client.close()
                                        self.clients.pop(client, None)

                elif message.startswith("NEWGROUP|"):
                    self.broadcast_all_group_lists()

                elif message.startswith("PROFILECHANGE|"):
                    _, changed_username = message.split("|", 1)

                    with self.lock:
                        for client, user in list(self.clients.items()):
                            try:
                                client.send(f"PROFILECHANGED|{changed_username}".encode('utf-8'))
                            except:
                                client.close()
                                self.clients.pop(client, None)

                elif message.startswith("USERNAMECHANGE|"):
                    parts = message.split("|")
                    old_username = parts[1]
                    new_username = parts[2]
                    with self.lock:
                        self.clients[client_socket] = new_username
                    username = new_username
                    print(f"User '{old_username}' changed username to '{new_username}'")
                    self.broadcast_username_change(old_username, new_username, client_socket)
                    with self.lock:
                        for client in list(self.clients.keys()):
                            if self.clients[client] == old_username:
                                self.clients[client] = new_username
                    self.send_contact_list(client_socket, username)
                    self.broadcast_all_group_lists()

                elif message.startswith("ADDMEMBER|"):
                    _, group_name, new_member_username = message.split("|", 2)
                    with Session() as session:
                        group = session.query(Group).filter_by(name=group_name).first()
                        new_member = session.query(User).filter_by(username=new_member_username).first()

                        if group and new_member:
                            existing = session.query(GroupMember).filter_by(group_id=group.id,
                                                                            user_id=new_member.id).first()
                            if not existing:
                                new_member_entry = GroupMember(group_id=group.id, user_id=new_member.id)
                                session.add(new_member_entry)
                                session.commit()

                                with self.lock:
                                    for client, uname in self.clients.items():
                                        if uname == new_member_username:
                                            try:
                                                self.send_group_list(client, new_member_username)
                                                self.send_group_history(client, group_name)
                                            except:
                                                pass

        except Exception as e:
            print(f"Error: {e}")
        finally:
            with self.lock:
                self.clients.pop(client_socket, None)
            client_socket.close()
            self.broadcast_all_group_lists()

    def broadcast_all_group_lists(self):
        with self.lock:
            for client, username in self.clients.items():
                self.send_group_list(client, username)

    def send_group_list(self, client_socket, username):
        with Session() as session:
            user = session.query(User).filter_by(username=username).first()
            if not user:
                return
            groups = (
                session.query(Group.name)
                .join(GroupMember, Group.id == GroupMember.group_id)
                .filter(GroupMember.user_id == user.id)
                .all()
            )
            group_names = [g[0] for g in groups]
        message = "GROUPLIST|" + "|".join(group_names)
        try:
            client_socket.send(message.encode('utf-8'))
        except:
            pass

    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.HOST, self.PORT))
        server.listen()
        print(f"Server running on {self.HOST}:{self.PORT}")
        while True:
            client_socket, str = server.accept()
            threading.Thread(target=self.handle_client, args=(client_socket,), daemon=True).start()


if __name__ == "__main__":
    server = Server()


