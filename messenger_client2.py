import sys , bcrypt
import socket ,base64
import threading, os, shutil
from PyQt6 import QtWidgets, QtCore, QtGui
from PyQt6.QtCore import pyqtSignal
from PyQt6.QtGui import QPixmap
from PyQt6.QtWidgets import QLineEdit
from models2 import Session, User, Message, Group, GroupMember
from datetime import datetime
IMAGE_DIR = os.path.join(os.getcwd(), "received_images")
os.makedirs(IMAGE_DIR, exist_ok=True)

class MessengerApp(QtWidgets.QWidget):
    new_message_signal = pyqtSignal(str)
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Messenger")
        self.setGeometry(100, 100, 500, 600)
        self.username = ""
        self.client_socket = None
        self.current_chat = None

        self.init_ui()
        self.message_handler = MessageHandler(self)
        self.group_handler = GroupHandler(self)
        self.settings_manager = SettingsManager(self)
        self.chat_data_loader = ChatDataLoader(self)

        self.new_message_signal.connect(lambda msg: self.message_handler.receive_message(msg))

    def init_ui(self):
        self.main_stack = QtWidgets.QStackedLayout(self)

        # ----- Login Frame -----
        self.login_frame = QtWidgets.QFrame()
        login_layout = QtWidgets.QVBoxLayout(self.login_frame)
        login_layout.addStretch()

        self.username_input = QtWidgets.QLineEdit()
        self.username_input.setPlaceholderText("Username: ")

        self.password_input = QtWidgets.QLineEdit()
        self.password_input.setPlaceholderText("Password: ")
        self.password_input.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)

        self.login_button = QtWidgets.QPushButton("Login")
        self.login_button.setStyleSheet("QPushButton { background-color: mediumspringgreen; }")

        self.register_button = QtWidgets.QPushButton("Register")
        self.register_button.setStyleSheet("QPushButton { background-color: olive; }")

        login_layout.addWidget(self.username_input)
        login_layout.addWidget(self.password_input)
        login_layout.addWidget(self.login_button)
        login_layout.addWidget(self.register_button)

        self.login_button.clicked.connect(self.login)
        self.register_button.clicked.connect(self.register_page)

        self.login_frame.setStyleSheet("""
            QFrame {
                background-image: url('intro.jpg');
                background-repeat: no-repeat;
                background-position: center;
                border: none;
            }
        """)
        self.main_stack.addWidget(self.login_frame)

        # ----- Main App Layout -----
        self.main_widget = QtWidgets.QWidget()
        self.main_layout = QtWidgets.QHBoxLayout(self.main_widget)

        # ----- User List Frame (Left Pane) -----
        self.user_list_frame = QtWidgets.QFrame()
        user_list_layout = QtWidgets.QVBoxLayout(self.user_list_frame)

        # Top Bar (Settings + Profile)
        self.settings_button = QtWidgets.QPushButton()
        self.settings_button.setIcon(QtGui.QIcon("setting.png"))
        self.settings_button.setIconSize(QtCore.QSize(48, 48))
        self.settings_button.setToolTip("Settings")
        self.settings_button.setFlat(True)
        self.settings_button.clicked.connect(lambda: self.settings_manager.open_settings())

        self.profile_pic_label = QtWidgets.QLabel()
        self.profile_pic_label.setFixedSize(50, 50)
        self.profile_pic_label.setStyleSheet("""
            QLabel {
                border-radius: 25px;
                border: 2px solid #555;
                background-color: #ccc;
                qproperty-alignment: AlignCenter;
            }
        """)

        top_bar_layout = QtWidgets.QHBoxLayout()
        top_bar_layout.addWidget(self.settings_button)
        top_bar_layout.addWidget(self.profile_pic_label)
        top_bar_layout.addStretch()
        user_list_layout.addLayout(top_bar_layout)

        # Add Contact & Group Buttons
        self.add_contact_button = QtWidgets.QPushButton()
        self.add_contact_button.setIcon(QtGui.QIcon("Contact.png"))
        self.add_contact_button.setIconSize(QtCore.QSize(50, 50))
        self.add_contact_button.setToolTip("Add Contact")
        self.add_contact_button.setFlat(True)
        self.add_contact_button.clicked.connect(self.add_contact_page)

        self.create_group_button = QtWidgets.QPushButton()
        self.create_group_button.setIcon(QtGui.QIcon("create_group.png"))
        self.create_group_button.setIconSize(QtCore.QSize(50, 50))
        self.create_group_button.setToolTip("Create Group")
        self.create_group_button.setFlat(True)
        self.create_group_button.clicked.connect(lambda: self.group_handler.create_group())

        top_bar2_layout = QtWidgets.QHBoxLayout()
        top_bar2_layout.addStretch()
        top_bar2_layout.addWidget(self.create_group_button)
        top_bar2_layout.addWidget(self.add_contact_button)
        user_list_layout.addLayout(top_bar2_layout)

        user_list_layout.addWidget(QtWidgets.QLabel("Chats"))

        self.user_list = QtWidgets.QListWidget()
        self.user_list.setIconSize(QtCore.QSize(48, 48))
        self.user_list.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
        self.user_list.itemClicked.connect(self._on_user_list_item_clicked)
        self.user_list.customContextMenuRequested.connect(self._on_context_menu_requested)
        self.user_list.setStyleSheet("""
            QListWidget {
                background-image: url('back2.jpg');
                background-repeat: no-repeat;
                background-position: center;
            }
            QListWidget::item {
                padding: 8px;
            }
        """)
        user_list_layout.addWidget(self.user_list)

        # ----- Chat Frame (Right Pane) -----
        self.chat_frame = QtWidgets.QFrame()
        self.chat_layout = QtWidgets.QVBoxLayout(self.chat_frame)

        self.chat_frame.setStyleSheet("""
            QFrame {
                background-image: url('back3.jpg');
                background-repeat: no-repeat;
                background-position: center;
                border: none;
            }
        """)

        self.chat_scroll_area = QtWidgets.QScrollArea()
        self.chat_scroll_area.setWidgetResizable(True)

        self.chat_display_widget = QtWidgets.QWidget()
        self.chat_display_layout = QtWidgets.QVBoxLayout(self.chat_display_widget)
        self.chat_display_layout.setAlignment(QtCore.Qt.AlignmentFlag.AlignTop)

        self.chat_scroll_area.setWidget(self.chat_display_widget)
        self.chat_layout.addWidget(self.chat_scroll_area)

        # Message input and button row
        self.message_input = QtWidgets.QLineEdit()
        self.message_input.setPlaceholderText("Type your message here...")
        self.chat_layout.addWidget(self.message_input)

        button_layout = QtWidgets.QHBoxLayout()
        self.send_button = QtWidgets.QPushButton("Send")
        self.send_button.setStyleSheet("QPushButton { background-color: mediumaquamarine; }")
        self.send_button.setEnabled(False)
        self.send_button.clicked.connect(lambda: self.message_handler.send_message())

        self.image_button = QtWidgets.QPushButton("Send Image")
        self.image_button.setStyleSheet("QPushButton { background-color: lightblue; }")
        self.image_button.clicked.connect(self.choose_image)

        button_layout.addWidget(self.send_button)
        button_layout.addWidget(self.image_button)
        self.chat_layout.addLayout(button_layout)

        # Add Member (only for group chat)
        self.add_member_button = QtWidgets.QPushButton("Add Member")
        self.add_member_button.setStyleSheet("QPushButton { background-color: violet; }")
        self.add_member_button.clicked.connect(lambda: self.group_handler.add_member_to_group())
        self.chat_layout.addWidget(self.add_member_button)

        # Add frames to main layout with 1:2 ratio
        self.main_layout.addWidget(self.user_list_frame, 1)
        self.main_layout.addWidget(self.chat_frame, 2)

        self.main_stack.addWidget(self.main_widget)

        # ----- Register Page -----
        self.register_frame = QtWidgets.QFrame()
        self.register_layout = QtWidgets.QVBoxLayout(self.register_frame)

        self.username_register_input = QtWidgets.QLineEdit()
        self.username_register_input.setPlaceholderText("Username")

        self.password_register_input = QtWidgets.QLineEdit()
        self.password_register_input.setPlaceholderText("Password")
        self.password_register_input.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)

        self.repeat_password = QtWidgets.QLineEdit()
        self.repeat_password.setPlaceholderText("Repeat Password")
        self.repeat_password.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)

        self.phone_number_register_input = QtWidgets.QLineEdit()
        self.phone_number_register_input.setPlaceholderText("Phone Number")

        self.register2_button = QtWidgets.QPushButton("Register!")
        self.register2_button.clicked.connect(self.register)

        self.back_button = QtWidgets.QPushButton("Back")
        self.back_button.clicked.connect(self.back)

        self.register_layout.addWidget(self.username_register_input)
        self.register_layout.addWidget(self.password_register_input)
        self.register_layout.addWidget(self.repeat_password)
        self.register_layout.addWidget(self.phone_number_register_input)
        self.register_layout.addWidget(self.register2_button)
        self.register_layout.addWidget(self.back_button)

        self.register_frame.setStyleSheet("""
            QFrame {
                background-image: url('intro.jpg');
                background-repeat: no-repeat;
                background-position: center;
            }
        """)
        self.main_stack.addWidget(self.register_frame)

        # ----- Add Contact Page -----
        self.add_contact_frame = QtWidgets.QWidget()
        self.add_contact_layout = QtWidgets.QVBoxLayout(self.add_contact_frame)

        self.usn_input = QtWidgets.QLineEdit()
        self.usn_input.setPlaceholderText("Username")

        self.phone_number_add_contact = QtWidgets.QLineEdit()
        self.phone_number_add_contact.setPlaceholderText("Phone Number")

        self.add_contact2_button = QtWidgets.QPushButton("Add Contact")
        self.add_contact2_button.setStyleSheet("QPushButton { background-color: mediumaquamarine; }")
        self.add_contact2_button.clicked.connect(self.add_contact)

        self.back_button_add_contact = QtWidgets.QPushButton("Back")
        self.back_button_add_contact.setStyleSheet("QPushButton { background-color: violet; }")
        self.back_button_add_contact.clicked.connect(self.back)

        self.add_contact_layout.addWidget(self.usn_input)
        self.add_contact_layout.addWidget(self.phone_number_add_contact)
        self.add_contact_layout.addWidget(self.add_contact2_button)
        self.add_contact_layout.addWidget(self.back_button_add_contact)

        self.add_contact_frame.setStyleSheet("background-image: url(back5.jpg);")
        self.main_stack.addWidget(self.add_contact_frame)

        # Final setup
        self.main_widget.setFixedSize(800, 600)
        self.main_stack.setCurrentWidget(self.login_frame)

    def back(self):
        self.main_stack.setCurrentWidget(self.login_frame)

    def register_page(self):
        self.main_stack.setCurrentWidget(self.register_frame)

    def register(self):
        username = self.username_register_input.text()
        password = self.password_register_input.text()
        confirm_pass = self.repeat_password.text()
        phone_number = self.phone_number_register_input.text()

        if not password == confirm_pass:
            QtWidgets.QMessageBox.information(self, "Password Not Matched",
                                              "Registration was not successful. Please try again!")
            self.main_stack.setCurrentWidget(self.login_frame)
            return

        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        session = Session()
        try:
            user = User(username=username, password=hashed_pw, phone_number=phone_number)
            session.add(user)
            session.commit()
            QtWidgets.QMessageBox.information(self, "Success", "Registration successful!")
            self.connect_to_server()
            self.client_socket.send(f"NEWUSER|{username}".encode('utf-8'))
            self.client_socket.close()
            self.main_stack.setCurrentWidget(self.login_frame)
        except:
            QtWidgets.QMessageBox.warning(self, "Error", "Username already exists!")
        finally:
            session.close()

    def login(self):
        username = self.username_input.text()
        password = self.password_input.text()

        session = Session()
        user = session.query(User).filter_by(username=username).one_or_none()

        if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            self.username = username
            self.main_stack.setCurrentWidget(self.main_widget)
            self.chat_data_loader.load_user_list()
            self.chat_data_loader.load_profile_picture()
            self.connect_to_server()
        else:
            QtWidgets.QMessageBox.warning(self, "Error", "Invalid username or password.")
        session.close()

    def add_contact_page(self):
        self.main_stack.setCurrentWidget(self.add_contact_frame)

    def add_contact(self):
        username = self.usn_input.text().strip()
        phone = self.phone_number_add_contact.text().strip()
        if username and phone:
            try:
                self.client_socket.send(f"ADDCONTACT|{username}|{phone}".encode('utf-8'))
            except Exception as e:
                QtWidgets.QMessageBox.warning(self, "Error", f"Failed to send request: {e}")
        else:
            QtWidgets.QMessageBox.warning(self, "Error", "Username and phone number cannot be empty.")

        self.main_stack.setCurrentWidget(self.main_widget)

    def _on_user_list_item_clicked(self, item):
        widget = self.user_list.itemWidget(item)
        if widget:
            chat_target = widget.text_label.text().replace(" (New)", "")
            self.chat_data_loader.change_chat_user_by_name(chat_target)

    def _on_context_menu_requested(self, position):
        item = self.user_list.itemAt(position)
        if not item:
            return

        widget = self.user_list.itemWidget(item)
        if not widget:
            return
        name = widget.text_label.text()
        menu = QtWidgets.QMenu()

        if name.startswith("[Group]"):
            leave_action = menu.addAction("Leave Group")
            selected_action = menu.exec(self.user_list.mapToGlobal(position))
            if selected_action == leave_action:
                group_name = name.replace("[Group] ", "")
                self.group_handler.leave_group(group_name)
        else:
            view_profile_action = menu.addAction("View Profile")
            selected_action = menu.exec(self.user_list.mapToGlobal(position))
            if selected_action == view_profile_action:
                self.settings_manager.view_profile(name)

    def choose_image(self):
        file_path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Select Image to Send", "", "Image Files (*.png *.jpg *.jpeg)"
        )
        if not file_path:
            return

        try:
            with open(file_path, "rb") as f:
                image_data = f.read()
            encoded = base64.b64encode(image_data).decode("utf-8")
            filename = os.path.basename(file_path)
            recipient = self.current_chat
            if not recipient:
                QtWidgets.QMessageBox.warning(self, "Error", "No chat selected.")
                return

            msg = f"IMAGE|{self.username}|{recipient}|{filename}|{encoded}"
            self.client_socket.sendall(msg.encode("utf-8"))

            pixmap = QtGui.QPixmap()
            pixmap.loadFromData(image_data)
            label = QtWidgets.QLabel()
            label.setPixmap(pixmap.scaledToWidth(32))
            self.chat_display_layout.addWidget(label)
            self.message_handler.save_message("", recipient=recipient, is_image=True, file_path=file_path)

        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Error", f"Failed to send image:\n{e}")

    def scroll_to_bottom(self):
        scrollbar = self.chat_scroll_area.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def connect_to_server(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect(('127.0.0.1', 12345))
        self.client_socket.sendall(self.username.encode('utf-8'))
        threading.Thread(
            target=self.receive_messages,
            daemon=True
        ).start()

    def receive_messages(self):
        while True:
            try:
                message = self.client_socket.recv(4096).decode('utf-8')
                if not message:
                    break
                self.new_message_signal.emit(message)
            except:
                break

class UserListItemWidget(QtWidgets.QWidget):
    def __init__(self, username, profile_path=None, is_group=False):
        super().__init__()
        layout = QtWidgets.QHBoxLayout(self)
        layout.setContentsMargins(8, 4, 8, 4)
        layout.setSpacing(10)

        # Profile Image
        self.image_label = QtWidgets.QLabel()
        pixmap = QtGui.QPixmap(profile_path or "default_profile.png")
        pixmap = pixmap.scaled(48, 48, QtCore.Qt.AspectRatioMode.KeepAspectRatio, QtCore.Qt.TransformationMode.SmoothTransformation)
        self.image_label.setPixmap(pixmap)
        self.image_label.setFixedSize(48, 48)
        self.image_label.setStyleSheet("border-radius: 24px;")  # Round image

        # Username
        self.text_label = QtWidgets.QLabel(username)
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(True)
        self.text_label.setFont(font)

        layout.addWidget(self.image_label)
        layout.addWidget(self.text_label)
        layout.addStretch()

class ChatDataLoader:
    def __init__(self, app_instance):
        self.app = app_instance
        self.session_factory = Session

    def load_profile_picture(self):
        session = self.session_factory()
        user = session.query(User).filter_by(username=self.app.username).first()
        session.close()

        if user and user.profile_picture and os.path.exists(user.profile_picture):
            pixmap = QtGui.QPixmap(user.profile_picture).scaled(
                50, 50,
                QtCore.Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                QtCore.Qt.TransformationMode.SmoothTransformation
            )
            self.app.profile_pic_label.setPixmap(pixmap)
            self.app.profile_pic_label.setText("")
        else:
            self.app.profile_pic_label.setPixmap(QtGui.QPixmap())
            self.app.profile_pic_label.setText("No\nProfile")

    def load_user_list(self):
        session = self.session_factory()
        try:
            users = session.query(User).filter(User.username != self.app.username).all()
            groups = (
                session.query(Group)
                .join(GroupMember)
                .join(User)
                .filter(User.username == self.app.username)
                .all()
            )
            self.app.user_list.clear()

            for user in users:
                item = QtWidgets.QListWidgetItem()
                item.setSizeHint(QtCore.QSize(220, 60))
                profile = user.profile_picture if user.profile_picture and os.path.exists(
                    user.profile_picture) else None
                widget = UserListItemWidget(user.username, profile)
                self.app.user_list.addItem(item)
                self.app.user_list.setItemWidget(item, widget)

            for group in groups:
                item = QtWidgets.QListWidgetItem()
                item.setSizeHint(QtCore.QSize(220, 60))
                widget = UserListItemWidget(f"[Group] {group.name}", "group_icon.png", is_group=True)
                self.app.user_list.addItem(item)
                self.app.user_list.setItemWidget(item, widget)

            if self.app.user_list.count() > 0:
                self.app.user_list.setCurrentRow(0)
                self.app.send_button.setEnabled(True)
            else:
                self.app.send_button.setEnabled(False)

        finally:
            session.close()

    def change_chat_user_by_name(self, username):
        self.app.current_chat = username.replace(" (New)", "")

        for i in range(self.app.user_list.count()):
            item = self.app.user_list.item(i)
            widget = self.app.user_list.itemWidget(item)
            if widget:
                current_name = widget.text_label.text()
                if current_name == username or current_name == username + " (New)":
                    widget.text_label.setText(self.app.current_chat)
                    break

        while self.app.chat_display_layout.count():
            child = self.app.chat_display_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        self.load_chat_history()
        self.app.send_button.setEnabled(True)

    def load_chat_history(self):
        if not self.app.current_chat:
            return
        selected_chat = self.app.current_chat
        session = self.session_factory()
        try:
            while self.app.chat_display_layout.count():
                child = self.app.chat_display_layout.takeAt(0)
                if child.widget():
                    child.widget().deleteLater()
            if selected_chat.startswith("[Group]"):
                group_name = selected_chat.replace("[Group] ", "")
                self._load_group_chat_history(session, group_name)
            else:
                self._load_private_chat_history(session, selected_chat)
        finally:
            session.close()

    def _load_group_chat_history(self, session, group_name):
        group = session.query(Group).filter_by(name=group_name).first()
        if not group:
            return

        messages = (
            session.query(Message)
            .filter_by(group_id=group.id)
            .order_by(Message.timestamp)
            .all()
        )

        for m in messages:
            timestamp = m.timestamp.strftime('%H:%M') if m.timestamp else ''
            sender = "You" if m.sender_username == self.app.username else m.sender_username

            if m.is_image and m.file_path and os.path.exists(m.file_path):
                self.app.message_handler.display_image_message(sender, m.file_path)
            else:
                content = f"{timestamp} {sender}: {m.message}"
                self.app.message_handler.display_message(sender, content)

    def _load_private_chat_history(self, session, selected_user):
        messages = (
            session.query(Message)
            .filter(
                ((Message.sender_username == self.app.username) & (Message.receiver_username == selected_user)) |
                ((Message.sender_username == selected_user) & (Message.receiver_username == self.app.username))
            )
            .order_by(Message.timestamp)
            .all()
        )

        for m in messages:
            timestamp = m.timestamp.strftime('%H:%M') if m.timestamp else ''
            sender = "You" if m.sender_username == self.app.username else m.sender_username

            if m.is_image and m.file_path and os.path.exists(m.file_path):
                self.app.message_handler.display_image_message(sender, m.file_path)
            else:
                content = f"{timestamp} {sender}: {m.message}"
                self.app.message_handler.display_message(sender, content)


class MessageHandler:
    def __init__(self, msg_app):
            self.app = msg_app
            self.session_factory = Session

    def send_message(self):
        text = self.app.message_input.text().strip()
        selected_chat = self.app.current_chat

        if not selected_chat or not text:
            return

        if selected_chat.startswith("[Group]"):
            group_name = selected_chat.replace("[Group] ", "")
            message = f"GROUPMSG|{self.app.username}|{group_name}|{text}"
            self.app.client_socket.send(message.encode('utf-8'))
            self.save_message(text, recipient=None, group_name=group_name)
        else:
            message = f"FROM|{self.app.username}|TO|{selected_chat}|{text}"
            self.app.client_socket.send(message.encode('utf-8'))
            self.save_message(text, recipient=selected_chat)

        self.app.message_input.clear()
        self.app.chat_data_loader.load_chat_history()

    def display_message(self, sender, text):
        msg_widget = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(msg_widget)
        layout.setContentsMargins(8, 4, 8, 4)

        label = QtWidgets.QLabel(f"<b>{sender}:</b> {text}")
        label.setWordWrap(True)
        label.setStyleSheet("""
            QLabel {
                color: aqua;
                background-color: #e0ffe0;
                padding: 6px;
                border-radius: 8px;
            }
        """)
        layout.addWidget(label)
        self.app.chat_display_layout.addWidget(msg_widget)

    def save_message(self, content, recipient=None, group_name=None, is_image=False, file_path=None):
        session = self.session_factory()
        try:
            msg = Message(
                sender_username=self.app.username,
                receiver_username=recipient,
                message=content if not is_image else "",
                is_image=is_image,
                file_path=file_path
            )
            if group_name:
                group = session.query(Group).filter_by(name=group_name).first()
                if group:
                    msg.group_id = group.id
            session.add(msg)
            session.commit()
        finally:
            session.close()

    def receive_message(self, message):
            if message.startswith("CONTACTLIST|"):
                self._handle_contact_list(message)
            elif message.startswith("GROUPLIST|"):
                self._handle_group_list(message)
            elif message.startswith("CONTACTADDED|"):
                self._handle_contact_added(message)
            elif message.startswith("CONTACTFAILED|"):
                self._handle_contact_failed(message)
            elif message.startswith("UPDATEUSERNAME|"):
                self._handle_username_change(message)
            elif message.startswith("PROFILECHANGED|"):
                self._handle_profile_change(message)
            else:
                self._handle_chat_message(message)

    def _handle_profile_change(self, message):
        string, changed_username = message.split("|", 1)
        self.app.chat_data_loader.load_user_list()
        self.app.chat_data_loader.load_profile_picture()
        if self.app.current_chat == changed_username:
            self.app.chat_data_loader.load_chat_history()

    def _handle_contact_list(self, message):
            usernames = message.split("|")[1:]
            self.app.user_list.clear()

            session = self.session_factory()
            users = {u.username: u for u in session.query(User).filter(User.username.in_(usernames)).all()}
            session.close()

            for username in usernames:
                item = QtWidgets.QListWidgetItem()
                item.setSizeHint(QtCore.QSize(220, 60))
                user = users.get(username)
                profile = user.profile_picture if user and user.profile_picture and os.path.exists(
                    user.profile_picture) else None
                widget = UserListItemWidget(username, profile)
                self.app.user_list.addItem(item)
                self.app.user_list.setItemWidget(item, widget)

            self.app.send_button.setEnabled(self.app.user_list.count() > 0)
            if self.app.user_list.count() > 0:
                self.app.user_list.setCurrentRow(0)

    def _handle_group_list(self, message):
        groups = message.split("|")[1:]

        for i in reversed(range(self.app.user_list.count())):
            item = self.app.user_list.item(i)
            widget = self.app.user_list.itemWidget(item)
            if widget and widget.text_label.text().startswith("[Group]"):
                self.app.user_list.takeItem(i)

        for group in groups:
            if group.strip():
                item = QtWidgets.QListWidgetItem()
                item.setSizeHint(QtCore.QSize(220, 60))
                widget = UserListItemWidget(f"[Group] {group}", "group_icon.png", is_group=True)
                self.app.user_list.addItem(item)
                self.app.user_list.setItemWidget(item, widget)
        self.app.chat_data_loader.load_user_list()

    def _handle_contact_added(self, message):
            _, username = message.split("|", 1)
            self.app.user_list.addItem(username)
            self.app.client_socket.sendall("GETCONTACTS".encode('utf-8'))

    def _handle_contact_failed(self, message):
            _, error = message.split("|")
            QtWidgets.QMessageBox.warning(self.app, "Add Contact Failed", error)

    def _handle_username_change(self, message):
            _, old_username, new_username = message.split("|")
            self.update_username_in_list(old_username, new_username)

    def _handle_chat_message(self, message):
        if message.startswith("FROM|"):
            parts = message.split("|")

            sender = parts[1]
            recipient = parts[3]
            content = "|".join(parts[4:])
            self.app.message_handler.save_message(content, recipient)
            current_item = self.app.user_list.currentItem()

            if self.app.current_chat == sender:
                ts = datetime.now().strftime('%H:%M')
                self.app.message_handler.display_message( sender,f"{ts}: {content}")
                self.app.chat_data_loader.load_chat_history()
            else:
                for i in range(self.app.user_list.count()):
                    item = self.app.user_list.item(i)
                    widget = self.app.user_list.itemWidget(item)
                    if widget.text_label.text().replace(" (New)", "") == sender:
                        if "(New)" not in widget.text_label.text():
                            widget.text_label.setText(widget.text_label.text() + " (New)")
                        break

        elif message.startswith("GROUPMSG|"):
            parts = message.split("|")
            sender = parts[1]
            group_name = parts[2]
            content = "|".join(parts[3:])

            if self.app.current_chat  == f"[Group] {group_name}":
                    ts = datetime.now().strftime('%H:%M')
                    self.app.message_handler.display_message(sender ,f"{ts} [Group: {group_name}] : {content}")
                    self.app.chat_data_loader.load_chat_history()
            else:
                for i in range(self.app.user_list.count()):
                    item = self.app.user_list.item(i)
                    widget = self.app.user_list.itemWidget(item)
                    if widget:
                        text = widget.text_label.text().replace(" (New)", "")
                        if text == f"[Group] {group_name}":
                            if "(New)" not in widget.text_label.text():
                                widget.text_label.setText(widget.text_label.text() + " (New)")
                            break
        elif message.startswith("IMAGE|"):
            parts = message.split("|", 4)
            sender = parts[1]
            chat_id = parts[2]
            encoded = parts[4]
            image_path = self.save_image(encoded, sender, chat_id)

            is_group = chat_id.startswith("[Group]")
            clean_chat_id = chat_id.replace("[Group] ", "") if is_group else chat_id
            self.app.message_handler.save_message(
                                content="[Image]",
                                recipient=None if is_group else clean_chat_id,
                                group_name=clean_chat_id if is_group else None,
                                is_image=True,
                                file_path=image_path
                            )
            if self.app.current_chat == chat_id or self.app.current_chat == f"[Group] {chat_id}":
                self.display_image_message(sender, image_path)
                self.app.scroll_to_bottom()
            else:
                for i in range(self.app.user_list.count()):
                    item = self.app.user_list.item(i)
                    widget = self.app.user_list.itemWidget(item)
                    if widget and widget.text_label.text().replace(" (New)", "") == chat_id:
                        if "(New)" not in widget.text_label.text():
                                widget.text_label.setText(widget.text_label.text() + " (New)")
                        break

    def display_image_message(self, sender, image_path):
        container = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(container)
        layout.setContentsMargins(8, 4, 8, 4)

        sender_label = QtWidgets.QLabel(f"<b>{sender}:</b>")
        image_label = QtWidgets.QLabel()
        pixmap = QtGui.QPixmap(image_path)
        image_label.setPixmap(pixmap.scaledToWidth(200, QtCore.Qt.TransformationMode.SmoothTransformation))
        image_label.setStyleSheet("padding: 4px; border: 1px solid #ccc; background-color: #fff;")

        layout.addWidget(sender_label)
        layout.addWidget(image_label)

        self.app.chat_display_layout.addWidget(container)

    def safe_base64_decode(self, data):
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        return base64.b64decode(data)

    def save_image(self, encoded, sender, chat_id):
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        filename = f"{chat_id}_{sender}_{timestamp}.jpg"
        filepath = os.path.join(IMAGE_DIR, filename)

        with open(filepath, "wb") as f:
            f.write(self.safe_base64_decode(encoded))

        return filepath

    def update_username_in_list(self, old_username, new_username):
        for i in range(self.app.user_list.count()):
            item = self.app.user_list.item(i)
            widget = self.app.user_list.itemWidget(item)
            if widget and hasattr(widget, 'text_label') and widget.text_label.text() == old_username:
                widget.text_label.setText(new_username)
                break

        current_item = self.app.user_list.currentItem()
        if current_item:
            current_widget = self.app.user_list.itemWidget(current_item)
            if current_widget and current_widget.text_label.text() == new_username:
                return

            if current_widget and current_widget.text_label.text() == old_username:
                self.app.user_list.setCurrentItem(None)
                for i in range(self.app.user_list.count()):
                    item = self.app.user_list.item(i)
                    widget = self.app.user_list.itemWidget(item)
                    if widget and widget.text_label.text() == new_username:
                        self.app.user_list.setCurrentRow(i)
                        break


class GroupHandler:
    def __init__(self, app_instance):
        self.app = app_instance
        self.session_factory = Session

    def create_group(self):
        dialog = QtWidgets.QDialog(self.app)
        dialog.setWindowTitle("Create Group")
        layout = QtWidgets.QVBoxLayout(dialog)

        group_name_input = QtWidgets.QLineEdit()
        layout.addWidget(QtWidgets.QLabel("Group Name:"))
        layout.addWidget(group_name_input)

        user_checkboxes = []
        for i in range(self.app.user_list.count()):
            item = self.app.user_list.item(i)
            widget = self.app.user_list.itemWidget(item)
            if widget:
                username = widget.text_label.text().replace(" (New)", "")
                if username.startswith("[Group]") or username == self.app.username:
                    continue
                cb = QtWidgets.QCheckBox(username)
                layout.addWidget(cb)
                user_checkboxes.append(cb)

        create_button = QtWidgets.QPushButton("Create")
        layout.addWidget(create_button)

        def save_group():
            group_name = group_name_input.text().strip()
            selected_users = [cb.text() for cb in user_checkboxes if cb.isChecked()]
            if not group_name or not selected_users:
                QtWidgets.QMessageBox.warning(dialog, "Invalid Input", "Please provide a group name and select users.")
                return

            session = self.session_factory()
            try:
                group = Group(name=group_name)
                session.add(group)
                session.flush()

                for username in selected_users + [self.app.username]:
                    user = session.query(User).filter_by(username=username).first()
                    if user:
                        gm = GroupMember(group_id=group.id, user_id=user.id)
                        session.add(gm)

                session.commit()
                self.app.client_socket.sendall(f"NEWGROUP|{group_name}".encode('utf-8'))

                QtWidgets.QMessageBox.information(self.app, "Group Created",
                                                  "Group created successfully! It will appear for all members shortly.")
            except Exception as e:
                QtWidgets.QMessageBox.warning(self.app, "Error", f"Failed to create group: {e}")
            finally:
                session.close()
                dialog.accept()

        create_button.clicked.connect(save_group)
        dialog.exec()

    def add_member_to_group(self):
        if not self.app.current_chat or not self.app.current_chat.startswith("[Group]"):
            QtWidgets.QMessageBox.warning(self.app, "Error", "Select a group to add members.")
            return

        group_name = self.app.current_chat.replace("[Group] ", "")
        username, ok = QtWidgets.QInputDialog.getText(self.app, "Add Member", "Enter username to add:")

        if ok and username.strip():
            try:
                message = f"ADDMEMBER|{group_name}|{username.strip()}"
                self.app.client_socket.send(message.encode('utf-8'))
                QtWidgets.QMessageBox.information(self.app, "Request Sent",
                                                  f"Add request sent for user '{username.strip()}'.")
            except Exception as e:
                QtWidgets.QMessageBox.warning(self.app, "Error", f"Failed to send request: {e}")

    def leave_group(self, group_name):
        session = self.session_factory()
        try:
            group = session.query(Group).filter_by(name=group_name).first()
            if not group:
                QtWidgets.QMessageBox.warning(self.app, "Error", "Group does not exist.")
                return
            user = session.query(User).filter_by(username=self.app.username).first()
            gm = session.query(GroupMember).filter_by(group_id=group.id, user_id=user.id).first()
            if not gm:
                QtWidgets.QMessageBox.warning(self.app, "Error", "You are not a member of this group.")
                return
            session.delete(gm)
            session.commit()
            QtWidgets.QMessageBox.information(self.app, "Left Group", f"You left '{group_name}'.")
            self.app.chat_data_loader.load_user_list()
            if self.app.current_chat == f"[Group] {group_name}":
                self.app.chat_display_layout.takeAt(0)
                self.app.current_chat = None
                self.app.chat_display_layout.addWidget(QtWidgets.QLabel("You left this group."))
        finally:
            session.close()

class SettingsManager:
    def __init__(self, app_instance):
        self.app = app_instance
        self.session_factory = Session

    def open_settings(self):
        dialog = QtWidgets.QDialog(self.app)
        dialog.setWindowTitle("Settings")
        layout = QtWidgets.QVBoxLayout(dialog)
        dialog.setStyleSheet("QDialog { border-image: url(back4.jpg) stretch; }")

        session = self.session_factory()
        user = session.query(User).filter_by(username=self.app.username).first()
        session.close()

        profile_pic_label = QtWidgets.QLabel()
        profile_pic_label.setFixedSize(100, 100)
        if user and user.profile_picture and os.path.exists(user.profile_picture):
            pixmap = QtGui.QPixmap(user.profile_picture).scaled(
                100, 100, QtCore.Qt.AspectRatioMode.KeepAspectRatio,
                QtCore.Qt.TransformationMode.SmoothTransformation
            )
            profile_pic_label.setPixmap(pixmap)

        layout.addWidget(QtWidgets.QLabel("Current Profile Picture:"))
        layout.addWidget(profile_pic_label)
        profile_pic_label.mousePressEvent = lambda event: self._show_full_profile_picture(user)

        username_input = QtWidgets.QLineEdit(self.app.username)
        password_input = QtWidgets.QLineEdit()
        password_input.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        profile_pic_button = QtWidgets.QPushButton("Set Profile Picture")

        layout.addWidget(QtWidgets.QLabel("Change Username:"))
        layout.addWidget(username_input)
        layout.addWidget(QtWidgets.QLabel("Change Password:"))
        layout.addWidget(password_input)
        layout.addWidget(profile_pic_button)

        save_button = QtWidgets.QPushButton("Save Changes")
        layout.addWidget(save_button)

        profile_pic_button.clicked.connect(lambda: self._select_profile_picture(profile_pic_button))
        save_button.clicked.connect(
            lambda: self._save_changes(dialog, username_input, password_input, profile_pic_button)
        )
        dialog.exec()

    def _show_full_profile_picture(self, user):
        if user and user.profile_picture and os.path.exists(user.profile_picture):
            pic_dialog = QtWidgets.QDialog(self.app)
            pic_dialog.setWindowTitle("Full Profile Picture")
            layout = QtWidgets.QVBoxLayout(pic_dialog)
            label = QtWidgets.QLabel()
            pixmap = QtGui.QPixmap(user.profile_picture).scaled(
                400, 400, QtCore.Qt.AspectRatioMode.KeepAspectRatio
            )
            label.setPixmap(pixmap)
            layout.addWidget(label)
            pic_dialog.exec()

    def _select_profile_picture(self, button):
        file_name, _ = QtWidgets.QFileDialog.getOpenFileName(
            self.app, "Select Profile Picture", "", "Images (*.png *.jpg *.jpeg *.bmp)"
        )
        if file_name:
            target_dir = "profile_pics"
            os.makedirs(target_dir, exist_ok=True)
            target_path = os.path.join(target_dir, os.path.basename(file_name))
            shutil.copy(file_name, target_path)
            button.setText(os.path.basename(file_name))
            button.file_path = target_path

    def _save_changes(self, dialog, username_input, password_input, profile_pic_button):
        new_username = username_input.text().strip()
        new_password = password_input.text().strip()
        old_username = self.app.username

        session = self.session_factory()
        user = session.query(User).filter_by(username=old_username).first()

        if user:
            if new_username and new_username != old_username:

                user.username = new_username
                session.query(Message).filter_by(sender_username=old_username).update(
                    {Message.sender_username: new_username}, synchronize_session=False)
                session.query(Message).filter_by(receiver_username=old_username).update(
                    {Message.receiver_username: new_username}, synchronize_session=False)
                session.commit()

                self.app.username = new_username
                self.app.client_socket.sendall(
                    f"USERNAMECHANGE|{old_username}|{new_username}".encode("utf-8")
                )
                self.app.message_handler.update_username_in_list(old_username, new_username)

            if new_password:
                user.password = new_password

            if hasattr(profile_pic_button, "file_path"):
                user.profile_picture = profile_pic_button.file_path
                session.commit()
                self.app.chat_data_loader.load_profile_picture()
                self.app.client_socket.sendall(f"PROFILECHANGE|{self.app.username}".encode("utf-8"))

            QtWidgets.QMessageBox.information(dialog, "Success", "Settings updated successfully.")
            self.app.chat_data_loader.load_user_list()

        session.close()
        dialog.accept()

    def open_context_menu(self, position):
        item = self.app.user_list.itemAt(position)
        if not item:
            return

        widget = self.app.user_list.itemWidget(item)
        if not widget:
            return

        username_or_group = widget.text_label.text()
        menu = QtWidgets.QMenu()

        if username_or_group.startswith("[Group]"):
            leave_action = menu.addAction("Leave Group")
            selected = menu.exec(self.app.user_list.mapToGlobal(position))
            if selected == leave_action:
                group_name = username_or_group.replace("[Group] ", "")
                self.app.group_handler.leave_group(group_name)
        else:
            view_profile_action = menu.addAction("View Profile")
            selected = menu.exec(self.app.user_list.mapToGlobal(position))
            if selected == view_profile_action:
                self.view_profile(username_or_group)

    def view_profile(self, username):
        session = self.session_factory()
        user = session.query(User).filter_by(username=username).first()
        session.close()

        if user and user.profile_picture and os.path.exists(user.profile_picture):
            pic_dialog = QtWidgets.QDialog(self.app)
            pic_dialog.setWindowTitle(f"{username}'s Profile Picture")
            layout = QtWidgets.QVBoxLayout(pic_dialog)
            label = QtWidgets.QLabel()
            pixmap = QtGui.QPixmap(user.profile_picture).scaled(
                300, 300, QtCore.Qt.AspectRatioMode.KeepAspectRatio
            )
            label.setPixmap(pixmap)
            layout.addWidget(label)
            pic_dialog.exec()

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = MessengerApp()
    window.show()
    sys.exit(app.exec())
