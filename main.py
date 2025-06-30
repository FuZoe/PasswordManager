import sys
import os
import json
import random
import string
import csv
import webbrowser
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem,
                             QMessageBox, QInputDialog, QFileDialog, QAction, QToolBar,
                             QAbstractItemView, QTabWidget, QTextEdit, QCheckBox, QDialog,
                             QScrollArea, QSizePolicy, QMenu)
from PyQt5.QtCore import Qt, QSize, QUrl
from PyQt5.QtGui import QIcon, QFont, QDesktopServices
from cryptography.fernet import Fernet
from hashlib import sha256
import traceback


class PasswordManager(QMainWindow):
    def __init__(self):
        super().__init__()
        try:
            self.setWindowTitle("安全密码管理器")
            self.setGeometry(100, 100, 1724, 1028)

            # 加密相关
            self.key = None
            self.cipher_suite = None
            self.data_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "passwords.enc")
            self.key_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "key.key")

            # 双击复制弹窗限制
            self.copy_notification_shown = False

            self.init_ui()
        except Exception as e:
            self.show_error("初始化错误", traceback.format_exc())

    def init_ui(self):
        try:
            # 设置基础字体
            self.base_font = QFont('Microsoft YaHei', 11)
            self.setFont(self.base_font)

            # 样式表
            self.setStyleSheet("""
                QMainWindow, QDialog {
                    background-color: #f5f5f5;
                }
                QWidget {
                    font-family: 'Microsoft YaHei';
                    font-size: 14px;
                }
                QPushButton {
                    background-color: #4CAF50;
                    color: white;
                    border: none;
                    padding: 12px 24px;
                    font-size: 14px;
                    min-width: 120px;
                    min-height: 40px;
                    border-radius: 4px;
                }
                QPushButton:hover { background-color: #45a049; }
                QPushButton:pressed { background-color: #3e8e41; }
                QLineEdit, QTextEdit {
                    padding: 12px;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                    font-size: 14px;
                    min-height: 40px;
                }
                QTableWidget {
                    background-color: white;
                    border: 1px solid #ddd;
                    font-size: 14px;
                    selection-background-color: #e0f7fa;
                }
                QHeaderView::section {
                    background-color: #4CAF50;
                    color: white;
                    padding: 14px;
                    font-size: 14px;
                    font-weight: bold;
                }
                QTabWidget::pane {
                    border: 1px solid #ddd;
                    background: white;
                    padding: 10px;
                }
                QTabBar::tab {
                    background: #f1f1f1;
                    padding: 14px 24px;
                    border: 1px solid #ddd;
                    border-bottom: none;
                    border-top-left-radius: 4px;
                    border-top-right-radius: 4px;
                    font-size: 14px;
                }
                QTabBar::tab:selected {
                    background: white;
                    margin-bottom: -1px;
                    font-weight: bold;
                }
                QLabel {
                    font-size: 14px;
                    margin-bottom: 8px;
                }
                QTextEdit {
                    min-height: 120px;
                }
                QScrollArea {
                    border: none;
                }
            """)

            # 中央部件
            self.central_widget = QWidget()
            self.setCentralWidget(self.central_widget)
            self.main_layout = QVBoxLayout(self.central_widget)
            self.main_layout.setContentsMargins(25, 25, 25, 25)
            self.main_layout.setSpacing(20)

            # 创建界面
            self.create_login_ui()
            self.create_main_ui()
            self.create_menu_bar()

            # 初始显示登录界面
            self.main_layout.addWidget(self.login_widget)
            self.main_widget.hide()

            # 检查是否已有主密码
            if os.path.exists(self.key_file):
                try:
                    with open(self.key_file, 'rb') as f:
                        self.key = f.read()
                    self.cipher_suite = Fernet(self.key)
                except Exception as e:
                    self.show_error("密钥加载错误", traceback.format_exc())
        except Exception as e:
            self.show_error("UI初始化错误", traceback.format_exc())

    def create_login_ui(self):
        try:
            self.login_widget = QWidget()
            self.login_layout = QVBoxLayout(self.login_widget)
            self.login_layout.setContentsMargins(60, 60, 60, 60)
            self.login_layout.setSpacing(25)

            # 标题
            self.title_label = QLabel("安全密码管理器")
            self.title_label.setAlignment(Qt.AlignCenter)
            self.title_label.setFont(QFont('Microsoft YaHei', 20, QFont.Bold))

            # 密码输入
            self.password_label = QLabel("请输入主密码:")
            self.password_label.setAlignment(Qt.AlignCenter)
            self.password_label.setFont(QFont('Microsoft YaHei', 14))

            self.password_input = QLineEdit()
            self.password_input.setEchoMode(QLineEdit.Password)
            self.password_input.setPlaceholderText("输入主密码")
            self.password_input.setMinimumHeight(45)

            # 登录按钮
            self.login_button = QPushButton("登 录")
            self.login_button.setMinimumHeight(45)
            self.login_button.clicked.connect(self.authenticate)

            # 添加到布局
            self.login_layout.addWidget(self.title_label)
            self.login_layout.addSpacing(30)
            self.login_layout.addWidget(self.password_label)
            self.login_layout.addWidget(self.password_input)
            self.login_layout.addWidget(self.login_button)
            self.login_layout.addStretch()
        except Exception as e:
            self.show_error("登录界面创建错误", traceback.format_exc())

    def create_main_ui(self):
        try:
            self.main_widget = QTabWidget()
            self.main_widget.setFont(QFont('Microsoft YaHei', 11))

            # 密码管理标签页
            self.create_password_tab()

            # 设置标签页
            self.create_settings_tab()
        except Exception as e:
            self.show_error("主界面创建错误", traceback.format_exc())

    def create_password_tab(self):
        try:
            self.password_tab = QWidget()
            self.password_tab_layout = QVBoxLayout(self.password_tab)
            self.password_tab_layout.setContentsMargins(20, 20, 20, 20)
            self.password_tab_layout.setSpacing(20)

            # 搜索栏
            self.search_layout = QHBoxLayout()
            self.search_layout.setSpacing(15)

            self.search_input = QLineEdit()
            self.search_input.setPlaceholderText("输入关键词搜索...")
            self.search_input.setMinimumHeight(40)
            self.search_input.textChanged.connect(self.filter_table)

            self.search_button = QPushButton("搜 索")
            self.search_button.setMinimumHeight(40)
            self.search_button.clicked.connect(self.filter_table)

            self.search_layout.addWidget(self.search_input)
            self.search_layout.addWidget(self.search_button)

            # 密码表格
            self.password_table = QTableWidget()
            self.password_table.setColumnCount(7)
            self.password_table.setHorizontalHeaderLabels(["名称", "网址", "用户名", "密码", "手机", "邮箱", "备注"])
            self.password_table.horizontalHeader().setStretchLastSection(True)
            self.password_table.setSelectionBehavior(QAbstractItemView.SelectRows)
            self.password_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
            self.password_table.verticalHeader().setDefaultSectionSize(45)

            # 设置列宽
            self.password_table.setColumnWidth(0, 180)  # 名称
            self.password_table.setColumnWidth(1, 220)  # 网址
            self.password_table.setColumnWidth(2, 180)  # 用户名
            self.password_table.setColumnWidth(3, 180)  # 密码
            self.password_table.setColumnWidth(4, 150)  # 手机
            self.password_table.setColumnWidth(5, 200)  # 邮箱

            # 启用右键菜单
            self.password_table.setContextMenuPolicy(Qt.CustomContextMenu)
            self.password_table.customContextMenuRequested.connect(self.show_context_menu)

            # 操作按钮
            self.button_layout = QHBoxLayout()
            self.button_layout.setSpacing(20)

            self.add_button = QPushButton("添 加")
            self.add_button.setMinimumHeight(45)
            self.add_button.clicked.connect(self.add_entry)

            self.edit_button = QPushButton("编 辑")
            self.edit_button.setMinimumHeight(45)
            self.edit_button.clicked.connect(self.edit_entry)

            self.delete_button = QPushButton("删 除")
            self.delete_button.setMinimumHeight(45)
            self.delete_button.clicked.connect(self.delete_entry)

            self.generate_button = QPushButton("生成密码")
            self.generate_button.setMinimumHeight(45)
            self.generate_button.clicked.connect(self.generate_password)

            # 导入按钮
            self.import_button = QPushButton("批量导入")
            self.import_button.setMinimumHeight(45)
            self.import_button.clicked.connect(self.import_entries)

            # 模板按钮
            self.template_button = QPushButton("导出模板")
            self.template_button.setMinimumHeight(45)
            self.template_button.clicked.connect(self.export_template)

            # 备份和恢复按钮
            self.backup_button = QPushButton("备 份")
            self.backup_button.setMinimumHeight(45)
            self.backup_button.clicked.connect(self.backup_data)

            self.restore_button = QPushButton("恢 复")
            self.restore_button.setMinimumHeight(45)
            self.restore_button.clicked.connect(self.restore_data)

            self.button_layout.addWidget(self.add_button)
            self.button_layout.addWidget(self.edit_button)
            self.button_layout.addWidget(self.delete_button)
            self.button_layout.addWidget(self.generate_button)
            self.button_layout.addWidget(self.import_button)
            self.button_layout.addWidget(self.template_button)
            self.button_layout.addWidget(self.backup_button)
            self.button_layout.addWidget(self.restore_button)

            # 添加到标签页
            self.password_tab_layout.addLayout(self.search_layout)
            self.password_tab_layout.addWidget(self.password_table)
            self.password_tab_layout.addLayout(self.button_layout)

            self.main_widget.addTab(self.password_tab, "密码管理")
        except Exception as e:
            self.show_error("密码标签页创建错误", traceback.format_exc())

    def create_settings_tab(self):
        try:
            self.settings_tab = QWidget()
            self.settings_tab_layout = QVBoxLayout(self.settings_tab)
            self.settings_tab_layout.setContentsMargins(40, 40, 40, 40)
            self.settings_tab_layout.setSpacing(25)

            # 更改密码按钮
            self.change_password_button = QPushButton("更改主密码")
            self.change_password_button.setMinimumHeight(50)
            self.change_password_button.clicked.connect(self.change_master_password)

            # 添加到布局
            self.settings_tab_layout.addWidget(self.change_password_button)
            self.settings_tab_layout.addStretch()

            self.main_widget.addTab(self.settings_tab, "设 置")
        except Exception as e:
            self.show_error("设置标签页创建错误", traceback.format_exc())

    def create_menu_bar(self):
        try:
            menubar = self.menuBar()

            # 文件菜单
            file_menu = menubar.addMenu('文件')

            import_action = QAction('批量导入', self)
            import_action.triggered.connect(self.import_entries)
            file_menu.addAction(import_action)

            template_action = QAction('导出模板', self)
            template_action.triggered.connect(self.export_template)
            file_menu.addAction(template_action)

            file_menu.addSeparator()

            backup_action = QAction('备份', self)
            backup_action.triggered.connect(self.backup_data)
            file_menu.addAction(backup_action)

            restore_action = QAction('恢复', self)
            restore_action.triggered.connect(self.restore_data)
            file_menu.addAction(restore_action)

            file_menu.addSeparator()

            exit_action = QAction('退出', self)
            exit_action.triggered.connect(self.close)
            file_menu.addAction(exit_action)

            # 工具菜单
            tools_menu = menubar.addMenu('工具')

            generate_action = QAction('生成密码', self)
            generate_action.triggered.connect(self.generate_password)
            tools_menu.addAction(generate_action)

            # 帮助菜单
            help_menu = menubar.addMenu('帮助')

            about_action = QAction('关于', self)
            about_action.triggered.connect(self.show_about)
            help_menu.addAction(about_action)
        except Exception as e:
            self.show_error("菜单栏创建错误", traceback.format_exc())

    def export_template(self):
        """导出CSV导入模板"""
        try:
            options = QFileDialog.Options()
            file_name, _ = QFileDialog.getSaveFileName(self, "保存模板文件", "密码导入模板.csv",
                                                       "CSV文件 (*.csv);;所有文件 (*)",
                                                       options=options)
            if not file_name:
                return

            if not file_name.lower().endswith('.csv'):
                file_name += '.csv'

            # 创建模板文件（使用UTF-8编码并添加BOM解决中文兼容问题）
            with open(file_name, 'w', encoding='utf-8-sig', newline='') as csvfile:
                fieldnames = ['名称', '网址', '用户名', '密码', '手机', '邮箱', '备注']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

                # 添加示例数据
                writer.writerow({
                    '名称': '谷歌账户',
                    '网址': 'https://google.com',
                    '用户名': 'user@gmail.com',
                    '密码': 'StrongPass123!',
                    '手机': '13800138000',
                    '邮箱': 'user@gmail.com',
                    '备注': '主要工作账户'
                })
                writer.writerow({
                    '名称': '微信',
                    '网址': '',
                    '用户名': 'my_wechat',
                    '密码': 'WechatPass456',
                    '手机': '',
                    '邮箱': '',
                    '备注': '个人微信账号'
                })

            QMessageBox.information(self, "成功", f"模板文件已保存到: {file_name}")
        except Exception as e:
            self.show_error("导出模板失败", traceback.format_exc())

    def import_entries(self):
        """批量导入密码条目"""
        try:
            options = QFileDialog.Options()
            file_name, _ = QFileDialog.getOpenFileName(self, "选择CSV文件", "",
                                                       "CSV文件 (*.csv);;所有文件 (*)",
                                                       options=options)
            if not file_name:
                return

            # 读取CSV文件
            entries = []
            error_lines = []
            try:
                # 尝试使用不同的编码打开文件
                encodings = ['utf-8-sig', 'utf-8', 'gbk', 'latin-1']

                for encoding in encodings:
                    try:
                        with open(file_name, 'r', encoding=encoding) as csvfile:
                            reader = csv.DictReader(csvfile)

                            # 验证字段
                            required_fields = ['名称', '用户名', '密码']
                            field_map = {
                                '名称': 'name',
                                '网址': 'url',
                                '用户名': 'username',
                                '密码': 'password',
                                '手机': 'phone',
                                '邮箱': 'email',
                                '备注': 'notes'
                            }

                            # 检查是否包含必要字段
                            if not all(field in reader.fieldnames for field in required_fields):
                                continue

                            for i, row in enumerate(reader, 1):
                                try:
                                    # 映射字段到英文键名
                                    entry = {}
                                    for cn_field, en_field in field_map.items():
                                        if cn_field in row:
                                            entry[en_field] = row[cn_field].strip()
                                        else:
                                            entry[en_field] = ''

                                    # 检查必要字段
                                    if not entry['name'] or not entry['username'] or not entry['password']:
                                        error_lines.append(f"第 {i} 行: 缺少必要字段")
                                        continue

                                    entries.append(entry)
                                except Exception as e:
                                    error_lines.append(f"第 {i} 行: {str(e)}")

                            # 如果成功读取数据，跳出循环
                            break
                    except UnicodeDecodeError:
                        continue
                    except Exception as e:
                        error_lines.append(f"读取错误: {str(e)}")
                        continue
            except Exception as e:
                QMessageBox.warning(self, "错误", f"读取CSV文件失败: {str(e)}")
                return

            if not entries and not error_lines:
                QMessageBox.warning(self, "警告", "CSV文件中没有有效数据!")
                return

            # 显示错误信息
            if error_lines:
                error_msg = "\n".join(error_lines[:10])  # 最多显示10个错误
                if len(error_lines) > 10:
                    error_msg += f"\n... 以及另外 {len(error_lines) - 10} 个错误"

                QMessageBox.warning(self, "导入警告",
                                    f"导入过程中发现 {len(error_lines)} 个错误:\n\n{error_msg}")

            # 确认导入
            reply = QMessageBox.question(self, '确认导入',
                                         f'确定要导入 {len(entries)} 条记录吗?',
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.No:
                return

            # 导入数据
            data = self.load_data()
            data.extend(entries)
            self.save_data(data)
            self.load_password_table()

            QMessageBox.information(self, "成功", f"成功导入 {len(entries)} 条记录!")

        except Exception as e:
            self.show_error("导入错误", traceback.format_exc())

    def show_context_menu(self, position):
        """显示右键菜单 - 修复密码字段右键错误"""
        try:
            # 获取点击位置的索引
            index = self.password_table.indexAt(position)
            if not index.isValid():
                return

            row = index.row()
            col = index.column()

            # 只处理密码列
            if col != 3:
                return

            # 获取单元格项
            item = self.password_table.item(row, col)
            if not item:
                return

            # 创建右键菜单
            menu = QMenu()

            # 添加显示/隐藏密码选项
            if item.text() == "******":
                show_action = menu.addAction("显示密码")
            else:
                show_action = menu.addAction("隐藏密码")

            # 添加复制密码选项
            copy_action = menu.addAction("复制密码")

            # 显示菜单并获取用户选择
            action = menu.exec_(self.password_table.viewport().mapToGlobal(position))

            # 处理用户选择
            if action == show_action:
                if item.text() == "******":
                    item.setText(item.data(Qt.UserRole))
                else:
                    item.setText("******")
            elif action == copy_action:
                clipboard = QApplication.clipboard()
                clipboard.setText(item.data(Qt.UserRole))
                if not self.copy_notification_shown:
                    QMessageBox.information(self, "复制成功", "密码已复制到剪贴板")
                    self.copy_notification_shown = True

        except Exception as e:
            # 记录错误但不中断程序
            print(f"右键菜单错误: {str(e)}")
            traceback.print_exc()

    def authenticate(self):
        try:
            password = self.password_input.text()
            if not password:
                QMessageBox.warning(self, "错误", "请输入密码!")
                return

            # 如果是第一次运行，设置主密码
            if not os.path.exists(self.key_file):
                self.set_master_password()
                return

            try:
                # 加载密钥
                with open(self.key_file, 'rb') as f:
                    self.key = f.read()
                self.cipher_suite = Fernet(self.key)

                # 尝试解密数据文件来验证密码
                if os.path.exists(self.data_file):
                    with open(self.data_file, 'r') as f:
                        encrypted_data = f.read()
                    self.cipher_suite.decrypt(encrypted_data.encode())

                # 验证成功，显示主界面
                self.main_layout.removeWidget(self.login_widget)
                self.login_widget.hide()
                self.main_layout.addWidget(self.main_widget)
                self.main_widget.show()
                self.password_input.clear()
                self.load_password_table()
            except Exception as e:
                QMessageBox.warning(self, "错误", "密码错误或数据损坏!")
        except Exception as e:
            self.show_error("认证错误", traceback.format_exc())

    def set_master_password(self):
        try:
            password, ok = QInputDialog.getText(self, '设置主密码',
                                                '请输入新的主密码:',
                                                QLineEdit.Password)
            if ok and password:
                confirm, ok = QInputDialog.getText(self, '确认主密码',
                                                   '请再次输入主密码:',
                                                   QLineEdit.Password)
                if ok and confirm:
                    if password == confirm:
                        # 生成并保存新密钥
                        self.key = Fernet.generate_key()
                        with open(self.key_file, 'wb') as f:
                            f.write(self.key)
                        self.cipher_suite = Fernet(self.key)

                        # 创建空数据文件
                        self.save_data([])
                        QMessageBox.information(self, "成功", "主密码设置成功!")

                        # 自动登录
                        self.main_layout.removeWidget(self.login_widget)
                        self.login_widget.hide()
                        self.main_layout.addWidget(self.main_widget)
                        self.main_widget.show()
                        self.load_password_table()
                    else:
                        QMessageBox.warning(self, "错误", "两次输入的密码不匹配!")
                        self.set_master_password()
        except Exception as e:
            self.show_error("设置主密码错误", traceback.format_exc())

    def encrypt_data(self, data):
        try:
            data_str = json.dumps(data, ensure_ascii=False)
            return self.cipher_suite.encrypt(data_str.encode()).decode()
        except Exception as e:
            self.show_error("加密错误", traceback.format_exc())
            raise

    def decrypt_data(self, encrypted_data):
        try:
            decrypted_data = self.cipher_suite.decrypt(encrypted_data.encode())
            return json.loads(decrypted_data.decode())
        except Exception as e:
            self.show_error("解密错误", traceback.format_exc())
            raise

    def save_data(self, data):
        try:
            encrypted_data = self.encrypt_data(data)
            with open(self.data_file, 'w', encoding='utf-8') as f:
                f.write(encrypted_data)
        except Exception as e:
            self.show_error("保存数据失败", traceback.format_exc())

    def load_data(self):
        try:
            if not os.path.exists(self.data_file):
                return []

            with open(self.data_file, 'r', encoding='utf-8') as f:
                encrypted_data = f.read()
            return self.decrypt_data(encrypted_data)
        except Exception as e:
            self.show_error("加载数据失败", traceback.format_exc())
            return []

    def load_password_table(self):
        try:
            data = self.load_data()
            self.password_table.setRowCount(len(data))

            for row, entry in enumerate(data):
                self.password_table.setItem(row, 0, QTableWidgetItem(entry.get('name', '')))
                self.password_table.setItem(row, 1, QTableWidgetItem(entry.get('url', '')))
                self.password_table.setItem(row, 2, QTableWidgetItem(entry.get('username', '')))

                # 密码特殊处理
                password_item = QTableWidgetItem("******")
                password_item.setData(Qt.UserRole, entry.get('password', ''))
                password_item.setToolTip("右键点击显示/隐藏密码")
                self.password_table.setItem(row, 3, password_item)

                self.password_table.setItem(row, 4, QTableWidgetItem(entry.get('phone', '')))
                self.password_table.setItem(row, 5, QTableWidgetItem(entry.get('email', '')))
                self.password_table.setItem(row, 6, QTableWidgetItem(entry.get('notes', '')))

            # 连接点击事件（用于网址）
            self.password_table.cellClicked.connect(self.on_cell_clicked)
            # 连接双击事件（用于复制）
            self.password_table.cellDoubleClicked.connect(self.on_cell_double_clicked)
        except Exception as e:
            self.show_error("加载表格失败", traceback.format_exc())

    def on_cell_clicked(self, row, col):
        """处理单元格点击事件"""
        try:
            if col == 1:  # 网址列
                item = self.password_table.item(row, col)
                if not item:
                    return

                url = item.text().strip()
                if not url:
                    return

                if url.startswith(('http://', 'https://')):
                    QDesktopServices.openUrl(QUrl(url))
                else:
                    QDesktopServices.openUrl(QUrl(f"https://{url}"))
        except Exception as e:
            print(f"网址打开错误: {str(e)}")

    def on_cell_double_clicked(self, row, col):
        """处理单元格双击事件 - 复制内容"""
        try:
            item = self.password_table.item(row, col)
            if item and col != 3:  # 密码列不处理双击
                clipboard = QApplication.clipboard()
                clipboard.setText(item.text())

                # 限制只显示一次复制通知
                if not self.copy_notification_shown:
                    QMessageBox.information(self, "复制成功", "内容已复制到剪贴板")
                    self.copy_notification_shown = True
        except Exception as e:
            print(f"复制错误: {str(e)}")

    def filter_table(self):
        try:
            search_text = self.search_input.text().lower()
            for row in range(self.password_table.rowCount()):
                match = False
                for col in range(self.password_table.columnCount()):
                    item = self.password_table.item(row, col)
                    if item and search_text in item.text().lower():
                        match = True
                        break
                self.password_table.setRowHidden(row, not match)
        except Exception as e:
            print(f"搜索过滤错误: {str(e)}")

    def add_entry(self):
        try:
            dialog = PasswordEntryDialog(self)
            if dialog.exec_() == QDialog.Accepted:
                entry = dialog.get_entry()
                data = self.load_data()
                data.append(entry)
                self.save_data(data)
                self.load_password_table()
        except Exception as e:
            self.show_error("添加条目错误", traceback.format_exc())

    def edit_entry(self):
        try:
            selected_rows = self.password_table.selectionModel().selectedRows()
            if not selected_rows:
                QMessageBox.warning(self, "警告", "请选择要编辑的条目!")
                return

            row = selected_rows[0].row()
            data = self.load_data()
            if row >= len(data):
                return

            dialog = PasswordEntryDialog(self)
            dialog.set_entry(data[row])
            if dialog.exec_() == QDialog.Accepted:
                data[row] = dialog.get_entry()
                self.save_data(data)
                self.load_password_table()
        except Exception as e:
            self.show_error("编辑条目错误", traceback.format_exc())

    def delete_entry(self):
        try:
            selected_rows = self.password_table.selectionModel().selectedRows()
            if not selected_rows:
                QMessageBox.warning(self, "警告", "请选择要删除的条目!")
                return

            reply = QMessageBox.question(self, '确认', '确定要删除选中的条目吗?',
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

            if reply == QMessageBox.Yes:
                row = selected_rows[0].row()
                data = self.load_data()
                if row < len(data):
                    data.pop(row)
                    self.save_data(data)
                    self.load_password_table()
        except Exception as e:
            self.show_error("删除条目错误", traceback.format_exc())

    def generate_password(self):
        try:
            length, ok = QInputDialog.getInt(self, '生成密码', '密码长度:', 12, 8, 32, 1)
            if ok:
                chars = string.ascii_letters + string.digits + "!@#$%^&*()"
                password = ''.join(random.choice(chars) for _ in range(length))

                msg = QMessageBox()
                msg.setWindowTitle("生成的密码")
                msg.setText(password)
                msg.setStandardButtons(QMessageBox.Ok)

                # 添加复制按钮
                copy_button = QPushButton("复制")
                copy_button.clicked.connect(lambda: QApplication.clipboard().setText(password))
                msg.addButton(copy_button, QMessageBox.ActionRole)

                msg.exec_()
        except Exception as e:
            self.show_error("生成密码错误", traceback.format_exc())

    def change_master_password(self):
        try:
            old_password, ok = QInputDialog.getText(self, '更改主密码',
                                                    '请输入当前主密码:',
                                                    QLineEdit.Password)
            if not ok or not old_password:
                return

            try:
                # 临时保存当前密钥
                temp_key = self.key
                temp_cipher = self.cipher_suite

                # 测试当前密码是否正确
                self.load_data()

                # 输入新密码
                new_password, ok = QInputDialog.getText(self, '更改主密码',
                                                        '请输入新的主密码:',
                                                        QLineEdit.Password)
                if ok and new_password:
                    confirm, ok = QInputDialog.getText(self, '确认新密码',
                                                       '请再次输入新密码:',
                                                       QLineEdit.Password)
                    if ok and confirm:
                        if new_password == confirm:
                            # 生成新密钥
                            self.key = Fernet.generate_key()
                            self.cipher_suite = Fernet(self.key)

                            # 保存新密钥
                            with open(self.key_file, 'wb') as f:
                                f.write(self.key)

                            # 用新密钥重新加密数据
                            data = self.load_data()  # 用旧密钥解密
                            self.save_data(data)  # 用新密钥加密

                            QMessageBox.information(self, "成功", "主密码更改成功!")
                        else:
                            QMessageBox.warning(self, "错误", "两次输入的新密码不匹配!")
                            # 恢复旧密钥
                            self.key = temp_key
                            self.cipher_suite = temp_cipher
            except Exception as e:
                QMessageBox.warning(self, "错误", "当前密码错误!")
        except Exception as e:
            self.show_error("更改密码错误", traceback.format_exc())

    def backup_data(self):
        try:
            options = QFileDialog.Options()
            file_name, _ = QFileDialog.getSaveFileName(self, "备份数据", "",
                                                       "加密备份文件 (*.pkb);;所有文件 (*)",
                                                       options=options)
            if file_name:
                if not file_name.endswith('.pkb'):
                    file_name += '.pkb'

                try:
                    with open(self.data_file, 'r', encoding='utf-8') as f:
                        encrypted_data = f.read()

                    with open(file_name, 'w', encoding='utf-8') as f:
                        f.write(encrypted_data)

                    QMessageBox.information(self, "成功", f"数据已备份到 {file_name}")
                except Exception as e:
                    QMessageBox.warning(self, "错误", f"备份失败: {str(e)}")
        except Exception as e:
            self.show_error("备份数据错误", traceback.format_exc())

    def restore_data(self):
        try:
            reply = QMessageBox.question(self, '警告',
                                         '恢复数据将覆盖当前所有密码数据，是否继续?',
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.No:
                return

            options = QFileDialog.Options()
            file_name, _ = QFileDialog.getOpenFileName(self, "恢复数据", "",
                                                       "加密备份文件 (*.pkb);;所有文件 (*)",
                                                       options=options)
            if file_name:
                try:
                    with open(file_name, 'r', encoding='utf-8') as f:
                        encrypted_data = f.read()

                    # 验证数据是否有效
                    self.cipher_suite.decrypt(encrypted_data.encode())

                    # 写入数据文件
                    with open(self.data_file, 'w', encoding='utf-8') as f:
                        f.write(encrypted_data)

                    # 重新加载数据
                    self.load_password_table()

                    QMessageBox.information(self, "成功", "数据恢复成功!")
                except Exception as e:
                    QMessageBox.warning(self, "错误", f"恢复失败: 文件可能已损坏或密码错误\n{str(e)}")
        except Exception as e:
            self.show_error("恢复数据错误", traceback.format_exc())

    def show_about(self):
        QMessageBox.about(self, "关于密码管理器",
                          "安全密码管理器 v1.0\n\n"
                          "一个安全存储和管理您的密码的工具。\n"
                          "所有数据都经过加密存储，确保安全。\n\n"
                          "批量导入说明:\n"
                          "1. 点击'导出模板'按钮创建模板文件\n"
                          "2. 使用Excel或文本编辑器填写模板\n"
                          "3. 确保包含'名称','用户名','密码'字段\n"
                          "4. 点击'批量导入'按钮导入数据")

    def show_error(self, title, message):
        """显示错误信息"""
        error_msg = QMessageBox()
        error_msg.setIcon(QMessageBox.Critical)
        error_msg.setWindowTitle(title)
        error_msg.setText("发生错误，请查看详细信息")
        error_msg.setDetailedText(message)
        error_msg.exec_()


class PasswordEntryDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        try:
            self.setWindowTitle("密码条目")
            self.setModal(True)
            self.setMinimumSize(800, 700)

            # 主布局
            self.main_layout = QVBoxLayout()
            self.main_layout.setContentsMargins(20, 20, 20, 20)
            self.main_layout.setSpacing(15)
            self.setLayout(self.main_layout)

            # 滚动区域
            self.scroll_area = QScrollArea()
            self.scroll_area.setWidgetResizable(True)
            self.scroll_content = QWidget()
            self.scroll_layout = QVBoxLayout(self.scroll_content)
            self.scroll_layout.setContentsMargins(10, 10, 10, 10)
            self.scroll_layout.setSpacing(15)

            # 表单布局
            self.form_layout = QVBoxLayout()
            self.form_layout.setSpacing(15)

            # 名称
            self.name_label = QLabel("名称:")
            self.name_label.setFont(QFont('Microsoft YaHei', 12))
            self.name_input = QLineEdit()
            self.name_input.setMinimumHeight(45)
            self.name_input.setPlaceholderText("必填")
            self.form_layout.addWidget(self.name_label)
            self.form_layout.addWidget(self.name_input)

            # 网址
            self.url_label = QLabel("网址:")
            self.url_label.setFont(QFont('Microsoft YaHei', 12))
            self.url_input = QLineEdit()
            self.url_input.setMinimumHeight(45)
            self.url_input.setPlaceholderText("https://example.com")
            self.form_layout.addWidget(self.url_label)
            self.form_layout.addWidget(self.url_input)

            # 用户名
            self.username_label = QLabel("用户名:")
            self.username_label.setFont(QFont('Microsoft YaHei', 12))
            self.username_input = QLineEdit()
            self.username_input.setMinimumHeight(45)
            self.username_input.setPlaceholderText("必填")
            self.form_layout.addWidget(self.username_label)
            self.form_layout.addWidget(self.username_input)

            # 密码
            self.password_layout = QHBoxLayout()
            self.password_layout.setSpacing(10)
            self.password_label = QLabel("密码:")
            self.password_label.setFont(QFont('Microsoft YaHei', 12))
            self.password_input = QLineEdit()
            self.password_input.setMinimumHeight(45)
            self.password_input.setEchoMode(QLineEdit.Password)
            self.password_input.setPlaceholderText("必填")

            # 显示密码按钮
            self.show_password_button = QPushButton("显示")
            self.show_password_button.setMinimumHeight(45)
            self.show_password_button.setCheckable(True)
            self.show_password_button.toggled.connect(self.toggle_password_visibility)

            self.password_layout.addWidget(self.password_label)
            self.password_layout.addWidget(self.password_input)
            self.password_layout.addWidget(self.show_password_button)
            self.form_layout.addLayout(self.password_layout)

            # 手机
            self.phone_label = QLabel("手机:")
            self.phone_label.setFont(QFont('Microsoft YaHei', 12))
            self.phone_input = QLineEdit()
            self.phone_input.setMinimumHeight(45)
            self.phone_input.setPlaceholderText("13800138000")
            self.form_layout.addWidget(self.phone_label)
            self.form_layout.addWidget(self.phone_input)

            # 邮箱
            self.email_label = QLabel("邮箱:")
            self.email_label.setFont(QFont('Microsoft YaHei', 12))
            self.email_input = QLineEdit()
            self.email_input.setMinimumHeight(45)
            self.email_input.setPlaceholderText("user@example.com")
            self.form_layout.addWidget(self.email_label)
            self.form_layout.addWidget(self.email_input)

            # 备注
            self.notes_label = QLabel("备注:")
            self.notes_label.setFont(QFont('Microsoft YaHei', 12))
            self.notes_input = QTextEdit()
            self.notes_input.setMinimumHeight(200)
            self.notes_input.setPlaceholderText("可添加额外信息...")
            self.form_layout.addWidget(self.notes_label)
            self.form_layout.addWidget(self.notes_input)

            # 将表单添加到滚动区域
            self.scroll_layout.addLayout(self.form_layout)
            self.scroll_layout.addStretch()
            self.scroll_area.setWidget(self.scroll_content)
            self.main_layout.addWidget(self.scroll_area)

            # 按钮布局
            self.button_layout = QHBoxLayout()
            self.button_layout.setSpacing(15)

            self.ok_button = QPushButton("确 定")
            self.ok_button.setMinimumHeight(50)
            self.ok_button.setFont(QFont('Microsoft YaHei', 12))
            self.ok_button.clicked.connect(self.accept)

            self.cancel_button = QPushButton("取 消")
            self.cancel_button.setMinimumHeight(50)
            self.cancel_button.setFont(QFont('Microsoft YaHei', 12))
            self.cancel_button.clicked.connect(self.reject)

            self.button_layout.addWidget(self.ok_button)
            self.button_layout.addWidget(self.cancel_button)
            self.main_layout.addLayout(self.button_layout)

            # 调整对话框大小
            self.adjustSize()
        except Exception as e:
            QMessageBox.critical(self, "对话框创建错误", traceback.format_exc())

    def toggle_password_visibility(self, checked):
        """切换密码可见性"""
        if checked:
            self.password_input.setEchoMode(QLineEdit.Normal)
            self.show_password_button.setText("隐藏")
        else:
            self.password_input.setEchoMode(QLineEdit.Password)
            self.show_password_button.setText("显示")

    def set_entry(self, entry):
        """设置表单数据"""
        self.name_input.setText(entry.get('name', ''))
        self.url_input.setText(entry.get('url', ''))
        self.username_input.setText(entry.get('username', ''))
        self.password_input.setText(entry.get('password', ''))
        self.phone_input.setText(entry.get('phone', ''))
        self.email_input.setText(entry.get('email', ''))
        self.notes_input.setPlainText(entry.get('notes', ''))

    def get_entry(self):
        """获取表单数据"""
        return {
            'name': self.name_input.text().strip(),
            'url': self.url_input.text().strip(),
            'username': self.username_input.text().strip(),
            'password': self.password_input.text().strip(),
            'phone': self.phone_input.text().strip(),
            'email': self.email_input.text().strip(),
            'notes': self.notes_input.toPlainText().strip()
        }


if __name__ == "__main__":
    try:
        # 创建应用
        app = QApplication(sys.argv)

        # 启用高DPI缩放
        app.setAttribute(Qt.AA_EnableHighDpiScaling)
        app.setAttribute(Qt.AA_UseHighDpiPixmaps)

        # 设置字体
        font = QFont('Microsoft YaHei', 11)
        app.setFont(font)

        # 创建主窗口
        manager = PasswordManager()
        manager.show()

        # 运行应用
        sys.exit(app.exec_())
    except Exception as e:
        error_msg = QMessageBox()
        error_msg.setIcon(QMessageBox.Critical)
        error_msg.setWindowTitle("致命错误")
        error_msg.setText(f"程序启动时发生致命错误:\n{str(e)}")
        error_msg.setDetailedText(traceback.format_exc())
        error_msg.exec_()