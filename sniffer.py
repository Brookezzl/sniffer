import sys
from PySide6.QtWidgets import *
from PyQt5.QtCore import Qt
from PySide6.QtWidgets import QTreeWidgetItem as QRItem
from PySide6.QtWidgets import QTableWidgetItem as QTItem
from scapy.all import *
from scapy.layers.l2 import *
from scapy.layers.inet import *

class SnifferWindow(QWidget):

    def __init__(self):
        super().__init__()
        self.counter = 0
        
        # 创建UI控件
        self.host_filter_edit = QLineEdit()
        self.packets_list = QListWidget()
        self.start_button = QPushButton("开始嗅探")
        self.stop_button = QPushButton("停止嗅探")
        self.show_layers_button = QPushButton("显示分层信息")
        self.show_data_button = QPushButton("显示16进制信息")

        # 设置UI布局
        vbox = QVBoxLayout()
        vbox.addWidget(QLabel("主机过滤器："))
        vbox.addWidget(self.host_filter_edit)
        vbox.addWidget(QLabel("捕获的数据包："))
        vbox.addWidget(self.packets_list)
        hbox1 = QHBoxLayout()
        hbox1.addWidget(self.start_button)
        hbox1.addWidget(self.stop_button)
        hbox2 = QHBoxLayout()
        hbox2.addWidget(self.show_layers_button)
        hbox2.addWidget(self.show_data_button)
        vbox.addLayout(hbox1)
        vbox.addLayout(hbox2)
        self.setLayout(vbox)

        # 绑定信号和槽
        self.start_button.clicked.connect(self.start_sniffing)
        self.stop_button.clicked.connect(self.stop_sniffing)
        self.show_layers_button.clicked.connect(self.show_layers)
        self.show_data_button.clicked.connect(self.show_data)

        # 初始化嗅探器和数据包列表
        self.sniffer = None
        self.packets = []
    
    # 嗅探器创建与启动
    def start_sniffing(self):
            
            host_filter = self.host_filter_edit.text()
            self.sniffer = AsyncSniffer(prn=self.handle_packet, filter=f"host {host_filter}")

            # 启动嗅探器
            self.sniffer.start()

    # 停止嗅探器
    def stop_sniffing(self):
        self.sniffer.stop()

    # 处理捕获的数据包
    def handle_packet(self, packet):
        
        self.packets.append(packet)
        self.counter += 1
        self.packets_list.addItem(str(self.counter))
        self.packets_list.addItem(str(packet))
        
    # 创建新窗口显示分层信息
    def show_layers(self):
        
        layers_window = QDialog(self)
        layers_window.setWindowTitle("数据包分层信息")
        layers_layout = QVBoxLayout(layers_window)

        # 创建counter窗口
        
        # 显示分层信息
        layers_widget = LayersWindow(self.packets)
        layers_layout.addWidget(layers_widget)
        

        # 显示窗口
        layers_window.exec_()
    
    # 创建新窗口显示16进制数据信息    
    def show_data(self):
        data_window = QDialog(self)
        data_window.setWindowTitle("16进制信息")
        data_layout = QVBoxLayout(data_window)
        
        # 显示数据信息
        data_widget = DataWindow(self.packets)
        data_layout.addWidget(data_widget)

        # 显示窗口
        data_window.exec_()
    
# 定义16进制数据窗口类    
class DataWindow(QWidget):
    def __init__(self, packets):
        super().__init__()

        # 创建UI控件
        self.tree = QTreeWidget()

        # 填充数据包信息
        for packet in packets:
            self.add_packet(packet)

        # 设置UI布局
        vbox = QVBoxLayout()
        vbox.addWidget(self.tree)
        self.setLayout(vbox)

    def add_packet(self, packet):
        # 添加数据包节点
        packet_item = QTreeWidgetItem(self.tree, ["数据包", "", ""])
        # 获取根节点在QTreeWidget控件中的索引值
        index = self.tree.indexOfTopLevelItem(packet_item)
        # 设置节点的数字编号
        packet_item.setText(0, str(index + 1) + ".")
        self.add_layer(packet_item, packet)
        
    def add_layer(self, parent_item, packet):
        layer_name = packet.__class__.__name__
        layer_item = QTreeWidgetItem(parent_item, [layer_name, "", ""])   
        layer_item.setText(0,hexdump(packet, dump=True))

# 定义显示分层信息窗口类
class LayersWindow(QWidget):

    def __init__(self, packets):
        super().__init__()

        # 创建UI控件
        self.tree = QTreeWidget()

        # 填充数据包信息
        for packet in packets:
            self.add_packet(packet)

        # 设置UI布局
        vbox = QVBoxLayout()
        vbox.addWidget(self.tree)
        self.setLayout(vbox)

    def add_packet(self, packet):
        # 添加数据包节点
        packet_item = QTreeWidgetItem(self.tree, ["数据包", "", ""])
        # 获取根节点在QTreeWidget控件中的索引值
        index = self.tree.indexOfTopLevelItem(packet_item)
        # 设置节点的数字编号
        packet_item.setText(0, str(index + 1) + ".")
        self.add_layer(packet_item, packet)
    
    # 获取数据包的所有层
    def get_packet_layers(self, packet):
        counter = 0
        while True:
            layer = packet.getlayer(counter)
            if layer is None:
                break
            yield layer
            counter += 1
    
    def add_layer(self, parent_item, packet):
        # 添加协议层节点
        layer_name = packet.__class__.__name__
        layer_item = QTreeWidgetItem(parent_item, [layer_name, "", ""])

        for layer in self.get_packet_layers(packet):
            item = QRItem(layer_item)
            item.layer = layer
            item.setText(0,layer.name)

            for name,value in layer.fields.items():
                child = QRItem(item)
                child.setText(0, f"{name}: {value}")
        
         
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SnifferWindow()
    window.show()
    sys.exit(app.exec())