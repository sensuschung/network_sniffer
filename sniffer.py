from scapy.all import sniff,conf,Raw
import wmi
import netifaces
import tkinter as tk
from tkinter import scrolledtext, ttk, messagebox
from packet_processor import extract_packet_info,process_packet,get_ip_frag,reassemble_fragments
import threading
import time
from PIL import Image, ImageTk
from storage import Packet,save_binary_file, package_list_to_json, save_csv
import queue
from filter import filter

def get_network_interfaces():
    c = wmi.WMI()
    interfaces = {}
    for nic in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
        # print(f"NIC Description: {nic.Description}, MAC Address: {nic.MACAddress}")
        for interface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_LINK in addrs:
                mac_address = addrs[netifaces.AF_LINK][0]['addr'].lower()
                # print(f"Interface: {interface}, MAC Address: {mac_address}")
                if nic.MACAddress.lower() == mac_address:
                    interfaces[nic.Description] = interface
                    # print(f"Matched: {nic.Description} -> {interface}")
    return interfaces

class SnifferApp:
    def __init__(self, root):
        self.bpf = ""
        root.geometry("800x600")
        self.root = root
        self.root.title("Network Sniffer")

        self.main_frame = tk.Frame(root)
        self.main_frame.grid(row=0, column=0, sticky="nsew")

        root.grid_rowconfigure(0, weight=1)
        root.grid_columnconfigure(0, weight=1)

        self.main_frame.grid_rowconfigure(0, weight=0)
        self.main_frame.grid_rowconfigure(1, weight=1) 
        self.main_frame.grid_rowconfigure(2, weight=0) 
        self.main_frame.grid_rowconfigure(3, weight=1) 
        self.main_frame.grid_columnconfigure(0, weight=0)
        self.main_frame.grid_columnconfigure(1, weight=1) 
        self.main_frame.grid_columnconfigure(2, weight=1)
        self.main_frame.grid_columnconfigure(3, weight=1)
        self.main_frame.grid_columnconfigure(4, weight=1)
        self.main_frame.grid_columnconfigure(5, weight=1)
        self.main_frame.grid_columnconfigure(6, weight=1)
        self.main_frame.grid_columnconfigure(7, weight=1)

        self.images = {}

        try:
            start_img = Image.open("img/start.png")
            start_img = start_img.resize((20,20))  # 调整图片大小
            start_photo = ImageTk.PhotoImage(start_img)
            self.images["start"] = start_photo
            # print(self.images["start"])

            stop_img = Image.open("img/stop.png")
            stop_img = stop_img.resize((20,20))  # 调整图片大小
            stop_photo = ImageTk.PhotoImage(stop_img)
            self.images["stop"] = stop_photo
        except Exception as e:
            print(f"Error loading start image: {e}")

        # 创建菜单栏
        self.create_menubar()

        # 网卡选择下拉菜单
        self.interface_label = tk.Label(self.main_frame, text="Select Interface:")
        self.interface_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")

        self.interface_var = tk.StringVar()
        self.interfaces = get_network_interfaces()  # 获取网卡列表
        self.interface_menu = ttk.Combobox(self.main_frame, textvariable=self.interface_var)
        self.interface_menu['values'] = list(self.interfaces.keys())
        self.interface_menu.grid(row=0, column=1,columnspan=7, padx=(10,24), pady=5, sticky="ew")

        # 创建Frame容器放置TreeView
        self.frame = tk.Frame(self.main_frame)
        self.frame.grid(row=1, column=0, columnspan=8, sticky="nsew", padx=10, pady=5)

        # 设置frame的行列权重
        self.frame.grid_rowconfigure(0, weight=1)
        self.frame.grid_columnconfigure(0, weight=1)

        # 创建TreeView组件
        self.tree = ttk.Treeview(self.frame, columns=("No", "Time", "Source", "Destination", "Protocol", "Length", "Info"), show='headings', height=14)
        self.tree.heading("No", text="No")
        self.tree.heading("Time", text="Time")
        self.tree.heading("Source", text="Source")
        self.tree.heading("Destination", text="Destination")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.heading("Length", text="Length")
        self.tree.heading("Info", text="Info")
        self.tree.column("No", width=50)
        self.tree.column("Time", width=150)
        self.tree.column("Source", width=150)
        self.tree.column("Destination", width=150)
        self.tree.column("Protocol", width=100)
        self.tree.column("Length", width=100)
        self.tree.column("Info", width=400, stretch=True)
        self.tree.grid(row=0, column=0, sticky="nsew")

        # 添加垂直滚动条
        self.scrollbar_y = ttk.Scrollbar(self.frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=self.scrollbar_y.set)
        self.scrollbar_y.grid(row=0, column=7, sticky="ns")
        
        # 添加水平滚动条
        self.scrollbar_x = ttk.Scrollbar(self.frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(xscrollcommand=self.scrollbar_x.set)
        self.scrollbar_x.grid(row=1, column=0, sticky="ew")
        
        self.packet_info_label = tk.Label(self.main_frame, text="Packet Info")
        self.packet_info_label.grid(row=2, column=0, padx=(10,5), pady=0, sticky="w")

        self.payload_info_label = tk.Label(self.main_frame, text="Payload")
        self.payload_info_label.grid(row=2, column=4, padx=(10,5), pady=0, sticky="w")

        self.encode_menu = ttk.Combobox(self.main_frame, values=["Raw", "UTF-8", "ASCII", "Latin-1"])
        self.encode_menu.set("Raw")
        self.encode_menu.grid(row=2, column=5, columnspan=3,padx=(5,24), pady=0, sticky="ew")
        self.encode_menu.bind("<<ComboboxSelected>>", self.update_hex_text)

        # 添加详细内容显示框
        self.detail_text = scrolledtext.ScrolledText(self.main_frame, wrap=tk.WORD, height=20)
        self.detail_text.grid(row=3, column=0, columnspan=4, padx=(10,5), pady=(5,20), sticky="nsew")

        self.hex_text = scrolledtext.ScrolledText(self.main_frame, wrap=tk.WORD, height=20)
        self.hex_text.grid(row=3, column=4, columnspan=4, padx=(5,10), pady=(5,20), sticky="nsew")

        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)
        
        # 初始化一些参数
        self.sniffing = False
        self.packet_count = 0
        self.packet_list = {}  # 用于存储捕获的包
        self.packet_queue = queue.Queue()

        self.chosen_packet = None

    def create_menubar(self):
        # 创建菜单栏
        menubar = tk.Menu(self.root)

        # 创建 "File" 菜单
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Save", command=lambda: self.save_record())

        function_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Functions", menu=function_menu)
        
        # 将Start和Stop按钮加入File菜单
        # print(self.images)
        menubar.add_command(label="Start",command=self.start_sniffing)
        menubar.add_command(label= "Stop", command=self.stop_sniffing)

        function_menu.add_command(label="Track Stream", command=self.track_stream)
        function_menu.add_command(label="Set Filter", command=lambda: self.filter_menu())

        # 显示菜单
        self.root.config(menu=menubar)

    def track_stream(self):
        selected_item = self.tree.selection()
        if selected_item:
            packet_info = self.tree.item(selected_item[0], "values")
            selected_no = packet_info[0]
            packet = self.packet_list.get(int(selected_no), None)

            # info_label = tk.Label(self.track_stream_window, text=f"Selected: {packet}", font=("Arial", 12))
            # info_label.pack(pady=20)

            if packet.is_fragmented: 
                self.track_stream_window = tk.Toplevel(root)
                self.track_stream_window.title(f"Track Stream Info:{packet.src} -> {packet.dst}: {packet.proto}:{packet.fragment_id[-1]}")
                self.track_stream_window.geometry("600x400")
                self.track_frame = tk.Frame(self.track_stream_window)
                self.track_frame.grid(row=0, column=0, sticky="nsew")
                self.track_stream_window.grid_rowconfigure(0, weight=1)
                self.track_stream_window.grid_columnconfigure(0, weight=1)
                self.track_frame.grid_rowconfigure(0, weight=0)
                self.track_frame.grid_rowconfigure(1, weight=1)
                self.track_frame.grid_rowconfigure(2, weight=0)
                self.track_frame.grid_columnconfigure(0, weight=1)
                self.track_frame.grid_columnconfigure(1, weight=1)
                self.track_frame.grid_columnconfigure(2, weight=1)
                self.track_frame.grid_columnconfigure(3, weight=1)

                self.info_window_label = tk.Label(self.track_frame, text="Packet Info")
                self.info_window_label.grid(row=0, column=0, padx=(10,5), pady=0, sticky="w")
                self.info_window = scrolledtext.ScrolledText(self.track_frame, wrap=tk.WORD)
                self.info_window.grid(row=1, column=0, columnspan=4, padx=(10,10), pady=(5,5), sticky="nsew")

                self.decode_select = ttk.Combobox(self.track_frame, values=["Raw", "UTF-8", "ASCII", "Latin-1"])
                self.decode_select.grid(row=0, column=0,columnspan=4, padx=(100,25), sticky="ew")
                self.decode_select.set("Raw")

                track_id = packet.fragment_id
                track_list = []
                for packet in self.packet_list.values():
                    if packet.fragment_id == track_id:
                        track_list.append(packet.packet)
                track_list.sort(key=get_ip_frag)
                new_packet = reassemble_fragments(track_list)
                self.update_info_text(new_packet)
                self.decode_select.bind("<<ComboboxSelected>>", lambda event:self.update_info_text(new_packet))
                # print(full_packet)
                # print(track_list)   

                self.save_info_button = tk.Button(self.track_frame, text="Save", command=lambda: save_binary_file(new_packet))
                self.save_info_button.grid(row=2, column=3, padx=(10,25), pady=(5,5), sticky="ew")
            else:
                messagebox.showwarning("Warning", "Selected packet is not a fragmented packet.")
        else:
            messagebox.showwarning("No Selection", "Please select an item first.")

    def update_info_text(self,info):
        selected_encoding = self.decode_select.get()
        # print(info)
        self.info_window.delete(1.0, tk.END)
        if selected_encoding == "Raw":
            hex_info = info.hex()
            assert_info = ' '.join([hex_info[i:i+2].zfill(2) for i in range(0, len(hex_info), 2)])
        else:
            try:
                assert_info = info.decode(selected_encoding,errors='replace')
            except (UnicodeEncodeError, TypeError) as e:
                assert_info = f"编码错误: {e}"
        # print(assert_info)
        self.info_window.insert(tk.END,assert_info)

    def start_sniffing(self):
        self.sniffing = True
        self.tree.delete(*self.tree.get_children())  # 清空之前的结果
        self.packet_count = 0
        self.packet_list = {}  # 清空包列表
        self.sniffer_thread()
        self.process_queue_thread()

    def stop_sniffing(self):
        self.sniffing = False

    def sniffer_thread(self):
        interface_name = self.interface_var.get()
        interface = self.interfaces.get(interface_name)
        if interface:
            # print(f"Sniffing on interface: {interface}")
            self.sniff_thread = threading.Thread(target=self.run_sniffer, args=(interface_name,))
            self.sniff_thread.start()
        else:
            print(f"Error: Interface '{interface_name}' not found!")

    def run_sniffer(self, interface):
        try:
            # 配置scapy以避免标志值解释错误
            conf.use_pcap = True
            sniff(iface=interface, prn=self.enqueue_packet, stop_filter=lambda x: not self.sniffing or self.packet_count >= 1000,filter=self.bpf)
        except Exception as e:
            print(f"Error: {str(e)}")

    def enqueue_packet(self, packet):
        self.packet_queue.put(packet)

    def process_queue_thread(self):
        self.process_thread = threading.Thread(target=self.process_queue)
        self.process_thread.start()

    def process_queue(self):
        while self.sniffing or not self.packet_queue.empty():
            try:
                packet = self.packet_queue.get(timeout=1)
                self.process_packet(packet)
            except queue.Empty:
                continue

    def process_packet(self, packet):
        self.packet_count += 1
        packet_info = extract_packet_info(packet, self.packet_count)
        packet = Packet(*packet_info)  # 创建 packet 实例
        self.packet_list[packet.packet_count]=packet  # 将包添加到包列表中
        self.tree.insert("", "end", values=packet.get_all())  # 将包信息显示到 Tree 中

    def on_tree_select(self, event):
        self.encode_menu.set("Raw")
        selected_item = self.tree.selection()[0]
        packet_info = self.tree.item(selected_item, "values")
        selected_no = packet_info[0]
        packet = self.packet_list.get(int(selected_no), None)
        # print(self.packet_list)
        # print(f"Selected Packet No: {selected_no},{type(selected_no)}")
        self.detail_text.delete(1.0, tk.END)
        self.hex_text.delete(1.0, tk.END)

        if packet!=None:
            # print(packet)
            self.chosen_packet = packet
            process_packet(packet)
            # info = packet.get_all()
            self.detail_text.insert(tk.END, f"Packet No: {packet.packet_count}\n")
            self.detail_text.insert(tk.END, f"Time: {packet.timestamp}\n")
            self.detail_text.insert(tk.END, f"Source: {packet.src}\n")
            self.detail_text.insert(tk.END, f"Destination: {packet.dst}\n")
            self.detail_text.insert(tk.END, f"Protocol: {packet.proto}\n")
            self.detail_text.insert(tk.END, f"Length: {packet.length}\n")
            self.detail_text.insert(tk.END, f"Info: {packet.info}\n")
            self.detail_text.insert(tk.END, f"Details: {packet.details}\n")
            hex_string = packet.hex
            # max_per_line = 14
            # formatted_lines = [formatted_hex[i:i+3*max_per_line] for i in range(0, len(formatted_hex), 3*max_per_line)]
            # packet.update_hex(formatted_hex)
            # for line in formatted_lines:
            self.hex_text.insert(tk.END, f"{hex_string}\n")
        else:
            self.chosen_packet = None

    def update_hex_text(self, event=None):
        """根据选择的编码方式更新hex_text内容"""
        selected_encoding = self.encode_menu.get()
        raw_data = None
        if self.chosen_packet:
            raw_data = self.chosen_packet.raw
        if raw_data:
            # print(type(raw_data))
            byte_data = raw_data.load
            if selected_encoding == "Raw":
                # 如果选择了 Raw，展示十六进制内容
                hex_representation = self.chosen_packet.hex
                self.hex_text.delete(1.0, tk.END)
                self.hex_text.insert(tk.END, hex_representation)
            else:
                try:
                    # 根据选择的编码方式进行编码转换
                    decoded_text = byte_data.decode(selected_encoding,errors='replace')
                    self.hex_text.delete(1.0, tk.END)
                    self.hex_text.insert(tk.END, decoded_text)
                except (UnicodeEncodeError, TypeError) as e:
                    self.hex_text.delete(1.0, tk.END)
                    self.hex_text.insert(tk.END, f"编码错误: {e}")

    def hex_to_bytes(self, hex_str):
        """将十六进制字符串转换为字节"""
        hex_str = hex_str.replace(" ", "")  # 去除空格
        return bytes.fromhex(hex_str)

    def to_hex(self, data):
        """将数据转换为十六进制格式"""
        return ' '.join(f'{byte:02x}' for byte in data)

    def save_record(self):
        filenames = ["id", "timestamp", "src", "dst", "proto", "length", "info", "is_fragmented", "fragment_id","raw"]
        json = package_list_to_json(self.packet_list)
        save_csv(json,filenames)

    def filter_menu(self):
        filter(self)

if __name__ == "__main__":
    root = tk.Tk()
    app = SnifferApp(root)
    root.mainloop()
