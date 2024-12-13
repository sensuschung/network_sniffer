import tkinter as tk
from tkinter import filedialog, messagebox
from scapy.all import Raw
import csv

filetypes = [
    ("所有文件", "*.*"),
    ("文本文件", "*.txt"),
    ("PDF 文件", "*.pdf"),
    ("CSV 文件", "*.csv"),
    ("图像文件", "*.jpg;*.jpeg;*.png"),
    ("Python 文件", "*.py"),
    ("压缩文件", "*.zip;*.tar.gz;*.rar"),
    ("音频文件", "*.mp3;*.wav;*.flac"),
    ("视频文件", "*.mp4;*.avi;*.mkv")
]

class Packet:
    def __init__(self,packet, packet_count, timestamp, src, dst, proto, length, info, details,hex,raw,is_fragmented,fragment_id):
        self.packet = packet
        self.packet_count = packet_count
        self.timestamp = timestamp
        self.src = src
        self.dst = dst
        self.proto = proto
        self.length = length
        self.info = info
        self.details = details
        self.hex = hex
        self.raw = raw
        self.is_fragmented = is_fragmented
        self.fragment_id = fragment_id

# 修改details存储格式：按照字典存，然后设置格式化get_details方法
# 先测试当前内容是否可行

    def __str__(self):
        return f"{self.packet_count} | {self.timestamp} | {self.src} -> {self.dst} | {self.proto} | {self.length} | {self.info}| {self.details} | {self.hex}"
    
    def to_dict(self):
        raw_info = None
        if Raw in self.packet:
            raw = self.packet[Raw].load
            raw_info = raw.hex()
        return {
            "id": self.packet_count,
            "timestamp": self.timestamp,
            "src": self.src,
            "dst": self.dst,
            "proto": self.proto,
            "length": self.length,
            "info": self.info,
            "raw": raw_info,
            "is_fragmented": self.is_fragmented,
            "fragment_id": self.fragment_id
        }
    
    def get_all(self):
        return (self.packet_count, self.timestamp, self.src, self.dst, self.proto, self.length, self.info)

    def update_details(self,details):
        self.details = details
    
    def update_raw(self,raw):
        self.raw = raw

    def update_hex(self,hex):
        self.hex = hex

def package_list_to_json(packet_list):
    json_list = []
    for packet in packet_list.values():
        json_list.append(packet.to_dict())
    return json_list

def save_binary_file(data):
    file_path = filedialog.asksaveasfilename(
        title="Select Folder",  # 对话框标题
        defaultextension="",  # 默认扩展名
        filetypes=filetypes  # 文件类型
    )
    if file_path:
        # 将二进制数据保存为文件
        with open(file_path, 'wb') as f:
            f.write(data)
        # print(f"文件已保存为：{file_path}")
    else:
        # 如果未选择文件，弹出提示框
        messagebox.showwarning("Warning", "Please select file path and enter filename.")


def save_csv(data, fieldnames):
    # 打开文件保存对话框，获取用户选择的路径和文件名
    file_path = filedialog.asksaveasfilename(
        title="Select Folder",  # 对话框标题
        defaultextension=".csv",  # 默认扩展名
        filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]  # 文件类型
    )

    if file_path:
        try:
            # 打开文件并写入 CSV 数据
            with open(file_path, mode='w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()  # 写入字段名
                writer.writerows(data)  # 写入数据
            messagebox.showinfo("Success", f"File has been successfully saved as:{file_path}")
        except Exception as e:
            # 处理写入文件时的错误
            messagebox.showerror("Error", f"Fail to save file: {e}")
    else:
        # 如果未选择文件路径，弹出提示框
        messagebox.showwarning("Warning", "Please select file path and enter filename.")
