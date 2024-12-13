import tkinter as tk
from tkinter import messagebox

def filter(app):
    def generate_bpf():
        # 获取用户输入的所有过滤条件
        protocol = protocol_var.get()
        src_ip = src_ip_entry.get()
        dst_ip = dst_ip_entry.get()
        src_port = src_port_entry.get()
        dst_port = dst_port_entry.get()
        src_mac = src_mac_entry.get()
        dst_mac = dst_mac_entry.get()
        net_mask = net_mask_entry.get()

        bpf = []

        # 添加协议过滤
        if protocol != "any":
            bpf.append(protocol)
        
        # 添加 IP 地址过滤
        if src_ip:
            bpf.append(f"src host {src_ip}")
        if dst_ip:
            bpf.append(f"dst host {dst_ip}")
        
        # 添加端口过滤
        if src_port:
            bpf.append(f"src port {src_port}")
        if dst_port:
            bpf.append(f"dst port {dst_port}")

        # 添加 MAC 地址过滤
        if src_mac:
            bpf.append(f"ether src {src_mac}")
        if dst_mac:
            bpf.append(f"ether dst {dst_mac}")
        
        # 添加网络掩码过滤
        if net_mask:
            bpf.append(f"net {net_mask}")
        
        # 组合 BPF 过滤字符串
        bpf_string = " and ".join(bpf)
        
        # 如果没有设置任何过滤条件，默认返回捕获所有包
        if not bpf_string:
            bpf_string = "all"
        
        # 显示生成的 BPF 字符串
        messagebox.showinfo("BPF", f"Set BPF: {bpf_string}")
        app.bpf = bpf_string

    def reset_fields():
        """清空所有输入框并返回空字符串"""
        protocol_var.set("any")
        src_ip_entry.delete(0, tk.END)
        dst_ip_entry.delete(0, tk.END)
        src_port_entry.delete(0, tk.END)
        dst_port_entry.delete(0, tk.END)
        src_mac_entry.delete(0, tk.END)
        dst_mac_entry.delete(0, tk.END)
        net_mask_entry.delete(0, tk.END)
        messagebox.showinfo("BPF Reset", "All fields have been reset.")
        app.bpf = ""

    # 创建过滤窗口
    filter_window = tk.Toplevel(app.root)  # 使用 Toplevel 创建新窗口
    filter_window.title("Set Packet Filter")

    # 创建一个 Frame 用于过滤设置
    filter_frame = tk.Frame(filter_window)
    filter_frame.pack(padx=10, pady=10)

    # 使用 grid 布局
    filter_frame.columnconfigure(0, weight=1)
    filter_frame.columnconfigure(1, weight=1)

    # 协议选项
    tk.Label(filter_frame, text="Protocol:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
    protocol_var = tk.StringVar(value="any")
    protocol_menu = tk.OptionMenu(filter_frame, protocol_var, "any", "tcp", "udp", "icmp")
    protocol_menu.grid(row=0, column=1, padx=5, pady=5)

    # 源 IP 地址
    tk.Label(filter_frame, text="Source IP:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
    src_ip_entry = tk.Entry(filter_frame)
    src_ip_entry.grid(row=1, column=1, padx=5, pady=5)

    # 目的 IP 地址
    tk.Label(filter_frame, text="Destination IP:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
    dst_ip_entry = tk.Entry(filter_frame)
    dst_ip_entry.grid(row=2, column=1, padx=5, pady=5)

    # 源端口
    tk.Label(filter_frame, text="Source Port:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
    src_port_entry = tk.Entry(filter_frame)
    src_port_entry.grid(row=3, column=1, padx=5, pady=5)

    # 目的端口
    tk.Label(filter_frame, text="Destination Port:").grid(row=4, column=0, sticky=tk.W, padx=5, pady=5)
    dst_port_entry = tk.Entry(filter_frame)
    dst_port_entry.grid(row=4, column=1, padx=5, pady=5)

    # 源 MAC 地址
    tk.Label(filter_frame, text="Source MAC:").grid(row=5, column=0, sticky=tk.W, padx=5, pady=5)
    src_mac_entry = tk.Entry(filter_frame)
    src_mac_entry.grid(row=5, column=1, padx=5, pady=5)

    # 目的 MAC 地址
    tk.Label(filter_frame, text="Destination MAC:").grid(row=6, column=0, sticky=tk.W, padx=5, pady=5)
    dst_mac_entry = tk.Entry(filter_frame)
    dst_mac_entry.grid(row=6, column=1, padx=5, pady=5)

    # 网络掩码
    tk.Label(filter_frame, text="Network Mask:").grid(row=7, column=0, sticky=tk.W, padx=5, pady=5)
    net_mask_entry = tk.Entry(filter_frame)
    net_mask_entry.grid(row=7, column=1, padx=5, pady=5)

    # 创建按钮 Frame 用于存放按钮
    button_frame = tk.Frame(filter_window)
    button_frame.pack(padx=10, pady=10)

    # 生成 BPF 字符串按钮
    tk.Button(button_frame, text="Save", command=generate_bpf).grid(row=0, column=0, padx=5, pady=5)

    # 重置按钮，清空所有输入框
    tk.Button(button_frame, text="Reset", command=reset_fields).grid(row=0, column=1, padx=5, pady=5)