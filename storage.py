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
    
    def get_all(self):
        return (self.packet_count, self.timestamp, self.src, self.dst, self.proto, self.length, self.info)

    def update_details(self,details):
        self.details = details
    
    def update_raw(self,raw):
        self.raw = raw

    def update_hex(self,hex):
        self.hex = hex

