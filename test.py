from scapy.all import IP, UDP, TCP,Raw, fragment, send,conf

conf.iface = "Realtek RTL8852BE WiFi 6 802.11ax PCIe Adapter"
# conf.iface = "VMware Virtual Ethernet Adapter for VMnet8"

html_payload = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Very Long HTML Payload</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
        }
        h1, h2, h3 {
            color: #333;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        table, th, td {
            border: 1px solid black;
        }
        th, td {
            padding: 10px;
            text-align: left;
        }
        ul {
            list-style-type: square;
        }
    </style>
</head>
<body>
    <h1>Sample Long HTML Document</h1>
    <p>This is a very long HTML payload used for testing purposes. Below is some more content to make it even longer.</p>
    
    <h2>Introduction</h2>
    <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nullam vehicula, urna et fringilla dignissim, velit dolor cursus elit, eget dictum orci felis non nisi. Praesent bibendum enim vel sapien ultrices, at lacinia felis dapibus. Vestibulum sit amet eros sed sapien consectetur pretium.</p>
    
    <h3>Features</h3>
    <ul>
        <li>Feature 1: Detailed description about feature 1.</li>
        <li>Feature 2: Detailed description about feature 2.</li>
        <li>Feature 3: Detailed description about feature 3.</li>
        <li>Feature 4: Detailed description about feature 4.</li>
        <li>Feature 5: Detailed description about feature 5.</li>
    </ul>
    
    <h2>Data Table Example</h2>
    <table>
        <thead>
            <tr>
                <th>Item</th>
                <th>Description</th>
                <th>Quantity</th>
                <th>Price</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td>Item 1</td>
                <td>Description for item 1</td>
                <td>10</td>
                <td>$15.00</td>
            </tr>
            <tr>
                <td>Item 2</td>
                <td>Description for item 2</td>
                <td>5</td>
                <td>$25.00</td>
            </tr>
            <tr>
                <td>Item 3</td>
                <td>Description for item 3</td>
                <td>2</td>
                <td>$100.00</td>
            </tr>
            <tr>
                <td>Item 4</td>
                <td>Description for item 4</td>
                <td>20</td>
                <td>$7.50</td>
            </tr>
        </tbody>
    </table>
    
    <h2>Additional Information</h2>
    <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vestibulum congue ex non urna facilisis, at scelerisque magna laoreet. Proin eget dolor vitae nisl vehicula sollicitudin ac a elit. Donec eget felis magna. Suspendisse potenti. Nunc malesuada libero sit amet libero sollicitudin, quis efficitur erat vestibulum.</p>
    <p>Phasellus malesuada, nunc eget varius aliquam, ligula lectus viverra est, id fermentum risus felis vitae dui. Donec faucibus lorem ut ex fermentum, nec vulputate libero laoreet. Maecenas ultrices diam sed leo vulputate, in dictum neque pellentesque. Nam euismod, nisi in facilisis rutrum, sem lectus tincidunt mauris, a tristique ex nisi id lectus.</p>
    <p>Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Etiam fringilla, felis id ultrices vehicula, urna erat gravida risus, et lobortis enim lorem et risus.</p>

    <h2>Conclusion</h2>
    <p>In conclusion, this is an example of a very long HTML document used to demonstrate payload handling. The content is not meaningful but simply serves as a test for length and structure.</p>
    
    <h2>Final Remarks</h2>
    <p>Thank you for reviewing this document. It is intentionally lengthy to provide a substantial payload for testing network transmission of large data packets.</p>
</body>
</html>
""".encode()

a_payload = b"A"*5000

image_path = "./test/src_file/start.png"
with open(image_path, "rb") as img_file:
    image_data = img_file.read()

# 创建一个大的ICMP包
pkt_tcp = IP(dst="192.168.1.1") / TCP(dport=12345, sport=54321, flags="S")  / Raw(load=image_data)  # 超过MTU，会自动进行分片
pkt_udp = IP(dst="192.168.1.1") / UDP(dport=12345)  / Raw(load=image_data)
# print(pkt)

print(len(Raw(load=image_data)))

# 使用Scapy的 fragment() 函数将包分片
fragments = fragment(pkt_tcp,fragsize=1000)

# for fragment in fragments:
#     print(fragment.show())

# # 发送分片包
send(fragments)

fragments_udp = fragment(pkt_udp,fragsize=1000)
send(fragments_udp)
