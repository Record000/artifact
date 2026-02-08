from lxml import etree
import base64

class SnapshotXml:
    def __init__(self, session_id, serial, xmlns="http://www.ripe.net/rpki/rrdp", version="1"):
        self.session_id = session_id
        self.serial = serial
        self.root = etree.Element("snapshot")
        self.root.set("xmlns", xmlns)
        self.root.set("version", version)
        self.root.set("session_id", session_id)
        self.root.set("serial", serial)
    
    def add_publish_element(self, uri, base64_value):
        publish = etree.SubElement(self.root, "publish")
        publish.set("uri", uri)
        publish.text = base64_value
    
    def calculate_base64(self, file_path):
        with open(file_path, "rb") as f:
            data = f.read()
            base64_value = base64.b64encode(data).decode()
            return base64_value
    
    def add_publish(self, uri, file_path):
        # hash_value = self.calculate_hash(file_path)
        base64_value = self.calculate_base64(file_path)
        self.add_publish_element(uri, base64_value)
    
    def write(self, file_path):
        tree = etree.ElementTree(self.root)
        tree.write(file_path, encoding="utf-8", xml_declaration=False, pretty_print=True)