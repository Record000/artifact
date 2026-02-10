from lxml import etree
import hashlib

class NotificationXml:
    def __init__(self, session_id, serial, xmlns="http://www.ripe.net/rpki/rrdp", version="1"):
        self.root = etree.Element("notification")
        self.root.set("xmlns", xmlns)
        self.root.set("version", version)
        self.root.set("session_id", session_id)
        self.root.set("serial", serial)
        self.session_id = session_id
        self.serial = serial
    
    def add_snapshot_element(self, uri, hash_value):
        snapshot = etree.SubElement(self.root, "snapshot")
        snapshot.set("uri", uri)
        snapshot.set("hash", hash_value)
    
    def add_delta_element(self, uri, hash_value):
        delta = etree.SubElement(self.root, "delta")
        delta.set("serial", self.serial)
        delta.set("uri", uri)
        delta.set("hash", hash_value)
    
    def calculate_hash(self, file_path):
        with open(file_path, "rb") as f:
            data = f.read()
            hash = hashlib.sha256(data).hexdigest()
            print("file_name: ", file_path)
            print("hash: ", hash)
            return hash
    
    def add_snapshot(self, uri, file_path):
        hash_value = self.calculate_hash(file_path)
        self.add_snapshot_element(uri, hash_value)
    
    def add_delta(self, uri, file_path):
        hash_value = self.calculate_hash(file_path)
        self.add_delta_element(uri, hash_value)
    
    def write(self, file_path):
        tree = etree.ElementTree(self.root)
        tree.write(file_path, encoding="utf-8", xml_declaration=False, pretty_print=True)